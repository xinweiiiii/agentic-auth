"""``agentic-auth manifest validate|lint|diff`` — offline authoring helpers.

``diff`` shares :class:`ReconcilerService` and :class:`DiscoveryClient` with the server, so
its output matches ``POST /v1/agents`` for the same manifest.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import httpx
import typer
import yaml
from pydantic import ValidationError
from rich import print as rprint

from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.services.discovery import DiscoveryClient
from agentic_auth.services.reconciler import ReconcilerService

manifest_app = typer.Typer(help="Author, validate, and preview-reconcile agent manifests")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        rprint(f"[red]cannot read {path}[/red]")
        raise typer.Exit(EXIT_USAGE)
    text = path.read_text()
    try:
        data = yaml.safe_load(text)  # also parses JSON
    except yaml.YAMLError as exc:
        rprint(f"[red]not valid YAML or JSON: {exc}[/red]")
        raise typer.Exit(EXIT_USAGE) from exc
    if not isinstance(data, dict):
        rprint("[red]manifest must be a mapping[/red]")
        raise typer.Exit(EXIT_USAGE)
    return data


def _errors(exc: ValidationError) -> list[dict[str, Any]]:
    return [{"loc": [str(p) for p in e["loc"]], "msg": e["msg"]} for e in exc.errors()]


def _parse(doc: dict[str, Any]) -> AgentManifest:
    try:
        return AgentManifest.model_validate(doc)
    except ValidationError as exc:
        raise _Invalid(_errors(exc)) from exc


class _Invalid(Exception):
    def __init__(self, errors: list[dict[str, Any]]) -> None:
        self.errors = errors


def _make_discovery_client(timeout: float) -> DiscoveryClient:
    return DiscoveryClient(timeout=timeout)


@manifest_app.command()
def validate(
    file: Path = typer.Argument(..., help="Manifest file (YAML or JSON)"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Schema-validate a manifest. No network calls."""
    doc = _load(file)
    try:
        _parse(doc)
    except _Invalid as inv:
        if json_out:
            typer.echo(json.dumps({"valid": False, "errors": inv.errors}))
        else:
            for e in inv.errors:
                rprint(f"[red]{'.'.join(e['loc'])}[/red]: {e['msg']}")
        raise typer.Exit(EXIT_FINDINGS) from None
    rprint(json.dumps({"valid": True}) if json_out else "[green]valid[/green]")


def _lint_warnings(m: AgentManifest) -> list[dict[str, str]]:
    w: list[dict[str, str]] = []
    depths = [d.max_hop_depth for d in m.spec.downstream_agents]
    if depths and m.spec.hop_budget > max(depths):
        w.append(
            {
                "code": "DEAD_HOP_HEADROOM",
                "message": "hop_budget exceeds every declared max_hop_depth",
            }
        )
    if m.spec.downstream_agents and m.spec.hop_budget == 1:
        w.append(
            {"code": "CANNOT_DELEGATE", "message": "downstream_agents declared but hop_budget is 1"}
        )
    writes = set(m.spec.data_classes.writes)
    for t in m.spec.tools:
        if t.privileged and writes.intersection(t.data_classes):
            w.append(
                {"code": "PRIVILEGED_WRITE", "message": f"privileged tool {t.ref} also writes"}
            )
    seen: set[str] = set()
    for t in m.spec.tools:
        if t.ref in seen:
            w.append({"code": "DUPLICATE_TOOL", "message": f"duplicate tool ref {t.ref}"})
        seen.add(t.ref)
    used = {dc for t in m.spec.tools for dc in t.data_classes}
    for dc in set(m.spec.data_classes.reads) | writes:
        if dc not in used:
            w.append(
                {"code": "UNUSED_DATA_CLASS", "message": f"data class {dc} referenced by no tool"}
            )
    return w


@manifest_app.command()
def lint(
    file: Path = typer.Argument(...),
    json_out: bool = typer.Option(False, "--json"),
    strict: bool = typer.Option(False, "--strict", help="exit non-zero on any warning"),
) -> None:
    """Schema-validate, then report best-practice warnings."""
    doc = _load(file)
    try:
        m = _parse(doc)
    except _Invalid as inv:
        rprint(
            json.dumps({"valid": False, "errors": inv.errors}) if json_out else "[red]invalid[/red]"
        )
        raise typer.Exit(EXIT_FINDINGS) from None
    warnings = _lint_warnings(m)
    if json_out:
        typer.echo(json.dumps({"warnings": warnings}))
    else:
        for warn in warnings:
            rprint(f"[yellow]{warn['code']}[/yellow]: {warn['message']}")
        if not warnings:
            rprint("[green]no warnings[/green]")
    if strict and warnings:
        raise typer.Exit(EXIT_FINDINGS) from None


async def _run_diff(m: AgentManifest, timeout: float) -> dict[str, Any]:
    reconciler = ReconcilerService()
    client = _make_discovery_client(timeout)
    try:
        discovered = await client.discover(reconciler.authorities(m))
    finally:
        await client.aclose()
    outcome = reconciler.reconcile(m, discovered)
    return {
        "status": outcome.status,
        "diff": [d.model_dump(mode="json") for d in outcome.diff],
    }


def _make_http_client(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout)


async def _register_all(
    control_plane: str,
    admin_token: str,
    order: list[str],
    manifests: dict[str, AgentManifest],
    override_reason: str,
    timeout: float,
) -> list[tuple[str, int, dict[str, Any]]]:
    client = _make_http_client(timeout)
    results: list[tuple[str, int, dict[str, Any]]] = []
    try:
        for name in order:
            response = await client.post(
                f"{control_plane.rstrip('/')}/v1/agents",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={
                    "name": name,
                    "manifest": manifests[name].canonical_doc(),
                    # Test environments rarely serve the tools' discovery documents. An
                    # unreachable capability source lands in needs_review — not a hard
                    # reject — and a recorded override reason reconciles it.
                    "override": {"reason": override_reason},
                },
            )
            try:
                body = response.json()
            except ValueError:
                body = {}
            results.append((name, response.status_code, body))
    finally:
        await client.aclose()
    return results


@manifest_app.command("register-dir")
def register_dir(
    directory: Path = typer.Argument(..., help="Directory of agent manifests"),
    control_plane: str = typer.Option(..., "--control-plane", help="Control plane base URL"),
    override_reason: str = typer.Option(
        ..., "--override-reason", help="Recorded on every registration that needs an override"
    ),
    timeout: float = typer.Option(10.0, "--timeout"),
) -> None:
    """Register every manifest in a directory, leaf first — for test and CI environments.

    The admin token is read from AGENTIC_AUTH_ADMIN_TOKEN and never accepted on the command
    line, where it would land in shell history and CI logs.
    """
    from agentic_auth.services.drift import load_manifest_dirs, registration_order

    admin_token = os.environ.get("AGENTIC_AUTH_ADMIN_TOKEN", "")
    if not admin_token:
        rprint("[red]AGENTIC_AUTH_ADMIN_TOKEN is not set[/red]")
        raise typer.Exit(EXIT_USAGE)
    if not override_reason.strip():
        rprint("[red]--override-reason must not be empty[/red]")
        raise typer.Exit(EXIT_USAGE)

    loaded = load_manifest_dirs([directory])
    if loaded.errors:
        for error in loaded.errors:
            rprint(f"[red]{error.code}[/red] {error.path or ''} {error.message}")
        raise typer.Exit(EXIT_USAGE)

    order = registration_order(loaded.manifests)
    results = asyncio.run(
        _register_all(control_plane, admin_token, order, loaded.manifests, override_reason, timeout)
    )

    failed = False
    for name, status, body in results:
        if status == 201:
            version = body.get("manifest_version")
            rprint(f"registered {name}: {body.get('status')} (manifest v{version})")
            continue
        failed = True
        error = body.get("error", {}) if isinstance(body, dict) else {}
        code, message = error.get("code", ""), error.get("message", "")
        rprint(f"[red]failed {name}: HTTP {status} {code}[/red] {message}")
        for entry in (error.get("details") or {}).get("diff", []):
            rprint(f"  {entry.get('code')} {entry.get('tool_ref')} — {entry.get('remedy')}")
    if failed:
        raise typer.Exit(EXIT_FINDINGS)


@manifest_app.command()
def diff(
    file: Path = typer.Argument(...),
    json_out: bool = typer.Option(False, "--json"),
    discovery_timeout: float = typer.Option(5.0, "--discovery-timeout"),
) -> None:
    """Preview the reconciliation diff the server would return for this manifest."""
    doc = _load(file)
    try:
        m = _parse(doc)
    except _Invalid as inv:
        rprint(
            json.dumps({"valid": False, "errors": inv.errors}) if json_out else "[red]invalid[/red]"
        )
        raise typer.Exit(EXIT_FINDINGS) from None

    result = asyncio.run(_run_diff(m, discovery_timeout))
    if json_out:
        typer.echo(json.dumps(result))
    else:
        rprint(f"status: [bold]{result['status']}[/bold]")
        for d in result["diff"]:
            rprint(f"  [red]{d['code']}[/red] {d['tool_ref']} — {d['remedy']}")
    if result["status"] != "reconciled":
        raise typer.Exit(EXIT_FINDINGS) from None


async def replay_bundle(
    client: httpx.AsyncClient,
    control_plane: str,
    admin_token: str,
    plan: list[tuple[str, list[dict[str, Any]]]],
    override_reason: str,
) -> list[tuple[str, int, int, dict[str, Any]]]:
    """Register each agent's first manifest, then submit every later version in order.
    Returns ``(agent, version_index, status, body)`` per request; stops an agent at its
    first refusal, since a later version cannot be submitted for an agent that never
    registered."""
    base = control_plane.rstrip("/")
    headers = {"Authorization": f"Bearer {admin_token}"}
    override = {"reason": override_reason}
    results: list[tuple[str, int, int, dict[str, Any]]] = []
    for name, docs in plan:
        for index, doc in enumerate(docs):
            # The first version registers the agent; every later one is a new version of it.
            if index == 0:
                url, body = f"{base}/v1/agents", {"name": name, "manifest": doc}
            else:
                url, body = f"{base}/v1/manifests", {"agent": name, "manifest": doc}
            response = await client.post(url, headers=headers, json={**body, "override": override})
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            results.append((name, index + 1, response.status_code, payload))
            if response.status_code != 201:
                break
    return results


@manifest_app.command("register-bundle")
def register_bundle(
    bundle: Path = typer.Argument(..., help="Export bundle from EmbeddedControlPlane.export"),
    control_plane: str = typer.Option(..., "--control-plane", help="Control plane base URL"),
    override_reason: str = typer.Option(
        ..., "--override-reason", help="Recorded on every version that needs an override"
    ),
    timeout: float = typer.Option(10.0, "--timeout"),
) -> None:
    """Re-register an embedded instance's manifests, every version in order, downstream first.

    Each version reconciles against this control plane's own capability discovery, exactly as
    a fresh registration does. Enrollments are not carried over: an agent re-enrolls with its
    own key. The admin token is read from AGENTIC_AUTH_ADMIN_TOKEN, never the command line.
    """
    from agentic_auth.services.bundle_import import BundleError, read_bundle, registration_plan

    admin_token = os.environ.get("AGENTIC_AUTH_ADMIN_TOKEN", "")
    if not admin_token:
        rprint("[red]AGENTIC_AUTH_ADMIN_TOKEN is not set[/red]")
        raise typer.Exit(EXIT_USAGE)
    if not override_reason.strip():
        rprint("[red]--override-reason must not be empty[/red]")
        raise typer.Exit(EXIT_USAGE)
    try:
        plan = registration_plan(read_bundle(bundle))
    except (OSError, BundleError) as exc:
        rprint(f"[red]{exc}[/red]")
        raise typer.Exit(EXIT_USAGE) from exc

    async def run() -> list[tuple[str, int, int, dict[str, Any]]]:
        client = _make_http_client(timeout)
        try:
            return await replay_bundle(client, control_plane, admin_token, plan, override_reason)
        finally:
            await client.aclose()

    failed = False
    for name, version, status, body in asyncio.run(run()):
        if status == 201:
            rprint(f"registered {name} v{version}: {body.get('status')}")
            continue
        failed = True
        error = body.get("error", {}) if isinstance(body, dict) else {}
        rprint(
            f"[red]failed {name} v{version}: HTTP {status} {error.get('code', '')}[/red] "
            f"{error.get('message', '')}"
        )
    if failed:
        raise typer.Exit(EXIT_FINDINGS)
