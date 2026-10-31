"""``agentic-auth sandbox`` — observe a first-time agent, propose, ratify (Phase 5).

Three commands mirroring the three steps of FR-5, plus a local ``propose`` that folds a
trace file without going through the control plane at all — useful when the observation
happened somewhere the CLI cannot reach.

**Ratification is a human act and stays one.** There is no ``--yes`` and no batch mode:
a flag that ratifies without reading the proposal would be the automation FR-037 exists
to prevent, dressed as convenience.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import typer
from rich import print as rprint

from agentic_auth.coldstart.propose import added_by_administrator
from agentic_auth.coldstart.propose import propose as propose_document
from agentic_auth.schemas.edge_trace import EdgeTrace

sandbox_app = typer.Typer(help="Cold start: sandboxed observation and manifest proposals.")


def _client(base_url: str, token: str) -> httpx.Client:
    return httpx.Client(
        base_url=base_url.rstrip("/"),
        headers={"Authorization": f"Bearer {token}"},
        timeout=httpx.Timeout(30.0),
    )


@sandbox_app.command()
def run(
    agent_id: str = typer.Argument(..., help="The agent to observe"),
    scope: str = typer.Option(..., "--scope", help="The synthetic all-allow scope"),
    base_url: str = typer.Option("http://localhost:8000", "--url"),
    token: str = typer.Option(..., "--token", envvar="AGENTIC_AUTH_ADMIN_TOKEN"),
    deadline: int | None = typer.Option(None, "--deadline-seconds"),
    tools: list[str] = typer.Option([], "--tool", help="A mock tool ref to expose"),
) -> None:
    """Start an observation run. Every tool is a mock that records and performs nothing."""
    body: dict = {"scope": scope, "mock_tools": list(tools)}
    if deadline is not None:
        body["deadline_seconds"] = deadline
    with _client(base_url, token) as client:
        response = client.post(f"/v1/agents/{agent_id}/sandbox", json=body)
    if response.status_code != 201:
        rprint(f"[red]could not start a run:[/red] {response.status_code} {response.text}")
        raise typer.Exit(code=1)
    rprint(json.dumps(response.json(), indent=2))


@sandbox_app.command()
def propose(
    agent_id: str = typer.Argument(...),
    base_url: str = typer.Option("http://localhost:8000", "--url"),
    token: str = typer.Option(..., "--token", envvar="AGENTIC_AUTH_ADMIN_TOKEN"),
    run_id: str | None = typer.Option(None, "--run"),
) -> None:
    """Read the manifest proposed from a completed run. It governs nothing yet."""
    params = {"run_id": run_id} if run_id else None
    with _client(base_url, token) as client:
        response = client.get(f"/v1/agents/{agent_id}/proposed-manifest", params=params)
    if response.status_code != 200:
        rprint(f"[red]no proposal:[/red] {response.status_code} {response.text}")
        raise typer.Exit(code=1)

    body = response.json()
    if body.get("covers_no_behaviour"):
        rprint(
            "[yellow]This run observed no behaviour.[/yellow] The proposal below is empty, "
            "which is not the same as an agent that needs nothing."
        )
    errors = (body["doc"].get("x-proposal") or {}).get("recorder_errors", 0)
    if errors:
        rprint(
            f"[yellow]{errors} event(s) were lost while recording.[/yellow] The proposal "
            "may be narrower than the agent's real behaviour."
        )
    rprint(json.dumps(body["doc"], indent=2))


@sandbox_app.command("propose-local")
def propose_local(
    trace: Path = typer.Argument(..., help="An edge trace produced by `drift record`"),
    agent: str = typer.Option(..., "--agent"),
    run_id: str = typer.Option("local", "--run-id"),
) -> None:
    """Fold a trace file into a proposal locally, without the control plane."""
    document = propose_document(
        EdgeTrace.model_validate_json(trace.read_text()), agent, run_id=run_id
    )
    rprint(json.dumps(document, indent=2))


@sandbox_app.command()
def ratify(
    agent_id: str = typer.Argument(...),
    run_id: str = typer.Option(..., "--run"),
    base_url: str = typer.Option("http://localhost:8000", "--url"),
    token: str = typer.Option(..., "--token", envvar="AGENTIC_AUTH_ADMIN_TOKEN"),
    document: Path | None = typer.Option(None, "--doc", help="An edited proposal to pin"),
) -> None:
    """Pin a proposal as the agent's manifest. This is the human decision (FR-037)."""
    body: dict = {"run_id": run_id}
    if document is not None:
        edited = json.loads(document.read_text())
        added = added_by_administrator(edited)
        if any(added.values()):
            # Not a refusal — editing is legitimate. But the operator should see what
            # they are adding beyond what anyone observed, before it becomes policy.
            rprint("[yellow]Beyond what the run observed, this pins:[/yellow]")
            rprint(json.dumps({k: v for k, v in added.items() if v}, indent=2))
        body["doc"] = edited

    with _client(base_url, token) as client:
        response = client.post(f"/v1/agents/{agent_id}/proposed-manifest/ratify", json=body)
    if response.status_code != 201:
        rprint(f"[red]not ratified:[/red] {response.status_code} {response.text}")
        raise typer.Exit(code=1)
    rprint(json.dumps(response.json(), indent=2))


__all__ = ["sandbox_app"]
