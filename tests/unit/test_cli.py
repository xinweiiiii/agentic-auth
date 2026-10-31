"""Agentic-auth manifest validate|lint|diff + server parity."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import yaml
from httpx import ASGITransport
from typer.testing import CliRunner

from agentic_auth.cli import app
from agentic_auth.services.discovery import DiscoveryClient
from tests.fixtures.bank import BALANCE_AGENT, BANK_ASSISTANT, SUPPORT_AGENT, bank_docs
from tests.fixtures.discovery.server import fake_discovery_app
from tests.fixtures.manifests import base_manifest, discovery_down_manifest, overbroad_manifest

runner = CliRunner()


@pytest.fixture(autouse=True)
def _wire_fake_discovery(monkeypatch):
    def _factory(timeout: float) -> DiscoveryClient:
        return DiscoveryClient(
            client=httpx.AsyncClient(transport=ASGITransport(app=fake_discovery_app))
        )

    monkeypatch.setattr("agentic_auth.cli.manifest._make_discovery_client", _factory)


def _write(tmp_path, doc, name="m.yaml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(doc))
    return str(p)


def test_validate_ok(tmp_path):
    res = runner.invoke(app, ["manifest", "validate", _write(tmp_path, base_manifest()), "--json"])
    assert res.exit_code == 0
    assert json.loads(res.stdout)["valid"] is True


def test_validate_reports_missing_field(tmp_path):
    doc = base_manifest()
    del doc["spec"]["hop_budget"]
    res = runner.invoke(app, ["manifest", "validate", _write(tmp_path, doc), "--json"])
    assert res.exit_code == 1
    errs = json.loads(res.stdout)["errors"]
    assert any("hop_budget" in ".".join(e["loc"]) for e in errs)


def test_validate_missing_file():
    res = runner.invoke(app, ["manifest", "validate", "/no/such/file.yaml"])
    assert res.exit_code == 2


def test_lint_warns_without_failing(tmp_path):
    doc = base_manifest()
    doc["spec"]["data_classes"]["reads"].append("unused.class")
    res = runner.invoke(app, ["manifest", "lint", _write(tmp_path, doc), "--json"])
    assert res.exit_code == 0
    codes = {w["code"] for w in json.loads(res.stdout)["warnings"]}
    assert "UNUSED_DATA_CLASS" in codes


def test_lint_strict_fails_on_warning(tmp_path):
    doc = base_manifest()
    doc["spec"]["data_classes"]["reads"].append("unused.class")
    res = runner.invoke(app, ["manifest", "lint", _write(tmp_path, doc), "--json", "--strict"])
    assert res.exit_code == 1


def test_diff_clean(tmp_path):
    res = runner.invoke(app, ["manifest", "diff", _write(tmp_path, base_manifest()), "--json"])
    assert res.exit_code == 0
    assert json.loads(res.stdout) == {"status": "reconciled", "diff": []}


def test_diff_overbroad(tmp_path):
    res = runner.invoke(app, ["manifest", "diff", _write(tmp_path, overbroad_manifest()), "--json"])
    assert res.exit_code == 1
    out = json.loads(res.stdout)
    assert out["status"] == "rejected"
    assert out["diff"][0]["code"] == "DECLARED_EXCEEDS_DISCOVERED"


def test_diff_discovery_unavailable(tmp_path):
    res = runner.invoke(
        app, ["manifest", "diff", _write(tmp_path, discovery_down_manifest()), "--json"]
    )
    assert res.exit_code == 1
    out = json.loads(res.stdout)
    assert out["status"] == "needs_review"
    assert out["diff"][0]["code"] == "DISCOVERY_UNAVAILABLE"


async def test_cli_diff_matches_api(client, admin_headers, tmp_path):
    doc = overbroad_manifest()
    api = await client.post(
        "/v1/agents", json={"name": "kb-search-agent", "manifest": doc}, headers=admin_headers
    )
    api_diff = api.json()["error"]["details"]["diff"]

    cli = await asyncio.to_thread(
        runner.invoke, app, ["manifest", "diff", _write(tmp_path, doc), "--json"]
    )
    cli_diff = json.loads(cli.stdout)["diff"]

    assert cli_diff == api_diff


# -- register-dir --------------------------------------------------------


def _bank_dir(tmp_path):
    directory = tmp_path / "manifests"
    directory.mkdir()
    for name, doc in bank_docs().items():
        (directory / f"{name}.yaml").write_text(yaml.safe_dump(doc))
    return directory


def _control_plane(monkeypatch, *, reject: str | None = None):
    seen: list[tuple[str | None, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append((request.headers.get("authorization"), body))
        if body["name"] == reject:
            return httpx.Response(
                422,
                json={
                    "error": {
                        "code": "reconciliation_rejected",
                        "message": "manifest rejected",
                        "details": {
                            "diff": [
                                {
                                    "code": "UNKNOWN_TOOL",
                                    "tool_ref": "mcp://x/y",
                                    "remedy": "remove it",
                                }
                            ]
                        },
                    }
                },
            )
        return httpx.Response(
            201,
            json={
                "agent_id": "7c1e0000-0000-4000-8000-000000000001",
                "manifest_version": 1,
                "status": "reconciled",
            },
        )

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        "agentic_auth.cli.manifest._make_http_client",
        lambda timeout: httpx.AsyncClient(transport=transport),
    )
    return seen


def _register(directory):
    return runner.invoke(
        app,
        [
            "manifest",
            "register-dir",
            str(directory),
            "--control-plane",
            "http://control-plane.test",
            "--override-reason",
            "ci drift recording",
        ],
    )


def test_register_dir_registers_leaf_first_with_the_override(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTIC_AUTH_ADMIN_TOKEN", "ci-secret-token")
    seen = _control_plane(monkeypatch)

    res = _register(_bank_dir(tmp_path))

    assert res.exit_code == 0, res.output
    assert [body["name"] for _, body in seen] == [SUPPORT_AGENT, BALANCE_AGENT, BANK_ASSISTANT]
    assert all(body["override"] == {"reason": "ci drift recording"} for _, body in seen)
    assert all(auth == "Bearer ci-secret-token" for auth, _ in seen)
    assert "ci-secret-token" not in res.output


def test_register_dir_fails_when_a_manifest_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTIC_AUTH_ADMIN_TOKEN", "ci-secret-token")
    _control_plane(monkeypatch, reject=BALANCE_AGENT)

    res = _register(_bank_dir(tmp_path))

    assert res.exit_code == 1
    assert "UNKNOWN_TOOL" in res.output


def test_register_dir_requires_the_admin_token_in_the_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTIC_AUTH_ADMIN_TOKEN", raising=False)
    seen = _control_plane(monkeypatch)

    res = _register(_bank_dir(tmp_path))

    assert res.exit_code == 2
    assert seen == []
