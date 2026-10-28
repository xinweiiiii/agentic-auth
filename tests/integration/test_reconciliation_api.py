"""US2 — reconciliation over the API: actionable diff, needs-review + override."""

from __future__ import annotations

import httpx

from tests.fixtures.manifests import base_manifest, discovery_down_manifest, overbroad_manifest


async def _register(client, name, manifest, headers, override=None):
    body = {"name": name, "manifest": manifest}
    if override:
        body["override"] = override
    return await client.post("/v1/agents", json=body, headers=headers)


async def test_overbroad_manifest_422_with_actionable_diff(
    client: httpx.AsyncClient, admin_headers
) -> None:
    resp = await _register(client, "kb-search-agent", overbroad_manifest(), admin_headers)
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "reconciliation_rejected"
    diff = err["details"]["diff"]
    assert diff, "diff must be non-empty"
    for entry in diff:
        assert entry["tool_ref"]
        assert entry["remedy"]
    offending = [d for d in diff if d["code"] == "DECLARED_EXCEEDS_DISCOVERED"][0]
    assert offending["tool_ref"] == "mcp://accounts.internal/read_account"


async def test_rejected_manifest_and_report_are_persisted(
    client: httpx.AsyncClient, admin_headers
) -> None:
    await _register(client, "kb-search-agent", overbroad_manifest(), admin_headers)
    # agent row exists with a rejected manifest v1
    agents = (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    assert agents[0]["latest_status"] == "rejected"
    assert agents[0]["latest_manifest_version"] == 1
    agent_id = agents[0]["id"]
    report = await client.get(f"/v1/agents/{agent_id}/reconciliation", headers=admin_headers)
    assert report.status_code == 200
    assert report.json()["status"] == "rejected"
    assert report.json()["diff"]


async def test_discovery_unavailable_409_then_override_201(
    client: httpx.AsyncClient, admin_headers
) -> None:
    manifest = discovery_down_manifest()
    resp = await _register(client, "down-agent", manifest, admin_headers)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "needs_review"

    # resubmit a NEW version with an override reason
    ok = await client.post(
        "/v1/manifests",
        json={
            "agent": "down-agent",
            "manifest": manifest,
            "override": {"reason": "down.internal confirmed manually with the KB team"},
        },
        headers=admin_headers,
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["status"] == "reconciled"
    assert ok.json()["version"] == 2

    agent_id = (await client.get("/v1/agents", headers=admin_headers)).json()["data"][0]["id"]
    report = (
        await client.get(f"/v1/agents/{agent_id}/reconciliation", headers=admin_headers)
    ).json()
    assert report["discovery_ok"] is False
    assert report["status"] == "reconciled"


async def test_reconciliation_404_when_no_manifest(
    client: httpx.AsyncClient, admin_headers
) -> None:
    # register a clean agent, then query a random agent id
    await _register(client, "kb-search-agent", base_manifest(), admin_headers)
    resp = await client.get(
        "/v1/agents/00000000-0000-0000-0000-000000000000/reconciliation", headers=admin_headers
    )
    assert resp.status_code == 404
