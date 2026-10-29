"""Register an agent, pin & read back its manifest."""

from __future__ import annotations

import httpx

from tests.fixtures.manifests import base_manifest


async def test_register_returns_201_and_version_1(client: httpx.AsyncClient, admin_headers) -> None:
    body = {"name": "kb-search-agent", "manifest": base_manifest()}
    resp = await client.post("/v1/agents", json=body, headers=admin_headers)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["manifest_version"] == 1
    assert data["status"] == "reconciled"
    assert data["agent_id"]


async def test_manifest_reads_back_byte_identical(client: httpx.AsyncClient, admin_headers) -> None:
    manifest = base_manifest()
    await client.post(
        "/v1/agents", json={"name": "kb-search-agent", "manifest": manifest}, headers=admin_headers
    )
    resp = await client.get("/v1/manifests/kb-search-agent?version=1", headers=admin_headers)
    assert resp.status_code == 200
    doc = resp.json()["doc"]
    from app.schemas.manifest import AgentManifest

    assert (
        AgentManifest.model_validate(doc).canonical_doc()
        == AgentManifest.model_validate(manifest).canonical_doc()
    )


async def test_malformed_manifest_422_and_nothing_persisted(
    client: httpx.AsyncClient, admin_headers
) -> None:
    bad = base_manifest()
    del bad["spec"]["hop_budget"]
    resp = await client.post(
        "/v1/agents", json={"name": "kb-search-agent", "manifest": bad}, headers=admin_headers
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"

    listing = await client.get("/v1/agents", headers=admin_headers)
    assert listing.json()["data"] == []


async def test_missing_admin_token_401(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/agents", json={"name": "x", "manifest": base_manifest("x")})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_get_unknown_manifest_404(client: httpx.AsyncClient, admin_headers) -> None:
    resp = await client.get("/v1/manifests/ghost", headers=admin_headers)
    assert resp.status_code == 404


async def test_list_agents_pagination(client: httpx.AsyncClient, admin_headers) -> None:
    for i in range(3):
        name = f"agent-{i}"
        await client.post(
            "/v1/agents",
            json={"name": name, "manifest": base_manifest(name)},
            headers=admin_headers,
        )
    page1 = (await client.get("/v1/agents?limit=2", headers=admin_headers)).json()
    assert len(page1["data"]) == 2
    assert page1["page"]["next_cursor"] is not None
    page2 = (
        await client.get(
            f"/v1/agents?limit=2&cursor={page1['page']['next_cursor']}", headers=admin_headers
        )
    ).json()
    assert len(page2["data"]) == 1
    assert page2["page"]["next_cursor"] is None


# -- Phase 4: identity state on the listing -----------------------------------------


async def test_new_agents_are_registered_and_the_status_filter_works(
    client: httpx.AsyncClient, admin_headers
) -> None:
    await client.post(
        "/v1/agents", json={"name": "a1", "manifest": base_manifest("a1")}, headers=admin_headers
    )
    listing = (await client.get("/v1/agents", headers=admin_headers)).json()
    assert listing["data"][0]["status"] == "registered"
    assert listing["data"][0]["trust_anchor_version"] is None

    only_enrolled = (await client.get("/v1/agents?status=enrolled", headers=admin_headers)).json()
    assert only_enrolled["data"] == []

    bad = await client.get("/v1/agents?status=bogus", headers=admin_headers)
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "validation_error"
