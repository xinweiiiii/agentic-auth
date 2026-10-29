"""Scope catalog reads (latest, pinned, 404, cache back-fill)."""

from __future__ import annotations

import httpx

from tests.fixtures.manifests import base_manifest


async def _register(client, name, manifest, headers):
    return await client.post(
        "/v1/agents", json={"name": name, "manifest": manifest}, headers=headers
    )


async def test_catalog_matches_manifest(client: httpx.AsyncClient, admin_headers) -> None:
    await _register(client, "kb-search-agent", base_manifest(), admin_headers)
    cat = (await client.get("/v1/scopes/kb-search-agent/catalog", headers=admin_headers)).json()
    assert cat["scope"] == "kb-search-agent"
    refs = {t["ref"] for t in cat["tools"]}
    assert refs == {"mcp://kb.internal/search"}
    assert set(cat["data_classes"]["reads"]) == {"kb.public", "kb.internal"}
    assert cat["hop_budget"] == 4


async def test_unknown_scope_404(client: httpx.AsyncClient, admin_headers) -> None:
    resp = await client.get("/v1/scopes/nope/catalog", headers=admin_headers)
    assert resp.status_code == 404


async def test_pinned_version_read(client: httpx.AsyncClient, admin_headers) -> None:
    await _register(client, "kb-search-agent", base_manifest(), admin_headers)
    v1 = (await client.get("/v1/scopes/kb-search-agent/catalog", headers=admin_headers)).json()[
        "version"
    ]
    resp = await client.get(
        f"/v1/scopes/kb-search-agent/catalog?version={v1}", headers=admin_headers
    )
    assert resp.status_code == 200
    assert resp.json()["version"] == v1


async def test_cache_backfill_after_flush(
    client: httpx.AsyncClient, admin_headers, redis_client
) -> None:
    await _register(client, "kb-search-agent", base_manifest(), admin_headers)
    await redis_client.flushdb()  # drop the warm-write
    cat = (await client.get("/v1/scopes/kb-search-agent/catalog", headers=admin_headers)).json()
    assert await redis_client.get(f"dag:kb-search-agent:{cat['version']}") is not None
