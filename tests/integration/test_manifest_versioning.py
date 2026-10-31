"""Immutable, server-assigned, monotonic versioning."""

from __future__ import annotations

import asyncio
from copy import deepcopy

import httpx

from tests.fixtures.manifests import base_manifest


async def _register(client, name, manifest, headers):
    return await client.post(
        "/v1/agents", json={"name": name, "manifest": manifest}, headers=headers
    )


async def test_new_version_leaves_v1_byte_identical(
    client: httpx.AsyncClient, admin_headers
) -> None:
    v1_doc = base_manifest()
    await _register(client, "kb-search-agent", v1_doc, admin_headers)

    v2_doc = deepcopy(v1_doc)
    v2_doc["spec"]["hop_budget"] = 5
    r = await client.post(
        "/v1/manifests",
        json={"agent": "kb-search-agent", "manifest": v2_doc},
        headers=admin_headers,
    )
    assert r.status_code == 201
    assert r.json()["version"] == 2

    read_v1 = (
        await client.get("/v1/manifests/kb-search-agent?version=1", headers=admin_headers)
    ).json()
    from agentic_auth.schemas.manifest import AgentManifest

    assert (
        AgentManifest.model_validate(read_v1["doc"]).canonical_doc()
        == AgentManifest.model_validate(v1_doc).canonical_doc()
    )
    assert read_v1["version"] == 1


async def test_identical_resubmission_still_bumps_version(
    client: httpx.AsyncClient, admin_headers
) -> None:
    doc = base_manifest()
    await _register(client, "kb-search-agent", doc, admin_headers)
    r = await client.post(
        "/v1/manifests", json={"agent": "kb-search-agent", "manifest": doc}, headers=admin_headers
    )
    assert r.json()["version"] == 2


async def test_client_supplied_version_rejected(client: httpx.AsyncClient, admin_headers) -> None:
    doc = base_manifest()
    doc["metadata"]["version"] = 7
    r = await _register(client, "kb-search-agent", doc, admin_headers)
    assert r.status_code == 422


async def test_submit_to_unknown_agent_404(client: httpx.AsyncClient, admin_headers) -> None:
    r = await client.post(
        "/v1/manifests",
        json={"agent": "ghost", "manifest": base_manifest("ghost")},
        headers=admin_headers,
    )
    assert r.status_code == 404


async def test_concurrent_submissions_are_gap_free(
    client: httpx.AsyncClient, admin_headers
) -> None:
    await _register(client, "kb-search-agent", base_manifest(), admin_headers)
    docs = [deepcopy(base_manifest()) for _ in range(4)]
    for i, d in enumerate(docs):
        d["spec"]["hop_budget"] = 3 + (i % 4)
    results = await asyncio.gather(
        *(
            client.post(
                "/v1/manifests",
                json={"agent": "kb-search-agent", "manifest": d},
                headers=admin_headers,
            )
            for d in docs
        )
    )
    assert all(r.status_code == 201 for r in results)
    versions = sorted(r.json()["version"] for r in results)
    assert versions == [2, 3, 4, 5]
