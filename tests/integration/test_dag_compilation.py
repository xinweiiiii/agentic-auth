"""DAG compilation over the API: chain compiles, cycle rejected."""

from __future__ import annotations

import httpx


def _agent(name: str, *, hop_budget: int, downstream=None) -> dict:
    return {
        "apiVersion": "agentic-auth/v1",
        "kind": "AgentManifest",
        "metadata": {"agent": name},
        "spec": {
            "tools": [{"ref": "mcp://kb.internal/search", "data_classes": ["kb.public"]}],
            "data_classes": {"reads": ["kb.public"], "writes": []},
            "downstream_agents": downstream or [],
            "hop_budget": hop_budget,
        },
    }


async def _register(client, name, manifest, headers):
    return await client.post(
        "/v1/agents", json={"name": name, "manifest": manifest}, headers=headers
    )


async def test_chain_compiles_and_recompiles(client: httpx.AsyncClient, admin_headers) -> None:
    await _register(client, "leaf", _agent("leaf", hop_budget=3), admin_headers)
    await _register(
        client,
        "mid",
        _agent("mid", hop_budget=4, downstream=[{"ref": "agent://leaf", "max_hop_depth": 2}]),
        admin_headers,
    )
    r = await _register(
        client,
        "root",
        _agent("root", hop_budget=5, downstream=[{"ref": "agent://mid", "max_hop_depth": 4}]),
        admin_headers,
    )
    assert r.status_code == 201

    cat = (await client.get("/v1/scopes/root/catalog", headers=admin_headers)).json()
    assert cat["version"] >= 1
    assert "kb.public" in cat["data_classes"]["reads"]

    # a new version of leaf recompiles; old DAG version stays readable
    v1 = cat["version"]
    await client.post(
        "/v1/manifests",
        json={
            "agent": "root",
            "manifest": _agent(
                "root", hop_budget=5, downstream=[{"ref": "agent://mid", "max_hop_depth": 4}]
            ),
        },
        headers=admin_headers,
    )
    old = await client.get(f"/v1/scopes/root/catalog?version={v1}", headers=admin_headers)
    assert old.status_code == 200


async def test_cycle_rejected_and_nothing_persisted(
    client: httpx.AsyncClient, admin_headers
) -> None:
    await _register(
        client,
        "a",
        _agent("a", hop_budget=4, downstream=[{"ref": "agent://b", "max_hop_depth": 2}]),
        admin_headers,
    )
    await _register(client, "b", _agent("b", hop_budget=3), admin_headers)

    resp = await client.post(
        "/v1/manifests",
        json={
            "agent": "b",
            "manifest": _agent(
                "b", hop_budget=3, downstream=[{"ref": "agent://a", "max_hop_depth": 2}]
            ),
        },
        headers=admin_headers,
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "dag_cycle"

    # b still has only version 1
    b = (await client.get("/v1/manifests/b", headers=admin_headers)).json()
    assert b["version"] == 1
