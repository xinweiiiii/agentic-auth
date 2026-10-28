"""US2 — removing a declared edge denies the hop, with no change to caller code (T037).

SC-003. This is the runtime twin of Phase 3's CI drift check: the manifest moved, the
agent did not, and the next hop along the removed edge stops working.
"""

from __future__ import annotations

from tests.fixtures.chains import KB_SEARCH, ORCHESTRATOR, chain_docs

USER = "user:alice"


async def _authorize(client, token, **body):
    body.setdefault("guarantee", "full")  # mandatory since Phase 5 (FR-018)
    return await client.post(
        "/v1/authorize", headers={"Authorization": f"Bearer {token}"}, json=body
    )


async def _hop_one(client, session):
    """The identical call, made the identical way, before and after the drift."""
    return await _authorize(
        client,
        session["root_grant"],
        session_id=session["session_id"],
        caller=USER,
        target=f"agent://{KB_SEARCH}",
        data_class="kb.internal",
    )


async def test_removing_a_declared_edge_denies_that_hop(
    client, admin_headers, register_chain, consent
) -> None:
    await register_chain()

    before = await consent()
    assert (await _hop_one(client, before)).json()["outcome"] == "allow"

    # Publish a manifest version without the orchestrator -> kb-search declaration.
    drifted = chain_docs(include_kb_edge=False)[ORCHESTRATOR]
    r = await client.post(
        "/v1/manifests",
        headers=admin_headers,
        json={"agent": ORCHESTRATOR, "manifest": drifted},
    )
    assert r.status_code == 201

    after = await consent()  # pins the new policy version
    assert after["policy_version"] > before["policy_version"]

    body = (await _hop_one(client, after)).json()
    assert body["outcome"] == "deny"
    assert body["reason"] == "EDGE_NOT_IN_DAG"
    assert body["recoverable"] is False
    assert "not a declared edge" in body["message"]


async def test_a_session_pinned_before_the_drift_keeps_working(
    client, admin_headers, register_chain, consent
) -> None:
    """SC-009 from the other side: the pin protects work already in flight."""
    await register_chain()
    before = await consent()

    await client.post(
        "/v1/manifests",
        headers=admin_headers,
        json={"agent": ORCHESTRATOR, "manifest": chain_docs(include_kb_edge=False)[ORCHESTRATOR]},
    )

    assert (await _hop_one(client, before)).json()["outcome"] == "allow"


async def test_the_drift_is_recorded_as_a_denial(
    client, admin_headers, register_chain, consent, db_session
) -> None:
    from sqlalchemy import text

    await register_chain()
    await client.post(
        "/v1/manifests",
        headers=admin_headers,
        json={"agent": ORCHESTRATOR, "manifest": chain_docs(include_kb_edge=False)[ORCHESTRATOR]},
    )
    session = await consent()
    await _hop_one(client, session)

    row = (
        (
            await db_session.execute(
                text("SELECT deny_reason, target, hop FROM audit_decisions WHERE session_id = :i"),
                {"i": session["session_id"]},
            )
        )
        .mappings()
        .one()
    )
    assert row["deny_reason"] == "EDGE_NOT_IN_DAG"
    assert row["target"] == f"agent://{KB_SEARCH}"
    assert row["hop"] == 1
