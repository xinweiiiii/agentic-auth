"""Nothing secret lands anywhere durable (SC-018).

Phase 4 established the rule: no token, challenge, private key or credential in an audit
row, a metric, or a log. Phase 5 adds three new things that could break it — a step-up
challenge, a narrowed token relayed through a proxy, and an upstream tool's own
credential — so the sweep is extended rather than assumed to still hold.

The approach is deliberately blunt. Rather than reasoning about which fields *should*
be safe, the tests drive real flows and then grep everything that was written for the
actual secret values. A rule that is only true by argument stops being true the first
time someone adds a field.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from agentic_auth.models import AuditDecision, StepUpGrant
from agentic_auth.services.stepup import hash_challenge
from tests.conftest import ADMIN_TOKEN
from tests.fixtures.bank import BALANCE_AGENT, BANK_ASSISTANT, SUPPORT_AGENT, USER, bank_docs
from tests.fixtures.hops import authorize, hop, register_agents

WITHHELD = "kb.internal"


@pytest.fixture
async def granular(client, admin_headers, flags):
    flags(consent_granularity_enabled=True, step_up_enabled=True, taint_enforcement_enabled=False)
    await register_agents(client, admin_headers, bank_docs(widened=True, trust_kb=True))


async def _session(client, admin_headers):
    r = await client.post(
        "/v1/consent",
        headers=admin_headers,
        json={
            "scope": BANK_ASSISTANT,
            "user_sub": USER,
            "data_classes": ["account.read"],
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


async def _blocked(client, session):
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    decision = (
        await authorize(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class=WITHHELD)
    ).json()
    return t1, decision


# -- the step-up challenge (Phase 5's new bearer-shaped value) -------------------------


async def test_no_challenge_value_reaches_any_durable_store(
    client, admin_headers, granular, db_session, redis_client
) -> None:
    """A stored challenge would be a bearer credential sitting where anyone with read
    access could take it and approve a widening nobody asked for."""
    session = await _session(client, admin_headers)
    _, decision = await _blocked(client, session)
    challenge_id = decision["step_up"]["challenge_id"]

    await client.post(
        "/v1/consent/step-up/complete",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"challenge_id": challenge_id, "approved": True},
    )

    grants = (await db_session.execute(select(StepUpGrant))).scalars().all()
    rows = (await db_session.execute(select(AuditDecision))).scalars().all()

    assert grants and grants[0].challenge_hash == hash_challenge(challenge_id)
    for grant in grants:
        assert challenge_id not in json.dumps(
            {c.name: str(getattr(grant, c.name)) for c in StepUpGrant.__table__.columns}
        )
    for row in rows:
        serialised = json.dumps(
            {c.name: str(getattr(row, c.name)) for c in AuditDecision.__table__.columns}
        )
        assert challenge_id not in serialised

    # And it is gone from the cache the moment it is consumed.
    assert await redis_client.get(f"challenge:{challenge_id}") is None


async def test_the_challenge_is_consumed_from_redis_on_answer(
    client, admin_headers, granular, redis_client
) -> None:
    session = await _session(client, admin_headers)
    _, decision = await _blocked(client, session)
    challenge_id = decision["step_up"]["challenge_id"]

    assert await redis_client.get(f"challenge:{challenge_id}") is not None

    await client.post(
        "/v1/consent/step-up/complete",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"challenge_id": challenge_id, "approved": False},
    )

    assert await redis_client.get(f"challenge:{challenge_id}") is None


# -- no token of any kind in an audit row ------------------------------------------------


async def test_no_audit_row_contains_a_token(client, admin_headers, granular, db_session) -> None:
    session = await _session(client, admin_headers)
    token, _ = await _blocked(client, session)

    rows = (await db_session.execute(select(AuditDecision))).scalars().all()

    for row in rows:
        serialised = json.dumps(
            {c.name: str(getattr(row, c.name)) for c in AuditDecision.__table__.columns}
        )
        assert token not in serialised
        assert session["root_grant"] not in serialised
        assert ADMIN_TOKEN not in serialised


# -- no secret in a metric label (bounded cardinality, and no identities) ------------------


async def test_no_phase_5_metric_carries_a_secret_or_an_identity(
    client, admin_headers, granular, metrics_registry
) -> None:
    """Phase 4's rule, extended to the Phase 5 counters. Session ids and action ids are
    excluded too — not because they are secret, but because they are unbounded, and the
    audit trail already provides that correlation properly."""
    session = await _session(client, admin_headers)
    token, decision = await _blocked(client, session)
    await client.post(
        "/v1/consent/step-up/complete",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"challenge_id": decision["step_up"]["challenge_id"], "approved": True},
    )

    forbidden = {
        token,
        session["root_grant"],
        session["session_id"],
        decision["step_up"]["challenge_id"],
        decision["action_id"],
        ADMIN_TOKEN,
    }

    for family in metrics_registry.registry.collect():
        for sample in family.samples:
            for value in sample.labels.values():
                assert value not in forbidden, f"{sample.name}: {value!r}"


# -- the connector proxy never hands the agent what it attached ----------------------------


async def test_the_proxy_returns_no_upstream_credential() -> None:
    """Covered end to end in test_mcp_proxy.py; asserted here as part of the sweep so a
    future change to the proxy trips this file too."""
    from agentic_auth.boundary.mcp import _jsonrpc_refusal
    from tests.fixtures.mcp.server import UPSTREAM_TOKEN

    class _Outcome:
        response = type("R", (), {"body": b'{"error":{"message":"denied"}}'})()
        attribution = type("A", (), {"outcome": "deny", "reason": "OUT_OF_SCOPE", "target": "t"})()

    body = json.dumps(_jsonrpc_refusal(1, _Outcome()).body.decode())

    assert UPSTREAM_TOKEN not in body
