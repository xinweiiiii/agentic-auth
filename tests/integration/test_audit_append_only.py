"""Audit rows cannot be changed — by anyone (T019, FR-003, SC-004).

Two different mechanisms, tested separately, because each alone has a gap. Grants do not
bind the table owner; a trigger alone is not defence in depth. Here the owner is stopped by
the trigger, and the runtime role is stopped before the trigger is even reached.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from tests.fixtures.bank import BALANCE_AGENT, BANK_ASSISTANT, bank_docs
from tests.fixtures.hops import authorize, consent_session, register_agents

APPEND_ONLY = "55000"
INSUFFICIENT_PRIVILEGE = "42501"

UPDATE = "UPDATE audit_decisions SET outcome = 'deny', deny_reason = 'OUT_OF_SCOPE' WHERE id = :i"
DELETE = "DELETE FROM audit_decisions WHERE id = :i"


def _sqlstate(error: DBAPIError) -> str | None:
    for candidate in (error.orig, getattr(error.orig, "__cause__", None)):
        for attr in ("sqlstate", "pgcode"):
            value = getattr(candidate, attr, None)
            if value:
                return str(value)
    return None


@pytest.fixture
async def recorded(client, admin_headers) -> dict[str, str]:
    await register_agents(client, admin_headers, bank_docs())
    session = await consent_session(client, admin_headers, BANK_ASSISTANT)
    decision = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
    ).json()
    assert decision["outcome"] == "allow" and decision["recorded"] is True, decision
    return {"session_id": session["session_id"], "action_id": decision["action_id"]}


@pytest.mark.parametrize("statement", [UPDATE, DELETE], ids=["update", "delete"])
async def test_the_table_owner_cannot_change_a_row(db_session, recorded, statement) -> None:
    with pytest.raises(DBAPIError) as exc:
        await db_session.execute(text(statement), {"i": recorded["action_id"]})
    await db_session.rollback()

    assert _sqlstate(exc.value) == APPEND_ONLY
    assert "audit_decisions is append-only" in str(exc.value)

    row = (
        await db_session.execute(
            text("SELECT outcome FROM audit_decisions WHERE id = :i"), {"i": recorded["action_id"]}
        )
    ).one()
    assert row.outcome == "allow"


@pytest.mark.parametrize(
    "statement", [UPDATE, DELETE, "TRUNCATE audit_decisions"], ids=["update", "delete", "truncate"]
)
async def test_the_runtime_role_cannot_change_a_row(writer_engine, recorded, statement) -> None:
    params = {"i": recorded["action_id"]} if ":i" in statement else {}
    async with writer_engine.connect() as conn:
        with pytest.raises(DBAPIError) as exc:
            await conn.execute(text(statement), params)

    assert _sqlstate(exc.value) == INSUFFICIENT_PRIVILEGE


async def test_the_runtime_role_can_append_and_read(writer_engine, recorded) -> None:
    session_id = uuid.UUID(recorded["session_id"])
    async with writer_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO audit_decisions (id, session_id, caller, target, target_kind, "
                "data_class, hop, outcome, recoverable, enforced, policy_version, act_chain, "
                "chain_break) VALUES (:id, :s, 'user:alice', 'agent://balance-agent', 'agent', "
                "'account.read', 1, 'allow', false, true, 1, CAST(:chain AS jsonb), 'LEGACY_TOKEN')"
            ),
            {"id": uuid.uuid4(), "s": session_id, "chain": '["user:alice"]'},
        )
        count = await conn.scalar(
            text("SELECT count(*) FROM audit_decisions WHERE session_id = :s"), {"s": session_id}
        )

    assert count == 2
