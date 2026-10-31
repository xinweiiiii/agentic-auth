"""One query answers "who authorized this, and through which agents?".

Every successful response is also validated against
the published contract, so the API and ``contracts/audit-plane.openapi.yaml`` cannot drift.
"""

from __future__ import annotations

import asyncio
import uuid

import jsonschema
import pytest
from sqlalchemy import text

from agentic_auth.api.service_deps import get_token_profile
from agentic_auth.config import get_settings
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    DRIFTED_CALLS,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    USER,
    bank_docs,
    deep_chain_docs,
)
from tests.fixtures.chains import KB_SEARCH, ORCHESTRATOR, SUMMARIZER
from tests.fixtures.contracts import component_schema
from tests.fixtures.hops import authorize, consent_session, register_agents, run_calls

CONTRACT = "audit-plane.openapi.yaml"


@pytest.fixture(scope="module")
def chain_schema() -> dict:
    return component_schema(CONTRACT, "ChainRead")


def assert_matches_contract(body: dict, schema: dict) -> None:
    jsonschema.Draft202012Validator(schema).validate(body)


async def get_chain(client, action_id, headers):
    return await client.get(f"/v1/audit/actions/{action_id}/chain", headers=headers)


# -- the PRD scenario, and depth ------------------------------------------------


async def test_the_prd_scenario_is_answered_by_one_query(
    client, admin_headers, chain_schema
) -> None:
    await register_agents(client, admin_headers, bank_docs())
    session = await consent_session(client, admin_headers, BANK_ASSISTANT)
    decisions, _ = await run_calls(client, session["root_grant"], DRIFTED_CALLS)
    refused = decisions[-1]
    assert refused["outcome"] == "deny"

    r = await get_chain(client, refused["action_id"], admin_headers)

    assert r.status_code == 200, r.text
    body = r.json()
    assert_matches_contract(body, chain_schema)
    assert body["action_id"] == refused["action_id"]
    assert body["complete"] is True
    assert body["break"] is None
    assert body["root_consent"]["user_sub"] == USER
    assert body["root_consent"]["scope"] == BANK_ASSISTANT
    assert body["root_consent"]["session_id"] == session["session_id"]
    assert body["policy_version"] == session["policy_version"]

    chain = body["chain"]
    assert [h["hop"] for h in chain] == [1, 2, 3]
    assert [h["acting_agent"] for h in chain] == [BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT]
    assert [h["action_id"] for h in chain] == [d["action_id"] for d in decisions]
    assert (chain[-1]["target"], chain[-1]["decision"], chain[-1]["deny_reason"]) == (
        TERMINATE_ACCOUNT,
        "deny",
        "OUT_OF_SCOPE",
    )
    assert all("unavailable" not in h for h in chain)


async def test_a_five_hop_chain_returns_every_hop_in_order(
    client, admin_headers, chain_schema
) -> None:
    docs, calls = deep_chain_docs(5)
    await register_agents(client, admin_headers, docs)
    session = await consent_session(client, admin_headers, "deep-1")
    decisions, _ = await run_calls(client, session["root_grant"], calls)
    assert [d["outcome"] for d in decisions] == ["allow"] * 5

    body = (await get_chain(client, decisions[-1]["action_id"], admin_headers)).json()

    assert_matches_contract(body, chain_schema)
    assert body["complete"] is True
    chain = body["chain"]
    assert [h["hop"] for h in chain] == [1, 2, 3, 4, 5]
    assert [h["acting_agent"] for h in chain] == [f"deep-{i}" for i in range(1, 6)]
    for previous, current in zip(chain, chain[1:], strict=False):
        assert previous["target"] == f"agent://{current['acting_agent']}"


# -- isolation ------------------------------------------------------------------


async def test_concurrent_sessions_never_share_a_hop(
    client, admin_headers, register_chain, consent
) -> None:
    await register_chain()
    calls = [
        (USER, f"agent://{KB_SEARCH}", "kb.internal"),
        (f"agent://{KB_SEARCH}", f"agent://{SUMMARIZER}", "account.read"),
    ]
    gate = asyncio.Semaphore(10)  # interleaved, without exhausting database connections

    async def one_session() -> tuple[set[str], str]:
        async with gate:
            session = await consent()
            decisions, _ = await run_calls(client, session["root_grant"], calls)
            return {d["action_id"] for d in decisions}, decisions[-1]["action_id"]

    sessions = await asyncio.gather(*(one_session() for _ in range(50)))

    for own_actions, last in sessions:
        body = (await get_chain(client, last, admin_headers)).json()
        assert body["complete"] is True
        assert {h["action_id"] for h in body["chain"]} == own_actions


# -- not found, expiry, legacy, broken links ------------------------------------


async def test_an_unknown_action_is_not_found_with_no_chain(client, admin_headers) -> None:
    r = await get_chain(client, uuid.uuid4(), admin_headers)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"
    assert "chain" not in r.json()


async def test_a_malformed_action_id_is_a_validation_error(client, admin_headers) -> None:
    r = await get_chain(client, "not-a-uuid", admin_headers)
    assert r.status_code == 422


async def test_the_chain_outlives_its_session(
    client, admin_headers, register_chain, consent, db_session
) -> None:
    await register_chain()
    session = await consent()
    decisions, _ = await run_calls(
        client, session["root_grant"], [(USER, f"agent://{KB_SEARCH}", "kb.internal")]
    )
    await db_session.execute(
        text(
            "UPDATE sessions SET expires_at = created_at + interval '1 millisecond' WHERE id = :i"
        ),
        {"i": session["session_id"]},
    )
    await db_session.commit()

    r = await get_chain(client, decisions[-1]["action_id"], admin_headers)

    assert r.status_code == 200
    assert r.json()["complete"] is True


async def test_a_legacy_record_is_answered_honestly(
    client, admin_headers, register_chain, consent, db_session, chain_schema
) -> None:
    await register_chain()
    session = await consent()
    legacy_id = uuid.uuid4()
    await db_session.execute(
        text(
            "INSERT INTO audit_decisions (id, session_id, caller, target, target_kind, data_class, "
            "hop, outcome, recoverable, enforced, policy_version, act_chain, chain_break) VALUES "
            "(:id, :s, 'agent://kb-search', 'agent://summarizer', 'agent', 'account.read', 2, "
            "'allow', false, true, :v, CAST(:chain AS jsonb), 'LEGACY_RECORD')"
        ),
        {
            "id": legacy_id,
            "s": uuid.UUID(session["session_id"]),
            "v": session["policy_version"],
            "chain": f'["{USER}", "agent://{ORCHESTRATOR}"]',
        },
    )
    await db_session.commit()

    body = (await get_chain(client, legacy_id, admin_headers)).json()

    assert_matches_contract(body, chain_schema)
    assert body["complete"] is False
    assert body["break"] == {"at_hop": 1, "reason": "LEGACY_RECORD"}
    first, own = body["chain"]
    assert first["unavailable"] is True
    assert first["acting_agent"] == ORCHESTRATOR
    assert (first["target"], first["data_class"], first["decision"]) == (None, None, None)
    assert own["action_id"] == str(legacy_id)
    assert own["acting_agent"] is None  # never stored, never guessed
    assert (own["target"], own["decision"]) == (f"agent://{SUMMARIZER}", "allow")
    assert "unavailable" not in own


async def test_a_token_naming_a_missing_parent_yields_an_incomplete_chain(
    client, admin_headers, register_chain, consent, chain_schema
) -> None:
    await register_chain()
    session = await consent()
    orphan = get_token_profile().mint_hop_token(
        sub=USER,
        target=f"agent://{KB_SEARCH}",
        data_class="kb.internal",
        session_id=session["session_id"],
        policy_version=session["policy_version"],
        hop=2,
        act={"sub": f"agent://{ORCHESTRATOR}"},
        action_id=str(uuid.uuid4()),
    )
    decision = (
        await authorize(client, orphan, target=f"agent://{SUMMARIZER}", data_class="account.read")
    ).json()
    assert decision["outcome"] == "allow", decision

    body = (await get_chain(client, decision["action_id"], admin_headers)).json()

    assert_matches_contract(body, chain_schema)
    assert body["complete"] is False
    assert body["break"] == {"at_hop": 1, "reason": "PARENT_NOT_FOUND"}
    assert [h["hop"] for h in body["chain"]] == [2]


# -- access ---------------------------------------------------------------------


@pytest.fixture
async def recorded_action(client, admin_headers, register_chain, consent) -> str:
    await register_chain()
    session = await consent()
    decisions, _ = await run_calls(
        client, session["root_grant"], [(USER, f"agent://{KB_SEARCH}", "kb.internal")]
    )
    return decisions[-1]["action_id"]


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}], ids=["none", "wrong"])
async def test_the_chain_requires_an_audit_reader(client, recorded_action, headers) -> None:
    r = await get_chain(client, recorded_action, headers)
    assert r.status_code == 401
    assert "chain" not in r.json()


async def test_the_dedicated_reader_token_can_read_the_chain(
    client, recorded_action, monkeypatch
) -> None:
    monkeypatch.setenv("AGENTIC_AUTH_AUDIT_READ_TOKEN", "test-audit-reader")
    get_settings.cache_clear()
    try:
        r = await get_chain(client, recorded_action, {"Authorization": "Bearer test-audit-reader"})
    finally:
        monkeypatch.delenv("AGENTIC_AUTH_AUDIT_READ_TOKEN")
        get_settings.cache_clear()

    assert r.status_code == 200
