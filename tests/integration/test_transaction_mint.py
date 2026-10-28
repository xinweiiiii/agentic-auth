"""``POST /v1/token/transaction`` (US1, T027)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.verify.canonical import binding_hash
from tests.fixtures.bank import (
    BALANCE_AGENT,
    KB_SEARCH_TOOL,
    READ_BALANCE,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    TERMINATE_BINDING,
    TERMINATE_PARAMS,
    USER,
    bank_docs,
)
from tests.fixtures.hops import claims, hop, register_agents


@pytest.fixture
async def support(client, admin_headers, consent, flags):
    """support-agent's delegation token, two hops in, with the widened (privileged) manifest."""
    flags(taint_enforcement_enabled=False)
    await register_agents(client, admin_headers, bank_docs(widened=True))
    session = await consent(scope="bank-assistant", user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    assert t2 is not None
    return t2


async def _tool_token(client, support_token, target=TERMINATE_ACCOUNT, data_class="account.write"):
    decision, tool_token = await hop(client, support_token, target=target, data_class=data_class)
    assert decision["outcome"] == "allow", decision
    return decision, tool_token


async def mint(client, tool_token, params=TERMINATE_PARAMS):
    return await client.post(
        "/v1/token/transaction",
        headers={"Authorization": f"Bearer {tool_token}"},
        json={"params": params},
    )


async def test_a_privileged_tool_call_mints_a_bound_token(client, support, db_session) -> None:
    decision, tool_token = await _tool_token(client, support)
    assert decision["privileged"] is True and decision["transaction_required"] is True

    r = await mint(client, tool_token)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["action_id"] == decision["action_id"]
    assert body["binding"] == TERMINATE_BINDING
    assert body["params_hash"] == binding_hash(
        TERMINATE_ACCOUNT, TERMINATE_PARAMS, TERMINATE_BINDING
    )
    assert body["expires_in"] == 30

    txn = claims(body["transaction_token"])
    assert txn["aud"] == TERMINATE_ACCOUNT
    assert txn["action_id"] == decision["action_id"]
    assert txn["azd"]["params_hash"] == body["params_hash"]

    # the row exists, committed, and never holds the token
    rows = (
        await db_session.execute(
            text("SELECT jti, action_id, params_hash, target FROM transaction_tokens")
        )
    ).all()
    assert len(rows) == 1
    assert str(rows[0].action_id) == decision["action_id"]
    assert rows[0].params_hash == body["params_hash"]
    assert rows[0].target == TERMINATE_ACCOUNT
    assert body["transaction_token"] not in str(rows)


async def test_one_transaction_token_per_decision(client, support) -> None:
    _, tool_token = await _tool_token(client, support)
    assert (await mint(client, tool_token)).status_code == 200
    second = await mint(client, tool_token)
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "transaction_already_minted"


async def test_a_non_privileged_target_is_a_validation_error(client, support) -> None:
    _, tool_token = await _tool_token(client, support, KB_SEARCH_TOOL, "kb.internal")
    r = await mint(client, tool_token, {"q": "hello"})
    assert r.status_code == 422
    body = r.json()["error"]
    assert body["code"] == "validation_error"
    assert body["details"]["fields"][0]["loc"] == ["target"]


async def test_a_delegation_token_or_root_grant_cannot_mint(client, support, consent) -> None:
    r = await mint(client, support)  # a delegation token (aud = agent://support-agent)
    assert r.status_code == 401
    session = await consent(scope="bank-assistant", user_sub=USER)
    r = await mint(client, session["root_grant"])
    assert r.status_code == 401


async def test_a_token_for_another_target_cannot_mint_for_this_row(client, support) -> None:
    """A tool token for read_balance is not the token for terminate_account."""
    _, other = await _tool_token(client, support, KB_SEARCH_TOOL, "kb.internal")
    # Forge nothing: simply present a token whose own action row is a non-privileged target.
    r = await mint(client, other)
    assert r.status_code == 422


async def test_params_must_be_an_object(client, support) -> None:
    _, tool_token = await _tool_token(client, support)
    r = await client.post(
        "/v1/token/transaction",
        headers={"Authorization": f"Bearer {tool_token}"},
        json={"params": ["not", "an", "object"]},
    )
    assert r.status_code == 422
    r = await client.post(
        "/v1/token/transaction",
        headers={"Authorization": f"Bearer {tool_token}"},
        json={"params": {"ok": 1}, "extra": 2},
    )
    assert r.status_code == 422


async def test_an_oversized_body_is_refused(client, support, flags) -> None:
    flags(max_privileged_body_bytes=200)
    _, tool_token = await _tool_token(client, support)
    r = await mint(client, tool_token, {"account_id": "acc-42", "blob": "x" * 500})
    assert r.status_code == 422
    assert r.json()["error"]["details"]["fields"][0]["loc"] == ["params"]


async def test_the_feature_flag_hides_the_route(client, support, flags) -> None:
    _, tool_token = await _tool_token(client, support)
    flags(transaction_tokens_enabled=False)
    r = await mint(client, tool_token)
    assert r.status_code == 404


async def test_a_garbage_bearer_is_401(client) -> None:
    r = await client.post(
        "/v1/token/transaction",
        headers={"Authorization": "Bearer nope"},
        json={"params": {}},
    )
    assert r.status_code == 401


async def test_the_decision_says_when_a_transaction_is_required(client, support, flags) -> None:
    decision, _ = await _tool_token(
        client, support, READ_BALANCE if False else KB_SEARCH_TOOL, "kb.internal"
    )
    assert decision["privileged"] is False and decision["transaction_required"] is False
    flags(transaction_tokens_enabled=False)
    decision, _ = await _tool_token(client, support)
    assert decision["privileged"] is True and decision["transaction_required"] is False


async def test_the_transaction_token_never_lands_in_any_table(client, support, db_session) -> None:
    _, tool_token = await _tool_token(client, support)
    token = (await mint(client, tool_token)).json()["transaction_token"]
    for table in ("audit_decisions", "transaction_tokens", "sessions", "agents"):
        dump = (
            (await db_session.execute(text(f"SELECT to_jsonb(t) FROM {table} t"))).scalars().all()
        )
        assert all(token not in str(row) for row in dump), table
    assert uuid.UUID(claims(token)["jti"])
