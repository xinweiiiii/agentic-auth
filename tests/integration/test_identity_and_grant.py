"""Identity AND grant at a real resource, offline after bootstrap (US3, T061; SC-007, SC-008,
SC-012, SC-013).

The SDK client (holding support-agent's key) walks the bank chain against the in-process
control plane, then calls the protected resource fixture, whose verifier bootstrapped from
that control plane and is then cut off from it.
"""

from __future__ import annotations

import pytest

from app.sdk import AgenticAuthClient, AgentKey
from tests.conftest import ADMIN_TOKEN
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    READ_BALANCE,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    TERMINATE_PARAMS,
    USER,
    bank_docs,
)
from tests.fixtures.hops import register_agents


@pytest.fixture
async def stack(client, admin_headers, flags, fake_idp, principal_assertion_for, resource_stack):
    """Every bank agent enrolled with its own key; identity on; the resource bootstrapped."""
    flags(taint_enforcement_enabled=False)  # this file is about identity, not taint
    await register_agents(client, admin_headers, bank_docs(widened=True))
    listing = (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    ids = {a["name"]: a["id"] for a in listing}
    keys: dict[str, AgentKey] = {}
    sdk = AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)
    for name in (BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT):
        key = AgentKey.generate(kid=f"{name}-k1")
        outcome = await sdk.enroll(
            ids[name], key=key, agent_name=name, principal_assertion=principal_assertion_for(name)
        )
        assert outcome["status"] == "enrolled", outcome
        keys[name] = key
    flags(identity_required=True)
    resource, recorder, verifier = await resource_stack.build(
        agents=[BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT]
    )
    resource_stack.transport.cut = True  # offline from here on (SC-008)

    from types import SimpleNamespace

    return SimpleNamespace(
        keys=keys, ids=ids, resource=resource, recorder=recorder, verifier=verifier
    )


def _sdk(client, key: AgentKey | None, name: str | None) -> AgenticAuthClient:
    return AgenticAuthClient(
        base_url="http://test",
        admin_token=ADMIN_TOKEN,
        client=client,
        identity_key=key,
        agent_name=name,
    )


async def _to_balance(client, stack):
    """One hop: bank-assistant (root) delegates to balance-agent, which declares read_balance."""
    root = _sdk(client, stack.keys[BANK_ASSISTANT], BANK_ASSISTANT)
    session = await root.consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, ctx = await root.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    return _sdk(client, stack.keys[BALANCE_AGENT], BALANCE_AGENT), ctx


async def _to_support(client, stack):
    """Two hops: to support-agent, which declares the privileged terminate_account."""
    balance, ctx = await _to_balance(client, stack)
    _, ctx = await balance.hop(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return _sdk(client, stack.keys[SUPPORT_AGENT], SUPPORT_AGENT), ctx


async def test_identity_plus_matching_grant_is_admitted_offline(
    client, stack, resource_stack
) -> None:
    balance, ctx = await _to_balance(client, stack)
    grant = await balance.authorize(ctx, target=READ_BALANCE, data_class="account.read")
    seen = resource_stack.transport.requests
    r = await stack.resource.get("/tools/read_balance", headers=grant.headers())
    assert r.status_code == 200, r.text
    assert r.json()["agent"] == BALANCE_AGENT
    assert stack.recorder.executed == [READ_BALANCE]
    assert resource_stack.transport.requests == seen  # nothing left the resource (SC-008)


async def test_the_matrix(client, stack) -> None:
    balance, ctx = await _to_balance(client, stack)
    grant = await balance.authorize(ctx, target=READ_BALANCE, data_class="account.read")
    headers = grant.headers()
    key = stack.keys[BALANCE_AGENT]

    identity_only = {"Agent-Identity": headers["Agent-Identity"]}
    grant_only = {"Authorization": headers["Authorization"]}
    wrong_key = {
        "Authorization": headers["Authorization"],
        "Agent-Identity": AgentKey.generate().identity_assertion(
            BALANCE_AGENT, grant.access_token, READ_BALANCE
        ),
    }
    other_grant_identity = {
        "Authorization": headers["Authorization"],
        "Agent-Identity": key.identity_assertion(BALANCE_AGENT, "x.y.z", READ_BALANCE),
    }
    other_agent_identity = {
        "Authorization": headers["Authorization"],
        "Agent-Identity": stack.keys[SUPPORT_AGENT].identity_assertion(
            SUPPORT_AGENT, grant.access_token, READ_BALANCE
        ),
    }

    expectations = [
        (identity_only, "GRANT_MISSING"),
        (grant_only, "IDENTITY_MISSING"),
        (wrong_key, "IDENTITY_INVALID"),
        (other_grant_identity, "IDENTITY_INVALID"),
        (other_agent_identity, "IDENTITY_INVALID"),
    ]
    for presented, reason in expectations:
        r = await stack.resource.get("/tools/read_balance", headers=presented)
        assert r.status_code == 403, (reason, r.text)
        assert r.json()["error"]["details"]["reason"] == reason, reason
    assert stack.recorder.executed == []

    ok = await stack.resource.get("/tools/read_balance", headers=headers)
    assert ok.status_code == 200
    assert stack.recorder.executed == [READ_BALANCE]


async def test_a_grant_for_another_target_is_refused_with_identity(client, stack) -> None:
    balance, ctx = await _to_balance(client, stack)
    grant = await balance.authorize(ctx, target=READ_BALANCE, data_class="account.read")
    headers = grant.headers()
    headers["Agent-Identity"] = stack.keys[BALANCE_AGENT].identity_assertion(
        BALANCE_AGENT, grant.access_token, TERMINATE_ACCOUNT
    )
    r = await stack.resource.post(
        "/tools/terminate_account", headers=headers, json=TERMINATE_PARAMS
    )
    assert r.status_code == 403
    assert r.json()["error"]["details"]["reason"] == "GRANT_TARGET_MISMATCH"


async def test_a_privileged_call_needs_all_three(client, stack) -> None:
    support, ctx = await _to_support(client, stack)
    grant = await support.authorize(
        ctx, target=TERMINATE_ACCOUNT, data_class="account.write", params=TERMINATE_PARAMS
    )
    headers = grant.headers()
    assert {"Authorization", "Agent-Identity", "Txn-Token"} <= set(headers)

    without_txn = {k: v for k, v in headers.items() if k != "Txn-Token"}
    r = await stack.resource.post(
        "/tools/terminate_account", headers=without_txn, json=TERMINATE_PARAMS
    )
    assert r.json()["error"]["details"]["reason"] == "TXN_MISSING"

    mutated = await stack.resource.post(
        "/tools/terminate_account",
        headers=headers,
        json={**TERMINATE_PARAMS, "account_id": "acc-99"},
    )
    assert mutated.json()["error"]["details"]["reason"] == "TXN_PARAMS_MISMATCH"

    ok = await stack.resource.post(
        "/tools/terminate_account", headers=headers, json=TERMINATE_PARAMS
    )
    assert ok.status_code == 200, ok.text
    replay = await stack.resource.post(
        "/tools/terminate_account", headers=headers, json=TERMINATE_PARAMS
    )
    assert replay.json()["error"]["details"]["reason"] == "TXN_REPLAY"
    assert stack.recorder.executed == [TERMINATE_ACCOUNT]


async def test_a_quarantined_agent_has_no_identity_at_the_resource(
    client, stack, resource_stack, flags
) -> None:
    """support-agent re-enrolls without a principal -> quarantined. The resource's next
    refresh learns it, and an identity assertion signed with its (once-pinned) key is
    IDENTITY_UNKNOWN_AGENT — before the transaction token is even looked at."""
    # A grant + txn for support-agent, minted while identity is off (a quarantined agent
    # cannot pass the exchange's possession check once it is on).
    flags(identity_required=False)
    support, ctx = await _to_support(client, stack)
    grant = await support.authorize(
        ctx, target=TERMINATE_ACCOUNT, data_class="account.write", params=TERMINATE_PARAMS
    )
    flags(identity_required=True)

    key = stack.keys[SUPPORT_AGENT]
    sdk = AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)
    outcome = await sdk.enroll(stack.ids[SUPPORT_AGENT], key=key, agent_name=SUPPORT_AGENT)
    assert outcome["status"] == "quarantined"

    resource_stack.transport.cut = False
    assert await stack.verifier.anchors.refresh() is True
    resource_stack.transport.cut = True

    r = await stack.resource.post(
        "/tools/terminate_account", headers=grant.headers(), json=TERMINATE_PARAMS
    )
    assert r.status_code == 403
    assert r.json()["error"]["details"]["reason"] == "IDENTITY_UNKNOWN_AGENT"
    assert stack.recorder.executed == []


async def test_no_secret_is_recorded_anywhere(client, stack, db_session) -> None:
    from sqlalchemy import text

    support, ctx = await _to_support(client, stack)
    grant = await support.authorize(
        ctx, target=TERMINATE_ACCOUNT, data_class="account.write", params=TERMINATE_PARAMS
    )
    secrets = [
        grant.transaction_token,
        grant.identity_assertion,
        stack.keys[SUPPORT_AGENT]._private_pem().decode(),
    ]
    for table in ("audit_decisions", "transaction_tokens", "trust_anchors", "agents", "sessions"):
        dump = str(
            (await db_session.execute(text(f"SELECT to_jsonb(t) FROM {table} t"))).scalars().all()
        )
        for secret in secrets:
            assert secret and secret not in dump, table
    assert "PRIVATE" not in repr(stack.keys[SUPPORT_AGENT])
