"""With all three Phase 4 controls off, Phase 3 behaviour is unchanged. The rest of the
suite proves Phase 1–3 files still pass; this file proves what "off" means for each control."""

from __future__ import annotations

import pytest

from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    TERMINATE_PARAMS,
    USER,
    bank_docs,
)
from tests.fixtures.hops import authorize, claims, exchange, hop, register_agents


@pytest.fixture
async def off(client, admin_headers, consent, flags):
    flags(
        transaction_tokens_enabled=False, taint_enforcement_enabled=False, identity_required=False
    )
    await register_agents(client, admin_headers, bank_docs(widened=True))
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return session, t2


async def test_the_transaction_route_is_hidden_and_decisions_do_not_require_one(
    client, off
) -> None:
    _, support = off
    d, tool = await hop(client, support, target=TERMINATE_ACCOUNT, data_class="account.write")
    assert d["privileged"] is True and d["transaction_required"] is False
    r = await client.post(
        "/v1/token/transaction",
        headers={"Authorization": f"Bearer {tool}"},
        json={"params": TERMINATE_PARAMS},
    )
    assert r.status_code == 404


async def test_taint_is_derived_and_recorded_but_never_enforced(client, off, admin_headers) -> None:
    _, support = off
    await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")
    d = (
        await authorize(client, support, target=TERMINATE_ACCOUNT, data_class="account.write")
    ).json()
    assert d["outcome"] == "allow"
    assert d["taint"] == "untrusted_external" and d["taint_source"] == KB_SEARCH_TOOL
    rows = (
        await client.get("/v1/audit/decisions?taint=untrusted_external", headers=admin_headers)
    ).json()["data"]
    assert any(r["id"] == d["action_id"] for r in rows)


async def test_the_exchange_needs_no_actor_token(client, off) -> None:
    session, support = off
    d = (await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")).json()
    r = await exchange(
        client, support, resource=KB_SEARCH_TOOL, scope="kb.internal", action_id=d["action_id"]
    )
    assert r.status_code == 200
    # the hop token still carries the (trusted) taint claim: recording is not enforcement
    assert claims(r.json()["access_token"]).get("taint") in ("trusted_internal", None)


async def test_the_sidecar_forwards_a_privileged_call_without_buffering_or_a_txn_header(
    sidecar_stack, off
) -> None:
    from agentic_auth.sidecar.config import Upstream

    _, support = off
    sidecar = await sidecar_stack.client(
        upstream_map={
            "/accounts": Upstream(
                url="http://upstream.test", target=TERMINATE_ACCOUNT, data_class="account.write"
            )
        },
        max_privileged_body_bytes=8,  # would block if the body were buffered against the cap
    )
    r = await sidecar.post(
        "/accounts/terminate", headers={"Authorization": f"Bearer {support}"}, json=TERMINATE_PARAMS
    )
    assert r.status_code == 200, r.text
    assert "txn-token" not in sidecar_stack.recorder.last["headers"]
    assert "agent-identity" not in sidecar_stack.recorder.last["headers"]


async def test_the_sdk_needs_no_params_for_a_privileged_call(client, off) -> None:
    from agentic_auth.sdk import AgenticAuthClient, HopContext
    from tests.conftest import ADMIN_TOKEN

    session, support = off
    sdk = AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)
    grant = await sdk.authorize(
        HopContext(session_id=session["session_id"], token=support),
        target=TERMINATE_ACCOUNT,
        data_class="account.write",
    )
    assert grant.transaction_token is None and "Txn-Token" not in grant.headers()
