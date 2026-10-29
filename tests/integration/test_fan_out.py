"""One delegation token, several recorded calls.

Phase 2 spent the subject token's ``jti`` on every exchange, so an agent could make exactly
one call per hop and the PRD injection scenario (read a KB article, THEN call
terminate_account, both by support-agent) was unexpressible. The guard is now per recorded
allow decision: one decision, one token — still — but a token buys as many decisions as the
PDP records for it.
"""

from __future__ import annotations

import pytest

from tests.fixtures.bank import (
    BALANCE_AGENT,
    KB_SEARCH_TOOL,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    USER,
    bank_docs,
)
from tests.fixtures.hops import authorize, claims, exchange, hop, register_agents


@pytest.fixture
async def support_token(client, admin_headers, consent, flags):
    """A hop token held by support-agent, two delegations deep."""
    flags(taint_enforcement_enabled=False)  # this file is about fan-out, not taint
    await register_agents(client, admin_headers, bank_docs(widened=True))
    session = await consent(scope="bank-assistant", user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    assert t2 is not None
    return t2


async def test_one_token_buys_a_call_per_recorded_decision(client, support_token) -> None:
    first_decision, kb_token = await hop(
        client, support_token, target=KB_SEARCH_TOOL, data_class="kb.internal"
    )
    second_decision, terminate_token = await hop(
        client, support_token, target=TERMINATE_ACCOUNT, data_class="account.write"
    )

    assert first_decision["outcome"] == second_decision["outcome"] == "allow"
    assert first_decision["action_id"] != second_decision["action_id"]
    assert kb_token and terminate_token and kb_token != terminate_token
    assert claims(kb_token)["aud"] == KB_SEARCH_TOOL
    assert claims(terminate_token)["aud"] == TERMINATE_ACCOUNT
    # each narrowed token names its own decision
    assert claims(kb_token)["action_id"] == first_decision["action_id"]
    assert claims(terminate_token)["action_id"] == second_decision["action_id"]


async def test_the_same_decision_still_mints_exactly_once(client, support_token) -> None:
    decision = (
        await authorize(client, support_token, target=KB_SEARCH_TOOL, data_class="kb.internal")
    ).json()
    first = await exchange(
        client,
        support_token,
        resource=KB_SEARCH_TOOL,
        scope="kb.internal",
        action_id=decision["action_id"],
    )
    second = await exchange(
        client,
        support_token,
        resource=KB_SEARCH_TOOL,
        scope="kb.internal",
        action_id=decision["action_id"],
    )
    assert first.status_code == 200
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"
    assert "already been exchanged" in second.json()["error_description"]
