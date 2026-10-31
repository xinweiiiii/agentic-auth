"""Observe mode at the gateway matches the sidecar exactly (FR-006).

Observe mode predicts what *policy* would block. It must never forward an infrastructure
failure — that would pass an outage off as a prediction, and an operator tuning a rollout
would read "would have been blocked" for something that was never decided at all.

Centrally the distinction matters more: one gateway in observe mode is every agent
unenforced, so "which refusals does it still honour" has to be exactly the sidecar's
answer, not approximately.
"""

from __future__ import annotations

import pytest

from agentic_auth.sidecar.config import Upstream
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    SUPPORT_AGENT,
    USER,
    bank_docs,
)
from tests.fixtures.hops import hop, register_agents

UNDECLARED = "mcp://kb.internal/absent"

TABLE = {
    (None, "/kb"): Upstream(
        url="http://upstream.test", target=KB_SEARCH_TOOL, data_class="kb.internal"
    ),
    (None, "/nowhere"): Upstream(
        url="http://upstream.test", target=UNDECLARED, data_class="kb.internal"
    ),
}
SIDECAR_MAP = {prefix: upstream for (_, prefix), upstream in TABLE.items()}


@pytest.fixture
async def support_token(client, admin_headers, consent):
    async def _setup():
        await register_agents(client, admin_headers, bank_docs(widened=True, trust_kb=True))
        session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
        _, t1 = await hop(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
        _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
        return session, t2

    return _setup


async def test_a_policy_refusal_is_forwarded_and_recorded_unenforced(
    gateway_stack, support_token, client, admin_headers
) -> None:
    session, token = await support_token()
    gateway = await gateway_stack.client(route_table=TABLE, observe_mode=True)

    response = await gateway.get("/nowhere/x", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200, "observe mode forwards a policy refusal"

    page = await client.get(
        f"/v1/audit/decisions?session_id={session['session_id']}", headers=admin_headers
    )
    rows = [r for r in page.json()["data"] if r["target"] == UNDECLARED]
    assert rows, "the refusal must still be recorded"
    assert rows[0]["outcome"] == "deny"
    assert rows[0]["enforced"] is False, "'would have been blocked' is the whole report"


async def test_an_infrastructure_failure_is_never_forwarded_in_observe_mode(
    gateway_stack, support_token
) -> None:
    """The rule observe mode exists to respect: it predicts policy, not outages."""
    _, token = await support_token()
    gateway = await gateway_stack.client(route_table=TABLE, observe_mode=True)
    gateway_stack.router.pdp_down = True
    before = gateway_stack.recorder.count

    response = await gateway.get("/kb/search", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 503
    assert response.json()["error"]["details"]["reason"] == "PDP_UNAVAILABLE"
    assert gateway_stack.recorder.count == before


async def test_the_gateway_and_the_sidecar_observe_identically(
    gateway_stack, sidecar_stack, support_token
) -> None:
    _, token_a = await support_token()
    sidecar = await sidecar_stack.client(upstream_map=SIDECAR_MAP, observe_mode=True)
    via_sidecar = await sidecar.get("/nowhere/x", headers={"Authorization": f"Bearer {token_a}"})

    _, token_b = await support_token()
    gateway = await gateway_stack.client(route_table=TABLE, observe_mode=True)
    via_gateway = await gateway.get("/nowhere/x", headers={"Authorization": f"Bearer {token_b}"})

    assert via_sidecar.status_code == via_gateway.status_code == 200


async def test_an_allowed_call_is_still_recorded_as_enforced_in_observe_mode(
    gateway_stack, support_token, client, admin_headers
) -> None:
    """An allow is forwarded either way, so it WAS acted on. Recording it as unenforced
    would make `enforced=false` mean two different things."""
    session, token = await support_token()
    gateway = await gateway_stack.client(route_table=TABLE, observe_mode=True)

    await gateway.get("/kb/search", headers={"Authorization": f"Bearer {token}"})

    page = await client.get(
        f"/v1/audit/decisions?session_id={session['session_id']}", headers=admin_headers
    )
    allows = [r for r in page.json()["data"] if r["outcome"] == "allow"]
    assert allows and all(r["enforced"] is True for r in allows)
