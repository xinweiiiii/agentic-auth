"""The gateway fails closed (FR-003, SC-002).

Four ways to be unable to decide. All four must refuse, and none may forward. Centrally
this matters more than it does in a sidecar: one gateway that forwards while it cannot
enforce is every agent unprotected at once.

The upstream fixture records what actually reached it, so "did not forward" is asserted
against the upstream's own count rather than inferred from a status code.
"""

from __future__ import annotations

import pytest

from agentic_auth.gateway.config import GatewayConfig, GatewayConfigError
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

TABLE = {
    (None, "/kb"): Upstream(
        url="http://upstream.test", target=KB_SEARCH_TOOL, data_class="kb.internal"
    ),
}


@pytest.fixture
async def token(client, admin_headers, consent):
    await register_agents(client, admin_headers, bank_docs(widened=True))
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return t2


async def test_an_unreachable_control_plane_refuses_and_does_not_forward(
    gateway_stack, token
) -> None:
    gateway = await gateway_stack.client(route_table=TABLE)
    gateway_stack.router.pdp_down = True
    before = gateway_stack.recorder.count

    response = await gateway.get("/kb/search", headers={"Authorization": f"Bearer {token}"})

    # 503, not 403: PDP_UNAVAILABLE is an INFRASTRUCTURE reason, and the sidecar answers
    # it the same way. An outage and a policy refusal send an operator to different
    # places, so they must not share a status.
    assert response.status_code == 503
    assert response.json()["error"]["details"]["reason"] == "PDP_UNAVAILABLE"
    assert gateway_stack.recorder.count == before, "nothing may reach the upstream"


async def test_a_decision_past_the_deadline_refuses(gateway_stack, token) -> None:
    """A slow decision is no decision. The gateway refuses rather than retrying, because
    retrying would turn a control-plane stall into an unbounded wait for every agent."""
    gateway = await gateway_stack.client(route_table=TABLE, decision_deadline_ms=50)
    gateway_stack.router.pdp_delay = 0.3
    before = gateway_stack.recorder.count

    response = await gateway.get("/kb/search", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 503, response.text
    assert response.json()["error"]["details"]["reason"] == "PDP_UNAVAILABLE"
    assert gateway_stack.recorder.count == before


async def test_a_transaction_mint_outage_refuses_a_privileged_call(
    gateway_stack, client, admin_headers, consent
) -> None:
    """A privileged call whose binding cannot be minted must not be forwarded unbound."""
    from tests.fixtures.bank import TERMINATE_ACCOUNT

    await register_agents(client, admin_headers, bank_docs(widened=True, trust_kb=True))
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, support = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")

    table = {
        (None, "/accounts"): Upstream(
            url="http://upstream.test", target=TERMINATE_ACCOUNT, data_class="account.write"
        )
    }
    gateway = await gateway_stack.client(route_table=table)
    gateway_stack.router.transaction_down = True
    before = gateway_stack.recorder.count

    response = await gateway.post(
        "/accounts/terminate",
        headers={"Authorization": f"Bearer {support}"},
        json={"account_id": "acc-42"},
    )

    assert response.status_code >= 400
    assert gateway_stack.recorder.count == before


async def test_an_empty_route_table_refuses_at_startup() -> None:
    """Not a runtime refusal — the process must not come up at all. A gateway that is up
    with nothing mapped looks healthy while blocking everything, for every agent."""
    with pytest.raises(GatewayConfigError, match="route_table is required"):
        GatewayConfig(pdp_url="http://pdp.test", route_table={}).validate()


async def test_health_reports_degraded_when_it_cannot_enforce(gateway_stack) -> None:
    gateway = await gateway_stack.client(route_table=TABLE)

    healthy = await gateway.get("/v1/gateway/healthz")
    assert healthy.status_code == 200
    assert healthy.json()["control_plane"] == "reachable"

    gateway_stack.router.pdp_down = True
    degraded = await gateway.get("/v1/gateway/healthz")

    assert degraded.status_code == 503, "an unenforceable gateway must never report 200"
    assert degraded.json()["status"] == "degraded"
    assert degraded.json()["control_plane"] == "unreachable"


async def test_the_route_table_is_visible_to_operators(gateway_stack) -> None:
    gateway = await gateway_stack.client(route_table=TABLE)

    routes = (await gateway.get("/v1/gateway/routes")).json()["routes"]

    assert routes == [
        {
            "prefix": "/kb",
            "agent": None,
            "url": "http://upstream.test",
            "target": KB_SEARCH_TOOL,
            "data_class": "kb.internal",
        }
    ]
