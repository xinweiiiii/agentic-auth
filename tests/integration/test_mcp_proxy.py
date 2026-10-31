"""Repointing a connector governs an agent whose code stays untouched
(US4; FR-010..FR-012; SC-006).

The premise to keep honest: **nothing in this file changes the agent.** The only thing
the integrator owns here is the URL its tool configuration points at. Every test drives
raw JSON-RPC, which is what an uncooperative third-party agent would send.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport

from agentic_auth.boundary.mcp import INFRASTRUCTURE, POLICY_REFUSED, build_app
from agentic_auth.gateway.config import GatewayConfig
from agentic_auth.sidecar.config import Upstream
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    SUPPORT_AGENT,
    USER,
    bank_docs,
)
from tests.fixtures.hops import hop, register_agents
from tests.fixtures.mcp.server import UPSTREAM_TOKEN, build_mcp_server

KB_HOST = "kb.internal"
DECLARED = frozenset({f"mcp://{KB_HOST}/search"})


@pytest.fixture
async def proxy_stack(client, flags):
    """The connector proxy in front of a fake MCP server, both in-process."""
    flags(taint_enforcement_enabled=False)
    mcp_app, recorder = build_mcp_server(require_token=False)

    class _Router(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.pdp = ASGITransport(app=client._transport.app)
            self.upstream = ASGITransport(app=mcp_app)
            self.upstream_down = False

        async def handle_async_request(self, request):
            if request.url.host == "pdp.test":
                return await self.pdp.handle_async_request(request)
            if self.upstream_down:
                raise httpx.ConnectError("upstream is down")
            return await self.upstream.handle_async_request(request)

    router = _Router()
    table = {
        (None, "/mcp"): Upstream(url=f"http://{KB_HOST}", data_class="kb.internal"),
    }
    config = GatewayConfig(pdp_url="http://pdp.test", route_table=table).validate()
    app = build_app(config, client=httpx.AsyncClient(transport=router), declared_tools=DECLARED)
    proxy = httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://proxy")

    from types import SimpleNamespace

    yield SimpleNamespace(proxy=proxy, upstream=recorder, router=router)
    await proxy.aclose()


@pytest.fixture
async def support_token(client, admin_headers, consent):
    await register_agents(client, admin_headers, bank_docs(widened=True, trust_kb=True))
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return t2


def _rpc(method: str, **params):
    body = {"jsonrpc": "2.0", "id": 7, "method": method}
    if params:
        body["params"] = params
    return body


# -- the agent is untouched (SC-006) -------------------------------------------------


async def test_an_in_scope_call_returns_the_real_result(proxy_stack, support_token) -> None:
    """Zero lines of agent code changed: the same JSON-RPC it always sent, to a
    different URL."""
    response = await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("tools/call", name="search", arguments={"q": "refund"}),
    )

    assert response.status_code == 200
    assert response.json()["result"]["content"][0]["text"] == "real result"
    assert proxy_stack.upstream.last_tool == "search"


async def test_the_upstream_receives_the_narrowed_token_not_the_presented_one(
    proxy_stack, support_token
) -> None:
    """The narrowing is the point. If the presented token reached the upstream, the
    proxy would be a router, not an enforcement point."""
    await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("tools/call", name="search", arguments={"q": "x"}),
    )

    received = proxy_stack.upstream.authorizations[-1]
    assert received != f"Bearer {support_token}"
    assert received.startswith("Bearer ")


async def test_an_out_of_scope_call_is_refused_as_a_json_rpc_error(
    proxy_stack, support_token
) -> None:
    """A shape the agent already handles — not an HTTP status it has no branch for."""
    response = await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("tools/call", name="terminate_account", arguments={"account_id": "a"}),
    )

    assert response.status_code == 200, "a JSON-RPC error is a successful HTTP response"
    error = response.json()["error"]
    assert error["code"] == POLICY_REFUSED
    assert error["data"]["reason"] in {"OUT_OF_SCOPE", "EDGE_NOT_IN_DAG"}
    assert error["data"]["recoverable"] is False
    assert error["data"]["guarantee_level"] == "connector"
    assert proxy_stack.upstream.calls == [], "the tool must not run"


async def test_the_refusal_names_the_guarantee_level(proxy_stack, support_token) -> None:
    response = await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("tools/call", name="terminate_account", arguments={}),
    )

    assert response.json()["error"]["data"]["guarantee_level"] == "connector"


# -- tools/list is filtered (FR-012) ---------------------------------------------------


async def test_tools_list_offers_only_what_the_policy_declares(proxy_stack, support_token) -> None:
    """The upstream advertises three tools; the pinned policy declares one."""
    response = await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("tools/list"),
    )

    names = [t["name"] for t in response.json()["result"]["tools"]]
    assert names == ["search"]


# -- everything else is relayed unchanged ------------------------------------------------


async def test_initialize_is_relayed(proxy_stack, support_token) -> None:
    response = await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("initialize"),
    )

    assert response.json()["result"]["serverInfo"]["name"] == "fake"


async def test_an_unknown_method_is_relayed_and_its_error_passed_through(
    proxy_stack, support_token
) -> None:
    """The upstream's own refusal must not be reported as a policy refusal — they send
    an operator to completely different places."""
    response = await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("resources/read"),
    )

    assert response.json()["error"]["code"] == -32601


# -- fail closed -----------------------------------------------------------------------


async def test_a_malformed_envelope_is_refused_not_relayed(proxy_stack, support_token) -> None:
    """Forwarding something we could not parse would mean forwarding a call we never
    decided on."""
    response = await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}", "content-type": "application/json"},
        content=b"{not json",
    )

    assert response.json()["error"]["code"] == -32600
    assert proxy_stack.upstream.calls == []


async def test_a_tools_call_without_a_name_is_refused(proxy_stack, support_token) -> None:
    response = await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("tools/call", arguments={}),
    )

    assert response.json()["error"]["code"] == -32600
    assert proxy_stack.upstream.calls == []


async def test_an_unreachable_upstream_is_an_infrastructure_error(
    proxy_stack, support_token
) -> None:
    proxy_stack.router.upstream_down = True

    response = await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("tools/call", name="search", arguments={"q": "x"}),
    )

    error = response.json()["error"]
    assert error["code"] == INFRASTRUCTURE
    assert error["data"]["reason"] == "UPSTREAM_UNREACHABLE"


async def test_an_unmapped_path_is_refused(proxy_stack, support_token) -> None:
    response = await proxy_stack.proxy.post(
        "/nowhere",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("tools/call", name="search", arguments={}),
    )

    assert response.json()["error"]["code"] == POLICY_REFUSED
    assert proxy_stack.upstream.calls == []


# -- the upstream's own handshake is passed through (research.md R8) ---------------------


async def test_the_upstream_credential_is_never_returned_to_the_agent(
    proxy_stack, support_token
) -> None:
    """FR-011. Whatever the proxy attaches on the way out, the agent does not see."""
    response = await proxy_stack.proxy.post(
        "/mcp",
        headers={"Authorization": f"Bearer {support_token}"},
        json=_rpc("tools/call", name="search", arguments={"q": "x"}),
    )

    assert UPSTREAM_TOKEN not in response.text
    assert "txn-token" not in {k.lower() for k in response.headers}
