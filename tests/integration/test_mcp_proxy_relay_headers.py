"""Relayed methods never carry the client's credentials (feature 011, research F1/R4).

0.3.0 relayed every non-``tools/call`` method with every inbound header, so the client's
bearer token reached the upstream on ``initialize``, ``tools/list`` and the rest. This
applies with every 0.4.0 flag off: it is a security fix, listed as an exception in spec
FR-019. An upstream that needs a credential on those methods gets an operator secret per
route (``relay_authorization``), never the client's.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport

from agentic_auth.boundary.mcp import build_app
from agentic_auth.gateway.config import GatewayConfig
from agentic_auth.sidecar.config import SidecarConfigError, Upstream
from tests.fixtures.mcp.server import UPSTREAM_TOKEN, build_mcp_server
from tests.fixtures.upstream.recording import assert_no_token_material

CLIENT_TOKEN = "client.bearer-token-value.signature-part"
STRIPPED = ("authorization", "cookie", "proxy-authorization")


def _proxy(upstream: Upstream, *, require_token: bool = False):
    mcp_app, recorder = build_mcp_server(require_token=require_token)
    config = GatewayConfig(
        pdp_url="http://pdp.test", route_table={(None, "/mcp"): upstream}
    ).validate()
    http = httpx.AsyncClient(transport=ASGITransport(app=mcp_app))
    app = build_app(config, client=http)
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://proxy"), recorder


def _rpc(method: str) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": method}


CLIENT_HEADERS = {
    "authorization": f"Bearer {CLIENT_TOKEN}",
    "cookie": "session=client-cookie-value",
    "proxy-authorization": "Basic Y2xpZW50OnNlY3JldA==",
    "x-request-id": "kept-1",
}


@pytest.mark.parametrize("method", ["initialize", "tools/list", "resources/read"])
async def test_relayed_methods_carry_no_client_credentials(method: str) -> None:
    proxy, recorder = _proxy(Upstream(url="http://kb.internal", data_class="kb.internal"))
    async with proxy:
        await proxy.post("/mcp", json=_rpc(method), headers=CLIENT_HEADERS)

    received = recorder.headers[-1]
    for name in STRIPPED:
        assert name not in received, f"{name} was relayed upstream"
    assert received.get("x-request-id") == "kept-1"  # everything else still passes
    assert_no_token_material(CLIENT_TOKEN, recorder)


async def test_a_route_secret_is_sent_instead_of_the_clients() -> None:
    upstream = Upstream(
        url="http://kb.internal",
        data_class="kb.internal",
        relay_authorization=f"Bearer {UPSTREAM_TOKEN}",
    )
    proxy, recorder = _proxy(upstream, require_token=True)
    async with proxy:
        response = await proxy.post("/mcp", json=_rpc("initialize"), headers=CLIENT_HEADERS)

    assert "result" in response.json(), response.json()
    assert recorder.authorizations[-1] == f"Bearer {UPSTREAM_TOKEN}"
    assert UPSTREAM_TOKEN not in response.text  # the operator secret never comes back
    assert_no_token_material(CLIENT_TOKEN, recorder)


async def test_without_a_route_secret_an_upstream_that_needs_one_refuses() -> None:
    """The visible cost of the fix: no silent fallback to the client's token."""
    proxy, recorder = _proxy(
        Upstream(url="http://kb.internal", data_class="kb.internal"), require_token=True
    )
    async with proxy:
        response = await proxy.post("/mcp", json=_rpc("initialize"), headers=CLIENT_HEADERS)

    assert response.json()["error"]["message"].startswith("upstream refused")
    assert recorder.authorizations[-1] == ""


def test_the_route_secret_is_parsed_and_never_printed() -> None:
    upstream = Upstream.parse(
        "/mcp", {"url": "http://kb.internal", "relay_authorization": "Bearer op-secret-123"}
    )
    assert upstream.relay_authorization == "Bearer op-secret-123"
    assert "op-secret-123" not in repr(upstream)


def test_an_empty_route_secret_is_refused() -> None:
    with pytest.raises(SidecarConfigError, match="relay_authorization"):
        Upstream.parse("/mcp", {"url": "http://kb.internal", "relay_authorization": ""})
