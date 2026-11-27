"""MCPA-RS-NOPASS: the client's token never reaches an upstream (INV-1, FR-004, FR-017).

Every path a request can take through either enforcement point, in both deployments. The
recorders fail the test if the whole token, any of its segments, or its ``jti`` appears in
any header or body any upstream received.
"""

from __future__ import annotations

import pytest

from tests.conformance.mcp_auth.conftest import TOOLS_CALL, bearer
from tests.fixtures.upstream.recording import assert_no_token_material

pytestmark = pytest.mark.conformance


async def test_MCPA_RS_NOPASS(stack) -> None:
    proxy = stack.proxy()
    gateway = stack.gateway()
    proxy_token = stack.token()
    gateway_token = stack.token(aud=stack.gateway_url)
    rpc = {"jsonrpc": "2.0", "id": 1}

    # relayed methods
    for method in ("initialize", "tools/list", "resources/read"):
        await proxy.post("/mcp", json={**rpc, "method": method}, headers=bearer(proxy_token))
    # allow: cache miss, then cache hit
    first = await proxy.post("/mcp", json=TOOLS_CALL, headers=bearer(proxy_token))
    await proxy.post("/mcp", json=TOOLS_CALL, headers=bearer(proxy_token))
    await gateway.get("/kb/search", headers=bearer(gateway_token))
    await gateway.get("/kb/search", headers=bearer(gateway_token))
    # deny
    deny = {**TOOLS_CALL, "params": {"name": "terminate_account"}}
    await proxy.post("/mcp", json=deny, headers=bearer(proxy_token))
    # control plane error on a cache miss
    stack.pdp_down(True)
    await proxy.post("/mcp", json=TOOLS_CALL, headers=bearer(stack.token(sub="bob")))
    await gateway.get("/kb/search", headers=bearer(stack.token(sub="bob", aud=stack.gateway_url)))
    stack.pdp_down(False)

    assert "result" in first.json(), first.text
    assert len(stack.mcp.calls) == 2 and stack.upstream.count == 2
    for token in (proxy_token, gateway_token):
        assert_no_token_material(token, stack.mcp, stack.upstream)
