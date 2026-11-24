"""An MCP client authenticating to the connector proxy, end to end, with no infrastructure.

    python examples/mcp-oauth/run_local.py

Everything runs in this process (feature 011, quickstart V2-V3):

- an embedded control plane with verified consent (M2) and client mapping (M4) on;
- its built-in test IdP, standing in for your organisation's IdP;
- the connector proxy as an OAuth protected resource (M1), in front of
- a tiny MCP tool server.

The client side is ``client_flow.py``, which contains no Agentic Auth code at all. What it
gets back is the tool's result; what the audit chain then shows is the human the IdP signed
in, and the client they used.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from agentic_auth.boundary.mcp import build_app as build_proxy
from agentic_auth.embedded import BASE_URL, EmbeddedControlPlane
from agentic_auth.embedded import idp as test_idp
from agentic_auth.gateway.config import GatewayConfig
from agentic_auth.sidecar.config import Upstream

sys.path.insert(0, str(Path(__file__).parent))
from client_flow import call_tool  # noqa: E402

PROXY = "https://mcp-proxy.example"
AGENT = "kb-assistant"
CLIENT_ID = "desktop-client"
CONSENT_TOKEN = "proxy-consent-token"

MANIFEST = {
    "apiVersion": "agentic-auth/v1",
    "kind": "AgentManifest",
    "metadata": {"agent": AGENT},
    "spec": {
        "tools": [
            {"ref": "mcp://kb.internal/search", "data_classes": ["kb.public"], "privileged": False}
        ],
        "data_classes": {"reads": ["kb.public"], "writes": []},
        "downstream_agents": [],
        "hop_budget": 2,
    },
}
CAPABILITIES = {
    "kb.internal": {
        "resource": "https://kb.internal",
        "scopes_supported": ["kb.public"],
        "tools": {"search": {"data_classes": ["kb.public"], "privileged": False}},
    }
}


def kb_server() -> Starlette:
    async def rpc(request: Request) -> JSONResponse:
        body = await request.json()
        result: dict[str, Any] = {"content": [{"type": "text", "text": "3 articles found"}]}
        return JSONResponse({"jsonrpc": "2.0", "id": body.get("id"), "result": result})

    return Starlette(routes=[Route("/{path:path}", rpc, methods=["POST"])])


async def main(log=print) -> dict[str, Any]:
    async with EmbeddedControlPlane.open(
        {AGENT: MANIFEST},
        capabilities=CAPABILITIES,
        verified_consent_enabled=True,
        client_mapping_enabled=True,
        consent_idp_audiences=PROXY,
        consent_token=CONSENT_TOKEN,
    ) as cp:
        admin = {"Authorization": f"Bearer {cp.admin_token}"}

        # The admin says which agent this IdP client acts as. Unmapped, it would get nothing.
        agents = (await cp.http.get(f"{BASE_URL}/v1/agents", headers=admin)).json()["data"]
        agent_id = next(a["id"] for a in agents if a["name"] == AGENT)
        await cp.http.post(
            f"{BASE_URL}/v1/agents/{agent_id}/clients", headers=admin, json={"client_id": CLIENT_ID}
        )

        config = GatewayConfig(
            pdp_url=BASE_URL,
            route_table={
                (None, "/mcp"): Upstream(url="http://kb.internal", data_class="kb.public")
            },
            oauth_resource_enabled=True,
            resource_url=PROXY,
            idp_issuer=test_idp.ISSUER,
            idp_jwks_url=f"{test_idp.ISSUER}/.well-known/jwks.json",
            consent_token=CONSENT_TOKEN,
        ).validate()
        cp.mount("kb.internal", kb_server())
        proxy = httpx.ASGITransport(app=build_proxy(config, client=cp.http))

        class Network(httpx.AsyncBaseTransport):
            """What the client can reach: the proxy, and everything the embedded instance
            serves (its IdP among it)."""

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                if request.url.host == httpx.URL(PROXY).host:
                    return await proxy.handle_async_request(request)
                return await cp.http.send(request)

        client = httpx.AsyncClient(transport=Network())

        async def sign_in(server: dict[str, Any], resource: str, scopes: list[str]) -> str:
            # A real client runs authorization code + PKCE at the IdP here.
            return cp.idp.mint_access_token(
                sub="alice", audience=resource, client_id=CLIENT_ID, scope=" ".join(scopes)
            )

        result = await call_tool(client, f"{PROXY}/mcp", "search", sign_in, log=log)
        await client.aclose()
        if "result" not in result:
            # Refused: an OAuth error from the proxy, or a JSON-RPC refusal from policy.
            error = result.get("error")
            log(f"   refused: {error if isinstance(error, str) else error['data']['reason']}")
            return {"result": result, "chain": None}
        log("   tool result: " + result["result"]["content"][0]["text"])

        rows = (await cp.http.get(f"{BASE_URL}/v1/audit/decisions", headers=admin)).json()
        chain = (
            await cp.http.get(
                f"{BASE_URL}/v1/audit/actions/{rows['data'][0]['id']}/chain", headers=admin
            )
        ).json()
        root = chain["root_consent"]
        log(
            f"6. audit chain root              -> {root['user_sub']} "
            f"({root['principal_source']}, client {root['client_id']})"
        )
        return {"result": result, "chain": chain}


if __name__ == "__main__":
    asyncio.run(main())
