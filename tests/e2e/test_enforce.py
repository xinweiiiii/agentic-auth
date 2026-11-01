"""Features → "Enforce it on the way out".

The in-process SDK, the sidecar, the gateway, the resource-server guard, the MCP connector
proxy, observe mode, and the egress proxy that is not available yet. Each enforcement point
is its real ASGI app, deciding against the embedded control plane and forwarding to a
recording tool server — only the network is in-process.
"""

from __future__ import annotations

import jwt
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from agentic_auth.boundary import __main__ as boundary_cli
from agentic_auth.boundary.mcp import POLICY_REFUSED
from agentic_auth.boundary.mcp import build_app as build_mcp_proxy
from agentic_auth.boundary.resource import RequireAgenticAuth
from agentic_auth.embedded import EmbeddedControlPlane
from agentic_auth.gateway.app import build_app as build_gateway
from agentic_auth.gateway.config import GatewayConfig
from agentic_auth.sdk import AgentKey
from agentic_auth.sidecar.app import build_app as build_sidecar
from agentic_auth.sidecar.config import SidecarConfig, Upstream
from tests.e2e.conftest import CONTROL_PLANE, asgi_client
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    USER,
    bank_docs,
)
from tests.fixtures.mcp.server import build_mcp_server

pytestmark = pytest.mark.e2e

KB_ROUTE = Upstream(url="https://kb.internal", target=KB_SEARCH_TOOL, data_class="kb.internal")
TERMINATE_ROUTE = Upstream(
    url="https://accounts.internal", target=TERMINATE_ACCOUNT, data_class="account.write"
)


async def test_the_sdk_calls_the_tool_with_the_narrowed_token(cp, tool_server) -> None:
    """In-process SDK: the orchestrator decides with `authorize`, then calls the tool with
    the grant; the tool receives the token narrowed to itself."""
    kb = tool_server("kb.internal")
    sdk = await _registered_sdk(cp)
    ctx = await _support_context(sdk)

    grant = await sdk.authorize(ctx, target=KB_SEARCH_TOOL, data_class="kb.internal")
    response = await sdk.call(grant, "GET", "https://kb.internal/search?q=refund")

    assert response.status_code == 200
    assert _audience(cp, kb.received[-1]["authorization"]) == KB_SEARCH_TOOL


async def test_the_sidecar_forwards_allowed_calls_and_blocks_the_rest(cp, tool_server) -> None:
    """Sidecar: the agent sends its call to the local proxy with its own token. An
    allowed call reaches the tool with a narrowed token; a refused one gets a structured
    403 and never reaches the tool."""
    kb, accounts = tool_server("kb.internal"), tool_server("accounts.internal")
    sdk = await _registered_sdk(cp)
    ctx = await _support_context(sdk)
    sidecar = build_sidecar(
        SidecarConfig(
            pdp_url=CONTROL_PLANE, upstream_map={"/kb": KB_ROUTE, "/accounts": TERMINATE_ROUTE}
        ).validate(),
        client=cp.http,
    )

    async with asgi_client(sidecar) as agent:
        allowed = await agent.get("/kb/search", headers=_bearer(ctx.token))
        refused = await agent.post("/accounts/terminate", headers=_bearer(ctx.token), json={})

    assert allowed.status_code == 200
    narrowed = kb.received[-1]["authorization"]
    assert narrowed != f"Bearer {ctx.token}"
    assert _audience(cp, narrowed) == KB_SEARCH_TOOL
    assert refused.status_code == 403
    error = refused.json()["error"]
    assert (error["code"], error["details"]["reason"]) == ("policy_denied", "OUT_OF_SCOPE")
    assert accounts.received == []


async def test_the_gateway_enforces_for_the_fleet_and_fails_closed(cp, tool_server) -> None:
    """Gateway: one shared enforcement point makes the same decision as the sidecar, and
    when the control plane is unreachable it refuses rather than forwarding."""
    kb = tool_server("kb.internal")
    sdk = await _registered_sdk(cp)
    ctx = await _support_context(sdk)
    gateway = build_gateway(
        GatewayConfig(pdp_url=CONTROL_PLANE, route_table={(None, "/kb"): KB_ROUTE}).validate(),
        client=cp.http,
    )

    async with asgi_client(gateway) as agent:
        allowed = await agent.get("/kb/search", headers=_bearer(ctx.token))
        forwarded = len(kb.received)
        cp.cut()
        try:
            outage = await agent.get("/kb/search", headers=_bearer(ctx.token))
        finally:
            cp.restore()

    assert allowed.status_code == 200 and forwarded == 1
    assert outage.status_code == 503
    assert len(kb.received) == forwarded, "nothing reaches the tool while the PDP is down"


async def test_the_resource_guard_admits_only_a_grant_plus_identity(cp) -> None:
    """Resource-server guard: middleware on the tool's own app admits a call carrying a
    grant for this tool and the calling agent's verified identity. Identity alone, or no
    credentials, never reaches the handler."""
    key = AgentKey.generate()
    sdk = await _registered_sdk(cp)
    await cp.enroll_test_principal(SUPPORT_AGENT, key)
    ctx = await _support_context(sdk)
    grant = await cp.client(SUPPORT_AGENT, key=key).authorize(
        ctx, target=KB_SEARCH_TOOL, data_class="kb.internal"
    )

    handled: list[str] = []

    async def search(request: Request) -> JSONResponse:
        handled.append(request.url.path)
        return JSONResponse({"results": []})

    guarded = RequireAgenticAuth(
        Starlette(routes=[Route("/search", search)]),
        verifier=await cp.verifier(agents=[SUPPORT_AGENT]),
        target_for=lambda scope: KB_SEARCH_TOOL if scope["path"] == "/search" else None,
    )
    identity_only = {k: v for k, v in grant.headers().items() if k != "Authorization"}

    async with asgi_client(guarded, "https://kb.internal") as caller:
        admitted = await caller.get("/search", headers=grant.headers())
        no_grant = await caller.get("/search", headers=identity_only)
        nothing = await caller.get("/search")

    assert admitted.status_code == 200
    assert (no_grant.status_code, nothing.status_code) == (401, 401)
    assert "GRANT_MISSING" in no_grant.text
    assert handled == ["/search"]


async def test_the_mcp_proxy_hides_and_refuses_undeclared_tools(cp) -> None:
    """MCP connector proxy: the agent's connector points at the proxy and nothing else
    changes. `tools/list` shows only declared tools, an allowed `tools/call` returns the
    real result, and an undeclared one is a JSON-RPC error that never reaches the server."""
    mcp_app, upstream = build_mcp_server()
    cp.mount("kb.internal", mcp_app)
    sdk = await _registered_sdk(cp)
    ctx = await _support_context(sdk)
    proxy = build_mcp_proxy(
        GatewayConfig(
            pdp_url=CONTROL_PLANE,
            route_table={
                (None, "/mcp"): Upstream(url="https://kb.internal", data_class="kb.internal")
            },
        ).validate(),
        client=cp.http,
        declared_tools=frozenset({KB_SEARCH_TOOL}),
    )

    async with asgi_client(proxy) as connector:
        listing = await connector.post("/mcp", headers=_bearer(ctx.token), json=_rpc("tools/list"))
        allowed = await connector.post(
            "/mcp",
            headers=_bearer(ctx.token),
            json=_rpc("tools/call", name="search", arguments={"q": "refund"}),
        )
        refused = await connector.post(
            "/mcp",
            headers=_bearer(ctx.token),
            json=_rpc("tools/call", name="terminate_account", arguments={"account_id": "a"}),
        )

    assert [tool["name"] for tool in listing.json()["result"]["tools"]] == ["search"]
    assert allowed.json()["result"]["content"][0]["text"] == "real result"
    error = refused.json()["error"]
    assert error["code"] == POLICY_REFUSED
    assert error["data"]["guarantee_level"] == "connector"
    assert upstream.last_tool == "search", "terminate_account never reached the server"


async def test_observe_mode_records_refusals_without_blocking(cp, tool_server) -> None:
    """Observe mode: a sidecar in observe mode decides and records every call, but
    forwards even the ones policy refuses. The decision log shows each refusal as not
    enforced — the report to read before switching to enforcing."""
    accounts = tool_server("accounts.internal")
    sdk = await _registered_sdk(cp)
    ctx = await _support_context(sdk)
    sidecar = build_sidecar(
        SidecarConfig(
            pdp_url=CONTROL_PLANE, upstream_map={"/accounts": TERMINATE_ROUTE}, observe_mode=True
        ).validate(),
        client=cp.http,
    )

    async with asgi_client(sidecar) as agent:
        response = await agent.post("/accounts/terminate", headers=_bearer(ctx.token), json={})

    assert response.status_code == 200 and len(accounts.received) == 1
    rows = (await sdk.audit.decisions())["data"]
    refused = [r for r in rows if r["target"] == TERMINATE_ACCOUNT]
    assert [(r["outcome"], r["deny_reason"], r["enforced"]) for r in refused] == [
        ("deny", "OUT_OF_SCOPE", False)
    ]


def test_the_egress_proxy_says_it_is_not_available(capsys, tmp_path) -> None:
    """Egress proxy: not available yet. Given a valid config, the command refuses to start
    a proxy that could not enforce, says why, and exits non-zero."""
    config = tmp_path / "egress.yaml"
    config.write_text(
        f"pdp_url: {CONTROL_PLANE}\n"
        "route_table:\n"
        '  "|/kb":\n'
        "    url: https://kb.internal\n"
        f"    target: {KB_SEARCH_TOOL}\n"
        "    data_class: kb.internal\n",
        encoding="utf-8",
    )

    exit_code = boundary_cli.main(["egress-proxy", str(config)])

    assert exit_code != 0
    assert "not available yet" in capsys.readouterr().err


# -- helpers ----------------------------------------------------------------------------


async def _registered_sdk(cp: EmbeddedControlPlane):
    await cp.register(bank_docs())
    return cp.client()


async def _support_context(sdk):
    """bank-assistant -> balance-agent -> support-agent: the context support-agent holds.
    The knowledge base is untrusted for support-agent, but nothing here reads it first."""
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, ctx = await sdk.hop(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return ctx


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _audience(cp: EmbeddedControlPlane, authorization: str) -> str:
    """The target a forwarded token was narrowed to, verified against the issuer's key."""
    [key] = cp.jwks()["keys"]
    claims = jwt.decode(
        authorization.removeprefix("Bearer "),
        jwt.PyJWK(key).key,
        algorithms=["EdDSA"],
        options={"verify_aud": False},
    )
    return claims["aud"]


def _rpc(method: str, **params) -> dict:
    body: dict = {"jsonrpc": "2.0", "id": 7, "method": method}
    if params:
        body["params"] = params
    return body
