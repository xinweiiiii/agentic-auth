"""The MCP authorization conformance suite's deployments (feature 011, M5).

Every test takes ``stack`` and runs twice: ``server`` (the control plane on PostgreSQL and
Redis, the integration harness's ``oauth_stack``) and ``embedded`` (an
``EmbeddedControlPlane`` on SQLite, nothing else running). Both get the same fake IdP, the
same recording MCP server and upstream, and a connector proxy and a gateway with every M1–M4
flag on, so a requirement that holds in one and not the other fails by name.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
import pytest_asyncio

from tests.fixtures.idp.server import ISSUER, JWKS_URL, FakeIdp, build_idp

PROXY_URL = "https://mcp-proxy.test"
GATEWAY_URL = "https://gateway.test"
CONSENT_TOKEN = "pep-consent-token"
CLIENT_ID = "desktop-client"


@dataclass
class Stack:
    name: str
    idp: FakeIdp
    mcp: Any
    upstream: Any
    proxy: Callable[..., httpx.AsyncClient]
    gateway: Callable[..., httpx.AsyncClient]
    _call: Callable[..., Any]
    _set_pdp_down: Callable[[bool], None]
    _flags: Callable[..., None]
    admin_headers: dict[str, str]
    proxy_url: str = PROXY_URL
    gateway_url: str = GATEWAY_URL
    issuer_url: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def token(self, **claims: Any) -> str:
        return self.idp.mint_access_token(**{"aud": self.proxy_url, "azp": CLIENT_ID, **claims})

    async def call(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """A request to the control plane itself."""
        return await self._call(method, path, **kwargs)

    def pdp_down(self, down: bool = True) -> None:
        self._set_pdp_down(down)

    def flags(self, **values: Any) -> None:
        self._flags(**values)


M1_TO_M4 = {
    "verified_consent_enabled": True,
    "client_mapping_enabled": True,
    "as_metadata_enabled": True,
    "consent_idp_audiences": f"{PROXY_URL},{GATEWAY_URL}",
    "consent_token": CONSENT_TOKEN,
}


async def _map_client(stack: Stack, agent: str) -> None:
    agents = (await stack.call("GET", "/v1/agents?limit=100", headers=stack.admin_headers)).json()
    agent_id = next(a["id"] for a in agents["data"] if a["name"] == agent)
    r = await stack.call(
        "POST",
        f"/v1/agents/{agent_id}/clients",
        headers=stack.admin_headers,
        json={"client_id": CLIENT_ID},
    )
    assert r.status_code == 201, r.text


@pytest_asyncio.fixture
async def server_stack(oauth_stack, flags, client, admin_headers) -> AsyncIterator[Stack]:
    flags(**M1_TO_M4)

    def set_pdp_down(down: bool) -> None:
        oauth_stack.router.pdp_down = down

    stack = Stack(
        name="server",
        idp=oauth_stack.idp,
        mcp=oauth_stack.mcp,
        upstream=oauth_stack.upstream,
        proxy=lambda **kw: oauth_stack.proxy(**{"consent_scope": None, **kw}),
        gateway=lambda **kw: oauth_stack.gateway(**{"consent_scope": None, **kw}),
        _call=client.request,
        _set_pdp_down=set_pdp_down,
        _flags=flags,
        admin_headers=admin_headers,
        issuer_url="https://authz.test",
    )
    from tests.fixtures.chains import ORCHESTRATOR

    await _map_client(stack, ORCHESTRATOR)
    yield stack


@pytest_asyncio.fixture
async def embedded_stack() -> AsyncIterator[Stack]:
    from prometheus_client import CollectorRegistry

    from agentic_auth.boundary.mcp import build_app as build_proxy
    from agentic_auth.embedded import BASE_URL, HOST, EmbeddedControlPlane
    from agentic_auth.gateway.app import build_app as build_gateway
    from agentic_auth.gateway.config import GatewayConfig
    from agentic_auth.sidecar.config import Upstream
    from tests.fixtures.chains import ORCHESTRATOR, chain_docs
    from tests.fixtures.discovery.server import RESOURCES
    from tests.fixtures.mcp.server import build_mcp_server
    from tests.fixtures.upstream.server import build_upstream

    idp = FakeIdp()
    idp_app, _ = build_idp(idp)
    mcp_app, mcp = build_mcp_server()
    upstream_app, upstream = build_upstream()
    settings = {
        **M1_TO_M4,
        "principal_idp_issuer": ISSUER,
        "principal_idp_jwks_url": JWKS_URL,
        "principal_idp_audience": "agentic-auth",
        # M3 needs an https issuer (RFC 8414); the server stack sets it in the one test that
        # reads the metadata, because changing it there changes every token's `iss`.
        "issuer": "https://authz.test",
    }
    from tests.fixtures.discovery.server import AUTHORIZATION_SERVERS, fake_discovery_app

    async with EmbeddedControlPlane.open(capabilities=RESOURCES, **settings) as cp:
        # M3 follows each capability source to its authorization server: serve those before
        # registering, as a real deployment's network would.
        for host in AUTHORIZATION_SERVERS:
            cp.mount(host, fake_discovery_app)
        await cp.register(chain_docs())
        cp.mount("idp.test", idp_app)
        cp.mount("kb.internal", mcp_app)
        cp.mount("upstream.test", upstream_app)
        clients: list[httpx.AsyncClient] = []
        transport = cp.http._transport

        def _client(app: Any, base_url: str) -> httpx.AsyncClient:
            c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base_url)
            clients.append(c)
            return c

        m1 = {
            "oauth_resource_enabled": True,
            "idp_issuer": ISSUER,
            "idp_jwks_url": JWKS_URL,
            "consent_token": CONSENT_TOKEN,
        }

        def proxy(**overrides: Any) -> httpx.AsyncClient:
            table = {(None, "/mcp"): Upstream(url="http://kb.internal", data_class="kb.public")}
            config = GatewayConfig(
                pdp_url=BASE_URL,
                route_table=table,
                **{**m1, "resource_url": PROXY_URL, **overrides},
            ).validate()
            return _client(
                build_proxy(config, client=httpx.AsyncClient(transport=transport)), PROXY_URL
            )

        def gateway(**overrides: Any) -> httpx.AsyncClient:
            table = {
                (None, "/kb"): Upstream(
                    url="http://upstream.test",
                    target="mcp://kb.internal/search",
                    data_class="kb.public",
                )
            }
            config = GatewayConfig(
                pdp_url=BASE_URL,
                route_table=table,
                **{**m1, "resource_url": GATEWAY_URL, **overrides},
            ).validate()
            app = build_gateway(
                config, client=httpx.AsyncClient(transport=transport), registry=CollectorRegistry()
            )
            return _client(app, GATEWAY_URL)

        async def call(method: str, path: str, **kwargs: Any) -> httpx.Response:
            return await cp.http.request(method, f"{BASE_URL}{path}", **kwargs)

        def set_pdp_down(down: bool) -> None:
            (cp.cut if down else cp.restore)(HOST)

        stack = Stack(
            name="embedded",
            idp=idp,
            mcp=mcp,
            upstream=upstream,
            proxy=proxy,
            gateway=gateway,
            _call=call,
            _set_pdp_down=set_pdp_down,
            _flags=lambda **values: cp.configure(**values),
            admin_headers={"Authorization": f"Bearer {cp.admin_token}"},
            issuer_url="https://authz.test",
            extra={"cp": cp},
        )
        await _map_client(stack, ORCHESTRATOR)
        try:
            yield stack
        finally:
            for c in clients:
                await c.aclose()


@pytest.fixture(params=["server", "embedded"])
def stack(request: pytest.FixtureRequest) -> Stack:
    return request.getfixturevalue(f"{request.param}_stack")


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


TOOLS_CALL = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "search"}}
