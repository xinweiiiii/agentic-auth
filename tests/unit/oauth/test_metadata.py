"""Reading an IdP's authorization server metadata (research R2, R9)."""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport

from agentic_auth.oauth.metadata import MetadataUnavailable, discover, discovery_urls
from tests.fixtures.idp.server import ISSUER, FakeIdp, build_idp


def _client_for(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_discovery_urls_follow_rfc_8414_then_oidc() -> None:
    assert discovery_urls("https://idp.example.com") == [
        "https://idp.example.com/.well-known/oauth-authorization-server",
        "https://idp.example.com/.well-known/openid-configuration",
    ]
    assert discovery_urls("https://idp.example.com/tenant/") == [
        "https://idp.example.com/.well-known/oauth-authorization-server/tenant",
        "https://idp.example.com/tenant/.well-known/openid-configuration",
    ]


async def test_the_fake_idp_is_discovered() -> None:
    app, _ = build_idp(FakeIdp())
    http = httpx.AsyncClient(transport=ASGITransport(app=app))
    server = await discover(ISSUER, lambda: http)

    assert server.issuer == ISSUER
    assert server.jwks_uri == f"{ISSUER}/.well-known/jwks.json"
    assert server.scopes_supported == ("account.read", "kb.internal", "kb.public")
    assert server.source.endswith("/oauth-authorization-server")


async def test_oidc_discovery_is_the_fallback() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": "https://k"})
        return httpx.Response(404)

    http = _client_for(handler)
    server = await discover(ISSUER, lambda: http)
    assert server.jwks_uri == "https://k"
    assert server.scopes_supported is None  # absent is not the same as empty


async def test_a_document_naming_another_issuer_is_not_trusted() -> None:
    http = _client_for(lambda _: httpx.Response(200, json={"issuer": "https://evil"}))
    with pytest.raises(MetadataUnavailable, match="names issuer"):
        await discover(ISSUER, lambda: http)


@pytest.mark.parametrize(
    "response",
    [httpx.Response(503), httpx.Response(200, content=b"nope"), httpx.Response(200, json=[1])],
)
async def test_unusable_documents_are_unavailable(response) -> None:
    http = _client_for(lambda _: response)
    with pytest.raises(MetadataUnavailable):
        await discover(ISSUER, lambda: http)


async def test_a_network_failure_is_unavailable_and_names_both_urls() -> None:
    def boom(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    http = _client_for(boom)
    with pytest.raises(MetadataUnavailable) as caught:
        await discover(ISSUER, lambda: http)
    assert "oauth-authorization-server" in str(caught.value)
    assert "openid-configuration" in str(caught.value)
