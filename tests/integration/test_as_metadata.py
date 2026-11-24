"""The control plane's authorization server metadata (feature 011, US4, M3, RFC 8414)."""

from __future__ import annotations

import pytest

ISSUER = "https://authz.test"


@pytest.fixture
def m3(flags):
    flags(as_metadata_enabled=True, issuer=ISSUER)


async def test_the_document_describes_an_exchange_only_server(client, register_chain, m3) -> None:
    await register_chain()
    r = await client.get("/.well-known/oauth-authorization-server")

    assert r.status_code == 200
    assert r.headers["cache-control"] == "public, max-age=300"
    doc = r.json()
    assert doc["issuer"] == ISSUER
    assert doc["token_endpoint"] == f"{ISSUER}/v1/token/exchange"
    assert doc["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
    assert doc["grant_types_supported"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert doc["token_endpoint_auth_methods_supported"] == ["none"]
    assert doc["agentic_auth_consent_endpoint"] == f"{ISSUER}/v1/consent"
    # Logins and client registration belong to the customer's IdP (FR-008, FR-015).
    assert "authorization_endpoint" not in doc
    assert "registration_endpoint" not in doc
    # Every data class a pinned policy declares, and only those.
    assert doc["scopes_supported"] == ["account.read", "account.write", "kb.internal", "kb.public"]


async def test_every_endpoint_it_names_answers(client, register_chain, m3) -> None:
    await register_chain()
    doc = (await client.get("/.well-known/oauth-authorization-server")).json()
    for key in ("token_endpoint", "jwks_uri", "agentic_auth_consent_endpoint"):
        path = doc[key].removeprefix(ISSUER)
        method = "GET" if key == "jwks_uri" else "POST"
        r = await client.request(method, path)
        assert r.status_code != 404, key


async def test_the_transaction_endpoint_appears_only_when_enabled(client, m3, flags) -> None:
    flags(transaction_tokens_enabled=True)
    on = (await client.get("/.well-known/oauth-authorization-server")).json()
    flags(transaction_tokens_enabled=False)
    off = (await client.get("/.well-known/oauth-authorization-server")).json()
    assert on["agentic_auth_transaction_endpoint"] == f"{ISSUER}/v1/token/transaction"
    assert "agentic_auth_transaction_endpoint" not in off


async def test_with_no_policies_no_scopes_are_advertised(client, m3) -> None:
    doc = (await client.get("/.well-known/oauth-authorization-server")).json()
    assert doc["scopes_supported"] == []


async def test_it_is_off_by_default(client, flags) -> None:
    flags(as_metadata_enabled=False)
    assert (await client.get("/.well-known/oauth-authorization-server")).status_code == 404
