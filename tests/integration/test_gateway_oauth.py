"""The gateway as an OAuth 2.1 protected resource (feature 011, US1, M1).

The same gate as the connector proxy, in front of the same unmodified ``enforce()``. The
gateway speaks plain HTTP rather than JSON-RPC, so a refusal after the challenge uses the
gateway's deny envelope; the challenge itself is identical.
"""

from __future__ import annotations

import pytest

from tests.fixtures.idp.server import ISSUER
from tests.fixtures.upstream.recording import assert_no_token_material


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def enforce_spy(monkeypatch):
    from agentic_auth.gateway import app

    calls: list[str] = []
    real = app.enforce

    async def spy(*args, **kwargs):
        calls.append(kwargs["path"])
        return await real(*args, **kwargs)

    monkeypatch.setattr(app, "enforce", spy)
    return calls


def _token(stack, **claims) -> str:
    return stack.token(**{"aud": stack.gateway_url, **claims})


async def test_no_token_is_challenged(oauth_stack) -> None:
    gateway = oauth_stack.gateway()
    r = await gateway.get("/kb/search")
    assert r.status_code == 401
    assert (
        'resource_metadata="https://gateway.test/.well-known/oauth-protected-resource"'
        in r.headers["www-authenticate"]
    )
    assert oauth_stack.upstream.count == 0


async def test_the_metadata_names_the_gateway(oauth_stack) -> None:
    gateway = oauth_stack.gateway()
    r = await gateway.get("/.well-known/oauth-protected-resource")
    assert r.json()["resource"] == "https://gateway.test"
    assert r.json()["authorization_servers"] == [ISSUER]
    assert r.json()["scopes_supported"] == ["kb.public"]


async def test_the_health_routes_need_no_token(oauth_stack) -> None:
    gateway = oauth_stack.gateway()
    assert (await gateway.get("/v1/gateway/routes")).status_code == 200


async def test_a_valid_token_reaches_the_upstream_with_a_hop_token_only(oauth_stack) -> None:
    gateway = oauth_stack.gateway()
    token = _token(oauth_stack)

    r = await gateway.get("/kb/search?q=x", headers=_bearer(token))
    again = await gateway.get("/kb/search?q=y", headers=_bearer(token))

    assert r.status_code == 200, r.text
    assert again.status_code == 200
    assert oauth_stack.router.consent_calls == 1
    assert oauth_stack.upstream.count == 2
    assert_no_token_material(token, oauth_stack.upstream)


async def test_a_token_for_the_proxy_is_not_accepted_by_the_gateway(
    oauth_stack, enforce_spy
) -> None:
    """RFC 8707: each resource accepts only tokens issued for it."""
    gateway = oauth_stack.gateway()
    r = await gateway.get("/kb/search", headers=_bearer(oauth_stack.token()))  # aud = proxy
    assert r.status_code == 401
    assert 'error_description="audience"' in r.headers["www-authenticate"]
    assert enforce_spy == []


@pytest.mark.parametrize(
    "claims",
    [{"expires_in": -600}, {"alg": "none"}, {"issuer": "https://evil.test"}, {"kid": "nope"}],
)
async def test_a_bad_token_never_reaches_enforce(oauth_stack, enforce_spy, claims) -> None:
    gateway = oauth_stack.gateway()
    r = await gateway.get("/kb/search", headers=_bearer(_token(oauth_stack, **claims)))
    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers["www-authenticate"]
    assert enforce_spy == []
    assert oauth_stack.upstream.count == 0


async def test_insufficient_scope_is_403(oauth_stack) -> None:
    gateway = oauth_stack.gateway()
    r = await gateway.get("/kb/search", headers=_bearer(_token(oauth_stack, scope="account.read")))
    assert r.status_code == 403
    assert 'error="insufficient_scope"' in r.headers["www-authenticate"]


async def test_an_idp_outage_is_a_retryable_refusal(oauth_stack) -> None:
    oauth_stack.idp.down = True
    gateway = oauth_stack.gateway()
    r = await gateway.get("/kb/search", headers=_bearer(_token(oauth_stack)))
    assert r.status_code == 503
    details = r.json()["error"]["details"]
    assert details["reason"] == "IDP_UNAVAILABLE" and details["recoverable"] is True


async def test_a_consent_refusal_uses_the_deny_envelope(oauth_stack, flags) -> None:
    flags(consent_idp_audiences="https://somewhere-else.test")
    gateway = oauth_stack.gateway()
    r = await gateway.get("/kb/search", headers=_bearer(_token(oauth_stack)))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "policy_denied"
    assert r.json()["error"]["details"]["reason"] == "SUBJECT_TOKEN_INVALID"


async def test_refusals_are_counted_with_their_reason(oauth_stack) -> None:
    gateway = oauth_stack.gateway()
    await gateway.get("/kb/search")
    body = (await gateway.get("/metrics")).text
    assert 'reason="TOKEN_MISSING"' in body


async def test_observe_mode_cannot_be_combined_with_m1(oauth_stack) -> None:
    from agentic_auth.gateway.config import GatewayConfigError

    with pytest.raises(GatewayConfigError, match="observe"):
        oauth_stack.gateway(observe_mode=True)
