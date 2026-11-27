"""MCP 2026-07-28 authorization: the connector proxy and the gateway as protected resources.

Each test is named for the requirement it covers (REQUIREMENTS.md) and runs against both
enforcement points in both deployments.
"""

from __future__ import annotations

import pytest

from tests.conformance.mcp_auth.conftest import TOOLS_CALL, bearer
from tests.fixtures.idp.server import ISSUER

pytestmark = pytest.mark.conformance

PEPS = ["proxy", "gateway"]


async def _send(stack, pep: str, token: str | None = None, *, query: str = ""):
    headers = bearer(token) if token else {}
    if pep == "proxy":
        return await stack.proxy().post(f"/mcp{query}", json=TOOLS_CALL, headers=headers)
    return await stack.gateway().get(f"/kb/search{query}", headers=headers)


def _token_for(stack, pep: str, **claims) -> str:
    aud = stack.proxy_url if pep == "proxy" else stack.gateway_url
    return stack.token(**{"aud": aud, **claims})


@pytest.mark.parametrize("pep", PEPS)
async def test_MCPA_RS_PRM(stack, pep) -> None:
    client = stack.proxy() if pep == "proxy" else stack.gateway()
    r = await client.get("/.well-known/oauth-protected-resource")
    doc = r.json()

    assert r.status_code == 200
    assert doc["resource"] == (stack.proxy_url if pep == "proxy" else stack.gateway_url)
    assert doc["authorization_servers"] == [ISSUER]
    assert doc["scopes_supported"] == ["kb.public"]
    assert doc["bearer_methods_supported"] == ["header"]


@pytest.mark.parametrize("pep", PEPS)
async def test_MCPA_RS_401(stack, pep) -> None:
    r = await _send(stack, pep)
    base = stack.proxy_url if pep == "proxy" else stack.gateway_url

    assert r.status_code == 401
    challenge = r.headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert f'resource_metadata="{base}/.well-known/oauth-protected-resource"' in challenge


@pytest.mark.parametrize("pep", PEPS)
async def test_MCPA_RS_AUD(stack, pep) -> None:
    other = stack.gateway_url if pep == "proxy" else stack.proxy_url
    for aud in (other, "https://unrelated.test", [other, "https://unrelated.test"]):
        r = await _send(stack, pep, stack.token(aud=aud))
        assert r.status_code == 401, aud
        assert 'error_description="audience"' in r.headers["www-authenticate"]
    ok = await _send(stack, pep, _token_for(stack, pep, aud=["https://unrelated.test"]))
    assert ok.status_code == 401
    ok = await _send(
        stack,
        pep,
        _token_for(
            stack,
            pep,
            aud=[
                "https://unrelated.test",
                stack.proxy_url if pep == "proxy" else stack.gateway_url,
            ],
        ),
    )
    assert ok.status_code == 200, ok.text


@pytest.mark.parametrize("pep", PEPS)
@pytest.mark.parametrize(
    ("claims", "check"),
    [
        ({"kid": "not-a-published-key"}, "signature"),
        ({"issuer": "https://evil.test"}, "issuer"),
        ({"expires_in": -600}, "expired"),
        ({"alg": "none"}, "algorithm"),
        ({"alg": "HS256"}, "algorithm"),
    ],
)
async def test_MCPA_RS_SIG(stack, pep, claims, check) -> None:
    r = await _send(stack, pep, _token_for(stack, pep, **claims))
    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers["www-authenticate"]
    assert f'error_description="{check}"' in r.headers["www-authenticate"]
    assert "resource_metadata=" in r.headers["www-authenticate"]


@pytest.mark.parametrize("pep", PEPS)
async def test_MCPA_RS_SCOPE(stack, pep) -> None:
    r = await _send(stack, pep, _token_for(stack, pep, scope="account.read"))
    assert r.status_code == 403
    assert 'error="insufficient_scope"' in r.headers["www-authenticate"]
    assert 'scope="kb.public"' in r.headers["www-authenticate"]


@pytest.mark.parametrize("pep", PEPS)
async def test_MCPA_RS_BEARER(stack, pep) -> None:
    token = _token_for(stack, pep)
    r = await _send(stack, pep, query=f"?access_token={token}")
    assert r.status_code in {400, 401}
    assert stack.mcp.calls == [] and stack.upstream.count == 0
