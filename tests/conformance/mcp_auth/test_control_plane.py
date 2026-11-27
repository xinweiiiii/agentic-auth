"""The control plane's side of the MCP authorization baseline: metadata, verified consent,
client mapping, and failing closed when the IdP's keys are gone."""

from __future__ import annotations

import pytest

from tests.conformance.mcp_auth.conftest import CLIENT_ID, TOOLS_CALL, bearer
from tests.fixtures.chains import ORCHESTRATOR
from tests.fixtures.idp.server import ISSUER

pytestmark = pytest.mark.conformance


async def test_MCPA_AS_META(stack) -> None:
    stack.flags(issuer=stack.issuer_url)
    r = await stack.call("GET", "/.well-known/oauth-authorization-server")
    doc = r.json()

    assert r.status_code == 200
    assert doc["issuer"] == stack.issuer_url
    for key in ("token_endpoint", "jwks_uri"):
        assert doc[key].startswith(stack.issuer_url)
    assert "urn:ietf:params:oauth:grant-type:token-exchange" in doc["grant_types_supported"]
    assert "authorization_endpoint" not in doc
    assert "registration_endpoint" not in doc
    assert "kb.public" in doc["scopes_supported"]


async def test_MCPA_CONSENT_VERIFY(stack) -> None:
    token = stack.token()

    ok = await stack.call(
        "POST", "/v1/consent", headers=stack.admin_headers, json={"subject_token": token}
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["user_sub"] == f"{ISSUER}#alice"
    assert ok.json()["principal_source"] in {"verified", "embedded-test"}

    missing = await stack.call(
        "POST",
        "/v1/consent",
        headers=stack.admin_headers,
        json={"scope": ORCHESTRATOR, "user_sub": "u"},
    )
    assert missing.status_code == 422

    mismatch = await stack.call(
        "POST",
        "/v1/consent",
        headers=stack.admin_headers,
        json={"subject_token": token, "user_sub": "someone-else"},
    )
    assert mismatch.status_code == 422

    forged = await stack.call(
        "POST",
        "/v1/consent",
        headers=stack.admin_headers,
        json={"subject_token": stack.token(alg="none")},
    )
    assert forged.status_code == 401


async def test_MCPA_CLIENT_MAP(stack) -> None:
    mapped = await stack.call(
        "POST", "/v1/consent", headers=stack.admin_headers, json={"subject_token": stack.token()}
    )
    assert mapped.status_code == 201
    assert mapped.json()["scope"] == ORCHESTRATOR
    assert mapped.json()["client_id"] == CLIENT_ID

    unmapped = await stack.call(
        "POST",
        "/v1/consent",
        headers=stack.admin_headers,
        json={"subject_token": stack.token(azp="nobody-mapped-me")},
    )
    assert unmapped.status_code == 403
    details = unmapped.json()["error"]["details"]
    assert details["reason"] == "CLIENT_NOT_AUTHORIZED"
    assert details["recoverable"] is False and details["next"] == "cold_start"

    # Through the proxy: governed by the mapped agent's manifest.
    proxy = stack.proxy()
    allowed = await proxy.post("/mcp", json=TOOLS_CALL, headers=bearer(stack.token()))
    assert "result" in allowed.json(), allowed.text
    denied = await proxy.post(
        "/mcp",
        json={**TOOLS_CALL, "params": {"name": "terminate_account"}},
        headers=bearer(stack.token()),
    )
    assert denied.json()["error"]["data"]["reason"] in {"OUT_OF_SCOPE", "EDGE_NOT_IN_DAG"}


async def test_MCPA_FAILCLOSED(stack) -> None:
    stack.idp.down = True
    proxy = stack.proxy()
    gateway = stack.gateway()

    r = await proxy.post("/mcp", json=TOOLS_CALL, headers=bearer(stack.token()))
    assert r.status_code == 503 and r.json()["error"]["data"]["reason"] == "IDP_UNAVAILABLE"
    r = await gateway.get("/kb/search", headers=bearer(stack.token(aud=stack.gateway_url)))
    assert r.status_code == 503
    r = await stack.call(
        "POST", "/v1/consent", headers=stack.admin_headers, json={"subject_token": stack.token()}
    )
    assert r.status_code == 503
    assert stack.mcp.calls == [] and stack.upstream.count == 0
