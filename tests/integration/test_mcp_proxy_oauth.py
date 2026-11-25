"""The connector proxy as an OAuth 2.1 protected resource (feature 011, US1, M1).

An off-the-shelf MCP client, with no Agentic Auth code: it calls, is challenged, finds the
IdP through the proxy's metadata, signs in, and calls again with the IdP's token. Every bad
token stops at the proxy, before a policy decision, and nothing the client presented ever
reaches the upstream server.
"""

from __future__ import annotations

import logging

import pytest

from agentic_auth.oauth.validate import fingerprint
from tests.fixtures.idp.server import ISSUER, FakeIdp
from tests.fixtures.upstream.recording import assert_no_token_material


def _call(tool: str = "search") -> dict:
    return {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": tool}}


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def enforce_spy(monkeypatch):
    """Counts calls into the shared enforce(), to prove a refused token never got there."""
    from agentic_auth.boundary import mcp

    calls: list[str] = []
    real = mcp.enforce

    async def spy(*args, **kwargs):
        calls.append(kwargs["path"])
        return await real(*args, **kwargs)

    monkeypatch.setattr(mcp, "enforce", spy)
    return calls


# -- discovery: 401 → metadata --------------------------------------------------------------


async def test_a_call_without_a_token_is_challenged_in_http(oauth_stack) -> None:
    proxy = oauth_stack.proxy()
    r = await proxy.post("/mcp", json=_call())

    assert r.status_code == 401
    challenge = r.headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert (
        'resource_metadata="https://mcp-proxy.test/.well-known/oauth-protected-resource"'
        in challenge
    )
    assert 'scope="kb.public"' in challenge
    assert "jsonrpc" not in r.json()  # an HTTP challenge, not a JSON-RPC error


async def test_the_metadata_names_the_proxy_its_idp_and_its_scopes(oauth_stack) -> None:
    proxy = oauth_stack.proxy()
    r = await proxy.get("/.well-known/oauth-protected-resource")

    assert r.status_code == 200
    assert r.json() == {
        "resource": "https://mcp-proxy.test",
        "authorization_servers": [ISSUER],
        "scopes_supported": ["kb.public"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Agentic Auth protected resource",
    }


async def test_a_resource_with_a_path_serves_the_path_suffixed_metadata(oauth_stack) -> None:
    proxy = oauth_stack.proxy(resource_url="https://mcp-proxy.test/mcp")
    for path in (
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource",
    ):
        r = await proxy.get(path)
        assert r.json()["resource"] == "https://mcp-proxy.test/mcp"


async def test_every_method_needs_a_token_not_only_tools_call(oauth_stack) -> None:
    proxy = oauth_stack.proxy()
    for method in ("initialize", "tools/list", "resources/read"):
        r = await proxy.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method})
        assert r.status_code == 401, method
    assert oauth_stack.mcp.headers == []  # nothing reached the upstream


# -- a valid token: one consent, then the existing decision ---------------------------------


async def test_a_valid_token_calls_the_tool_and_consents_once(oauth_stack, enforce_spy) -> None:
    proxy = oauth_stack.proxy()
    token = oauth_stack.token()

    first = await proxy.post("/mcp", json=_call(), headers=_bearer(token))
    second = await proxy.post("/mcp", json=_call(), headers=_bearer(token))

    assert first.status_code == 200, first.text
    assert first.json()["result"]["content"][0]["text"] == "real result"
    assert second.json()["result"]
    assert oauth_stack.router.consent_calls == 1  # one login, one consent
    assert len(enforce_spy) == 2


async def test_a_new_token_is_a_new_session(oauth_stack) -> None:
    proxy = oauth_stack.proxy()
    await proxy.post("/mcp", json=_call(), headers=_bearer(oauth_stack.token()))
    await proxy.post("/mcp", json=_call(), headers=_bearer(oauth_stack.token(sub="bob")))
    assert oauth_stack.router.consent_calls == 2


async def test_a_valid_token_is_not_authority_by_itself(oauth_stack) -> None:
    """FR-005: the manifest still decides. The orchestrator never declared this tool."""
    proxy = oauth_stack.proxy()
    r = await proxy.post(
        "/mcp", json=_call("terminate_account"), headers=_bearer(oauth_stack.token())
    )

    error = r.json()["error"]
    assert error["data"]["reason"] in {"OUT_OF_SCOPE", "EDGE_NOT_IN_DAG"}
    assert oauth_stack.mcp.calls == []


async def test_the_audit_chain_starts_at_the_verified_human(
    oauth_stack, client, admin_headers
) -> None:
    proxy = oauth_stack.proxy()
    await proxy.post("/mcp", json=_call(), headers=_bearer(oauth_stack.token()))
    rows = (await client.get("/v1/audit/decisions", headers=admin_headers)).json()["data"]

    chain = (
        await client.get(f"/v1/audit/actions/{rows[0]['id']}/chain", headers=admin_headers)
    ).json()
    assert chain["root_consent"]["user_sub"] == f"{ISSUER}#alice"
    assert chain["root_consent"]["principal_source"] == "verified"


# -- every bad token stops at the proxy ------------------------------------------------------


@pytest.mark.parametrize(
    ("claims", "check"),
    [
        ({"aud": "https://other-resource.test"}, "audience"),
        ({"issuer": "https://evil.test"}, "issuer"),
        ({"expires_in": -600}, "expired"),
        ({"not_before": 600}, "not_yet_valid"),
        ({"alg": "none"}, "algorithm"),
        ({"alg": "HS256"}, "algorithm"),
        ({"kid": "unknown-key"}, "signature"),
    ],
)
async def test_a_bad_token_is_refused_before_any_decision(
    oauth_stack, enforce_spy, caplog, claims, check
) -> None:
    proxy = oauth_stack.proxy()
    token = oauth_stack.token(**claims)

    with caplog.at_level(logging.INFO):
        r = await proxy.post("/mcp", json=_call(), headers=_bearer(token))

    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers["www-authenticate"]
    assert f'error_description="{check}"' in r.headers["www-authenticate"]
    assert "resource_metadata=" in r.headers["www-authenticate"]
    assert enforce_spy == []  # INV-2
    assert oauth_stack.router.consent_calls == 0
    assert token not in caplog.text
    assert any(getattr(r, "token_fingerprint", None) == fingerprint(token) for r in caplog.records)


async def test_a_token_signed_by_another_key_is_refused(oauth_stack) -> None:
    proxy = oauth_stack.proxy()
    forged = FakeIdp(kid=oauth_stack.idp.kid).mint_access_token(aud=oauth_stack.proxy_url)
    r = await proxy.post("/mcp", json=_call(), headers=_bearer(forged))
    assert r.status_code == 401
    assert 'error_description="signature"' in r.headers["www-authenticate"]


async def test_a_token_in_the_query_string_is_refused(oauth_stack, enforce_spy) -> None:
    proxy = oauth_stack.proxy()
    r = await proxy.post(f"/mcp?access_token={oauth_stack.token()}", json=_call())
    assert r.status_code == 400
    assert 'error="invalid_request"' in r.headers["www-authenticate"]
    assert enforce_spy == []


async def test_a_token_whose_scope_lacks_the_data_class_is_403(oauth_stack, enforce_spy) -> None:
    proxy = oauth_stack.proxy()
    r = await proxy.post(
        "/mcp", json=_call(), headers=_bearer(oauth_stack.token(scope="account.read"))
    )
    assert r.status_code == 403
    assert 'error="insufficient_scope"' in r.headers["www-authenticate"]
    assert 'scope="kb.public"' in r.headers["www-authenticate"]
    assert enforce_spy == []


async def test_a_token_whose_scope_includes_the_data_class_is_allowed(oauth_stack) -> None:
    proxy = oauth_stack.proxy()
    r = await proxy.post(
        "/mcp", json=_call(), headers=_bearer(oauth_stack.token(scope="kb.public openid"))
    )
    assert r.json()["result"]


async def test_an_unreachable_idp_fails_closed_and_retryable(oauth_stack, enforce_spy) -> None:
    oauth_stack.idp.down = True
    proxy = oauth_stack.proxy()
    r = await proxy.post("/mcp", json=_call(), headers=_bearer(oauth_stack.token()))

    assert r.status_code == 503
    assert r.json()["error"]["code"] == -32603
    assert r.json()["error"]["data"]["reason"] == "IDP_UNAVAILABLE"
    assert r.json()["error"]["data"]["recoverable"] is True
    assert enforce_spy == []


async def test_an_unreachable_control_plane_fails_closed(oauth_stack) -> None:
    oauth_stack.router.pdp_down = True
    proxy = oauth_stack.proxy()
    r = await proxy.post("/mcp", json=_call(), headers=_bearer(oauth_stack.token()))
    assert r.status_code == 503
    assert r.json()["error"]["data"]["reason"] == "PDP_UNAVAILABLE"
    assert oauth_stack.mcp.calls == []


async def test_a_consent_refusal_is_a_json_rpc_refusal_with_its_reason(oauth_stack, flags) -> None:
    flags(consent_idp_audiences="https://somewhere-else.test")  # consent rejects the audience
    proxy = oauth_stack.proxy()
    r = await proxy.post("/mcp", json=_call(), headers=_bearer(oauth_stack.token()))

    error = r.json()["error"]
    assert error["code"] == -32003
    assert error["data"]["reason"] == "SUBJECT_TOKEN_INVALID"
    assert error["data"]["recoverable"] is False
    assert error["data"]["guarantee_level"] == "connector"
    assert oauth_stack.mcp.calls == []


# -- the client's token never goes upstream (INV-1) -----------------------------------------


async def test_no_path_forwards_any_part_of_the_clients_token(oauth_stack) -> None:
    proxy = oauth_stack.proxy()
    token = oauth_stack.token()
    rpc = {"jsonrpc": "2.0", "id": 1}

    await proxy.post("/mcp", json={**rpc, "method": "initialize"}, headers=_bearer(token))
    await proxy.post("/mcp", json={**rpc, "method": "tools/list"}, headers=_bearer(token))
    await proxy.post("/mcp", json=_call(), headers=_bearer(token))  # allow, cache miss
    await proxy.post("/mcp", json=_call(), headers=_bearer(token))  # allow, cache hit
    await proxy.post("/mcp", json=_call("terminate_account"), headers=_bearer(token))  # deny
    oauth_stack.router.upstream_down = True
    await proxy.post("/mcp", json=_call(), headers=_bearer(token))  # upstream error

    assert len(oauth_stack.mcp.calls) == 2
    assert_no_token_material(token, oauth_stack.mcp)


async def test_the_upstream_receives_an_agentic_auth_hop_token(oauth_stack) -> None:
    import jwt

    proxy = oauth_stack.proxy()
    await proxy.post("/mcp", json=_call(), headers=_bearer(oauth_stack.token()))
    sent = oauth_stack.mcp.authorizations[-1].removeprefix("Bearer ")
    claims = jwt.decode(sent, options={"verify_signature": False})
    assert claims["iss"] != ISSUER
    assert claims["aud"] == "mcp://kb.internal/search"


async def test_a_client_cannot_point_the_decision_at_another_session(oauth_stack) -> None:
    proxy = oauth_stack.proxy()
    headers = {**_bearer(oauth_stack.token()), "x-agentic-session": "00000000-0000-0000-0000-0"}
    r = await proxy.post("/mcp", json=_call(), headers=headers)
    assert r.json()["result"]


# -- M1 with verified consent off (spec edge case, research R10) ---------------------------


async def test_without_an_asserted_root_scope_a_m2_off_control_plane_refuses(
    oauth_stack, flags
) -> None:
    flags(verified_consent_enabled=False)
    proxy = oauth_stack.proxy()
    r = await proxy.post("/mcp", json=_call(), headers=_bearer(oauth_stack.token()))

    assert r.json()["error"]["data"]["reason"] == "VALIDATION_ERROR"
    assert oauth_stack.router.consent_calls == 1  # refused, never retried as asserted
    assert oauth_stack.mcp.calls == []


async def test_an_asserted_root_scope_roots_the_session_in_the_validated_subject(
    oauth_stack, flags, client, admin_headers
) -> None:
    flags(verified_consent_enabled=False)
    proxy = oauth_stack.proxy(consent_scope=None, asserted_root_scope=oauth_stack.scope)
    token = oauth_stack.token()

    r = await proxy.post("/mcp", json=_call(), headers=_bearer(token))
    assert r.json()["result"]

    rows = (await client.get("/v1/audit/decisions", headers=admin_headers)).json()["data"]
    chain = (
        await client.get(f"/v1/audit/actions/{rows[0]['id']}/chain", headers=admin_headers)
    ).json()
    assert chain["root_consent"]["user_sub"] == f"{ISSUER}#alice"
    assert chain["root_consent"]["principal_source"] == "asserted"
    assert_no_token_material(token, oauth_stack.mcp)


async def test_a_refusal_in_asserted_mode_says_the_root_is_asserted(oauth_stack, flags) -> None:
    flags(verified_consent_enabled=False)
    proxy = oauth_stack.proxy(consent_scope=None, asserted_root_scope=oauth_stack.scope)
    r = await proxy.post(
        "/mcp", json=_call("terminate_account"), headers=_bearer(oauth_stack.token())
    )
    assert r.json()["error"]["data"]["reason"]
    oauth_stack.router.pdp_down = True
    r = await proxy.post("/mcp", json=_call(), headers=_bearer(oauth_stack.token(sub="carol")))
    assert r.json()["error"]["data"]["root_of_authority"] == "asserted"


# -- with client mapping (M4): the token's client picks the agent ----------------------------


async def test_a_mapped_client_runs_as_its_agent_and_an_unmapped_one_is_cold_start(
    oauth_stack, flags, client, admin_headers
) -> None:
    flags(client_mapping_enabled=True)
    agents = (await client.get("/v1/agents?limit=100", headers=admin_headers)).json()["data"]
    orchestrator = next(a["id"] for a in agents if a["name"] == oauth_stack.scope)
    await client.post(
        f"/v1/agents/{orchestrator}/clients", headers=admin_headers, json={"client_id": "desk"}
    )
    proxy = oauth_stack.proxy(consent_scope=None)  # the mapping chooses

    allowed = await proxy.post("/mcp", json=_call(), headers=_bearer(oauth_stack.token(azp="desk")))
    assert allowed.json()["result"]

    refused = await proxy.post(
        "/mcp", json=_call(), headers=_bearer(oauth_stack.token(azp="stranger"))
    )
    data = refused.json()["error"]["data"]
    assert data["reason"] == "CLIENT_NOT_AUTHORIZED"
    assert data["recoverable"] is False
    assert data["next"] == "cold_start"
    assert data["client_id"] == "stranger"
    assert len(oauth_stack.mcp.calls) == 1  # only the mapped client's call was dispatched
