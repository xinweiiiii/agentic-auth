"""Verified consent: the root of authority is a human the IdP signed in (feature 011, US2).

With ``verified_consent_enabled``, consent takes the user's IdP token as ``subject_token``,
verifies it itself, and roots the session at ``iss#sub``. An asserted ``user_sub`` alone is
refused, and one that disagrees with the token is refused without being echoed.
"""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import func, select

from agentic_auth.models import AuditDecision, Session
from tests.fixtures.chains import ORCHESTRATOR
from tests.fixtures.idp.server import ISSUER

CONTROL_PLANE = "https://authz.test"
PROXY = "https://mcp-proxy.test"


@pytest.fixture
def verified(fake_idp, flags, metrics_registry):
    flags(verified_consent_enabled=True, consent_idp_audiences=f"{CONTROL_PLANE},{PROXY}")
    return fake_idp


@pytest.fixture
async def chain(register_chain):
    await register_chain()


async def _consent(client, headers, **body):
    return await client.post("/v1/consent", headers=headers, json={"scope": ORCHESTRATOR, **body})


async def _count(db_session, model) -> int:
    return (await db_session.execute(select(func.count()).select_from(model))).scalar_one()


def _refusals(metrics_registry, reason: str) -> float:
    return (
        metrics_registry.registry.get_sample_value(
            "agentic_auth_consent_refusals_total", {"reason": reason}
        )
        or 0.0
    )


# -- success ---------------------------------------------------------------------------


async def test_a_valid_idp_token_roots_the_session_at_the_verified_human(
    client, admin_headers, chain, verified, db_session
) -> None:
    token = verified.mint_access_token(aud=CONTROL_PLANE)
    r = await _consent(client, admin_headers, subject_token=token)

    assert r.status_code == 201, r.json()
    body = r.json()
    assert body["user_sub"] == f"{ISSUER}#alice"
    assert body["principal_source"] == "verified"
    assert "client_id" not in body  # mapping is M4; without it no client is recorded

    row = (await db_session.execute(select(Session))).scalar_one()
    assert row.principal_source == "verified"
    assert row.subject_token_hash == hashlib.sha256(token.encode()).hexdigest()
    for value in (row.user_sub, row.subject_token_hash, str(row.consented_data_classes)):
        assert token not in value


async def test_a_token_relayed_by_a_proxy_is_accepted_for_the_proxys_audience(
    client, admin_headers, chain, verified
) -> None:
    r = await _consent(client, admin_headers, subject_token=verified.mint_access_token(aud=PROXY))
    assert r.status_code == 201


async def test_a_matching_asserted_subject_is_allowed(
    client, admin_headers, chain, verified
) -> None:
    r = await _consent(
        client,
        admin_headers,
        subject_token=verified.mint_access_token(aud=CONTROL_PLANE),
        user_sub=f"{ISSUER}#alice",
    )
    assert r.status_code == 201


async def test_an_id_token_is_accepted_as_evidence(client, admin_headers, chain, verified) -> None:
    r = await _consent(
        client,
        admin_headers,
        subject_token=verified.mint_access_token(aud=CONTROL_PLANE),
        subject_token_type="urn:ietf:params:oauth:token-type:id_token",
    )
    assert r.status_code == 201


async def test_the_audit_chain_names_the_verified_human(
    client, admin_headers, chain, verified
) -> None:
    from tests.fixtures.chains import KB_SEARCH
    from tests.fixtures.hops import hop

    session = (
        await _consent(
            client, admin_headers, subject_token=verified.mint_access_token(aud=CONTROL_PLANE)
        )
    ).json()
    decision, _ = await hop(
        client, session["root_grant"], target=f"agent://{KB_SEARCH}", data_class="kb.internal"
    )
    chain_body = (
        await client.get(f"/v1/audit/actions/{decision['action_id']}/chain", headers=admin_headers)
    ).json()

    assert chain_body["root_consent"]["user_sub"] == f"{ISSUER}#alice"
    assert chain_body["root_consent"]["principal_source"] == "verified"


# -- refusals -------------------------------------------------------------------------


async def test_no_subject_token_is_refused_and_names_the_missing_evidence(
    client, admin_headers, chain, verified, db_session, metrics_registry
) -> None:
    r = await _consent(client, admin_headers, user_sub="user:alice")

    assert r.status_code == 422
    assert r.json()["error"]["code"] == "subject_token_required"
    assert "subject_token" in r.json()["error"]["message"]
    assert await _count(db_session, Session) == 0
    assert _refusals(metrics_registry, "subject_token_required") == 1


async def test_a_disagreeing_asserted_subject_is_refused_and_not_echoed(
    client, admin_headers, chain, verified, db_session
) -> None:
    r = await _consent(
        client,
        admin_headers,
        subject_token=verified.mint_access_token(aud=CONTROL_PLANE),
        user_sub="user:mallory-asserted",
    )

    assert r.status_code == 422
    assert r.json()["error"]["code"] == "subject_mismatch"
    assert "mallory-asserted" not in r.text
    assert await _count(db_session, Session) == 0


@pytest.mark.parametrize(
    ("mint", "check"),
    [
        ({"aud": "https://elsewhere.test"}, "audience"),
        ({"aud": CONTROL_PLANE, "expires_in": -600}, "expired"),
        ({"aud": CONTROL_PLANE, "issuer": "https://evil.test"}, "issuer"),
        ({"aud": CONTROL_PLANE, "alg": "HS256"}, "algorithm"),
        ({"aud": CONTROL_PLANE, "alg": "none"}, "algorithm"),
        ({"aud": CONTROL_PLANE, "kid": "unknown"}, "signature"),
    ],
)
async def test_an_invalid_token_is_refused_with_the_failed_check(
    client, admin_headers, chain, verified, db_session, metrics_registry, mint, check
) -> None:
    token = verified.mint_access_token(**mint)
    r = await _consent(client, admin_headers, subject_token=token)

    assert r.status_code == 401
    error = r.json()["error"]
    assert error["code"] == "subject_token_invalid"
    assert error["details"]["check"] == check
    assert token not in r.text
    assert await _count(db_session, Session) == 0
    assert await _count(db_session, AuditDecision) == 0
    assert _refusals(metrics_registry, "subject_token_invalid") == 1


async def test_garbage_is_a_malformed_token(client, admin_headers, chain, verified) -> None:
    r = await _consent(client, admin_headers, subject_token="not-a-jwt")
    assert r.status_code == 401
    assert r.json()["error"]["details"]["check"] == "malformed"


async def test_an_unreachable_idp_is_retryable_and_never_an_allow(
    client, admin_headers, chain, verified, db_session
) -> None:
    verified.down = True
    r = await _consent(
        client, admin_headers, subject_token=verified.mint_access_token(aud=CONTROL_PLANE)
    )

    assert r.status_code == 503
    assert r.json()["error"]["code"] == "idp_unavailable"
    assert r.json()["error"]["details"]["retryable"] is True
    assert await _count(db_session, Session) == 0


async def test_an_unknown_subject_token_type_is_a_validation_error(
    client, admin_headers, chain, verified
) -> None:
    r = await _consent(
        client,
        admin_headers,
        subject_token=verified.mint_access_token(aud=CONTROL_PLANE),
        subject_token_type="urn:ietf:params:oauth:token-type:saml2",
    )
    assert r.status_code == 422


# -- flag off ---------------------------------------------------------------------------


async def test_with_the_flag_off_a_subject_token_is_refused_not_ignored(
    client, admin_headers, chain, fake_idp, flags
) -> None:
    flags(verified_consent_enabled=False)
    r = await _consent(
        client,
        admin_headers,
        user_sub="user:alice",
        subject_token=fake_idp.mint_access_token(aud=CONTROL_PLANE),
    )
    assert r.status_code == 422
    assert "verified consent is not enabled" in r.json()["error"]["message"]


async def test_with_the_flag_off_an_asserted_subject_is_recorded_as_asserted(
    client, admin_headers, chain, flags, db_session
) -> None:
    flags(verified_consent_enabled=False)
    r = await _consent(client, admin_headers, user_sub="user:alice")

    assert r.status_code == 201
    # The 0.3.0 response shape: no new keys a deployed SDK would choke on.
    assert "principal_source" not in r.json() and "client_id" not in r.json()
    assert (await db_session.execute(select(Session))).scalar_one().principal_source == "asserted"


# -- who may call consent ------------------------------------------------------------------


async def test_the_consent_token_may_consent(client, chain, verified, flags) -> None:
    flags(consent_token="proxy-consent-secret")
    r = await _consent(
        client,
        {"Authorization": "Bearer proxy-consent-secret"},
        subject_token=verified.mint_access_token(aud=PROXY),
    )
    assert r.status_code == 201


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/v1/agents"),
        ("POST", "/v1/manifests"),
        ("GET", "/v1/audit/decisions"),
        ("GET", "/v1/agents"),
    ],
)
async def test_the_consent_token_may_do_nothing_else(client, flags, method, path) -> None:
    flags(consent_token="proxy-consent-secret")
    r = await client.request(
        method, path, headers={"Authorization": "Bearer proxy-consent-secret"}, json={}
    )
    assert r.status_code == 401


async def test_an_empty_consent_token_setting_never_accepts_an_empty_bearer(
    client, chain, flags
) -> None:
    flags(consent_token="")
    r = await _consent(client, {"Authorization": "Bearer "}, user_sub="user:alice")
    assert r.status_code == 401
