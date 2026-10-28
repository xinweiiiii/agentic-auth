"""Enrollment end to end (US4, T049; quickstart §5)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from tests.fixtures.identity import agent_keypair, identity_document, sign_challenge
from tests.fixtures.manifests import base_manifest

ENROLL_TOKEN = "test-enroll-token"
AGENT = "kb-search-agent"


@pytest.fixture
def enroll_headers(flags):
    flags(enroll_token=ENROLL_TOKEN)
    return {"Authorization": f"Bearer {ENROLL_TOKEN}"}


@pytest.fixture
async def registered(client, admin_headers):
    r = await client.post(
        "/v1/agents", headers=admin_headers, json={"name": AGENT, "manifest": base_manifest(AGENT)}
    )
    assert r.status_code == 201, r.text
    return r.json()["agent_id"]


async def begin(client, headers, agent_id, doc):
    return await client.post(
        f"/v1/agents/{agent_id}/enroll", headers=headers, json={"identity_doc": doc}
    )


async def complete(client, headers, agent_id, challenge_id, signed):
    return await client.post(
        f"/v1/agents/{agent_id}/enroll/complete",
        headers=headers,
        json={"challenge_id": challenge_id, "signed_response": signed},
    )


async def enroll(client, headers, agent_id, key, assertion, **kwargs):
    doc = identity_document(key, principal_assertion=assertion, **kwargs)
    challenge = (await begin(client, headers, agent_id, doc)).json()
    signed = sign_challenge(key, challenge["nonce"])
    return await complete(client, headers, agent_id, challenge["challenge_id"], signed)


# -- outcomes -------------------------------------------------------------------------


async def test_good_signature_and_bindable_principal_enrolls(
    client, enroll_headers, admin_headers, registered, fake_idp, principal_assertion_for
) -> None:
    key = agent_keypair(AGENT)
    r = await enroll(client, enroll_headers, registered, key, principal_assertion_for(AGENT))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {
        "status": "enrolled",
        "trust_anchor_version": 1,
        "principal_ref": fake_idp.principal_ref(),
        "reason": None,
        "detail": None,
    }

    identity = (await client.get(f"/v1/agents/{registered}/identity", headers=admin_headers)).json()
    assert identity["status"] == "enrolled"
    assert identity["trust_anchor_version"] == 1
    assert identity["jwks"]["keys"][0]["kid"] == key.kid
    assert identity["principal_ref"] == fake_idp.principal_ref()
    assert identity["manifest_version"] == 1
    assert identity["revoked"] is False

    listing = (await client.get("/v1/agents?status=enrolled", headers=admin_headers)).json()
    assert [a["name"] for a in listing["data"]] == [AGENT]


async def test_unbindable_principal_quarantines(
    client, enroll_headers, admin_headers, registered, fake_idp, principal_assertion_for
) -> None:
    key = agent_keypair(AGENT)
    # names another agent
    r = await enroll(
        client, enroll_headers, registered, key, principal_assertion_for("other-agent")
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "quarantined"
    assert r.json()["reason"] == "PRINCIPAL_UNBINDABLE"
    assert "other-agent" in r.json()["detail"]

    identity = (await client.get(f"/v1/agents/{registered}/identity", headers=admin_headers)).json()
    assert identity["status"] == "quarantined"
    assert identity["jwks"] is None and identity["trust_anchor_version"] is None

    # inspectable: the presented document is kept, public keys only
    row = (await client.get("/v1/agents?status=quarantined", headers=admin_headers)).json()["data"]
    assert [a["name"] for a in row] == [AGENT]


async def test_no_assertion_quarantines(client, enroll_headers, registered, fake_idp) -> None:
    r = await enroll(client, enroll_headers, registered, agent_keypair(AGENT), None)
    assert r.status_code == 200 and r.json()["status"] == "quarantined"


async def test_no_idp_configured_quarantines_with_its_own_reason(
    client, enroll_headers, registered
) -> None:
    r = await enroll(client, enroll_headers, registered, agent_keypair(AGENT), None)
    assert r.status_code == 200
    assert r.json()["reason"] == "PRINCIPAL_IDP_NOT_CONFIGURED"


async def test_bad_signature_rejects_and_changes_nothing(
    client, enroll_headers, admin_headers, registered, fake_idp, principal_assertion_for
) -> None:
    key = agent_keypair(AGENT)
    doc = identity_document(key, principal_assertion=principal_assertion_for(AGENT))
    challenge = (await begin(client, enroll_headers, registered, doc)).json()
    signed = sign_challenge(key, challenge["nonce"], bad=True)  # wrong key, same kid
    r = await complete(client, enroll_headers, registered, challenge["challenge_id"], signed)
    assert r.status_code == 401
    identity = (await client.get(f"/v1/agents/{registered}/identity", headers=admin_headers)).json()
    assert identity["status"] == "registered"


async def test_wrong_nonce_or_wrong_audience_rejects(
    client, enroll_headers, registered, fake_idp, principal_assertion_for
) -> None:
    key = agent_keypair(AGENT)
    doc = identity_document(key, principal_assertion=principal_assertion_for(AGENT))
    challenge = (await begin(client, enroll_headers, registered, doc)).json()
    r = await complete(
        client,
        enroll_headers,
        registered,
        challenge["challenge_id"],
        sign_challenge(key, "not-the-nonce"),
    )
    assert r.status_code == 401
    challenge = (await begin(client, enroll_headers, registered, doc)).json()
    r = await complete(
        client,
        enroll_headers,
        registered,
        challenge["challenge_id"],
        sign_challenge(key, challenge["nonce"], aud="someone-else"),
    )
    assert r.status_code == 401


async def test_a_key_not_in_the_document_proves_nothing(
    client, enroll_headers, registered, fake_idp, principal_assertion_for
) -> None:
    presented = agent_keypair(AGENT)
    other = agent_keypair(AGENT, kid="rogue")
    doc = identity_document(presented, principal_assertion=principal_assertion_for(AGENT))
    challenge = (await begin(client, enroll_headers, registered, doc)).json()
    r = await complete(
        client,
        enroll_headers,
        registered,
        challenge["challenge_id"],
        sign_challenge(other, challenge["nonce"]),
    )
    assert r.status_code == 401


async def test_idp_down_is_retryable_and_changes_nothing(
    client, enroll_headers, admin_headers, registered, fake_idp, principal_assertion_for
) -> None:
    assertion = principal_assertion_for(AGENT)
    fake_idp.down = True
    r = await enroll(client, enroll_headers, registered, agent_keypair(AGENT), assertion)
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "idp_unavailable"
    identity = (await client.get(f"/v1/agents/{registered}/identity", headers=admin_headers)).json()
    assert identity["status"] == "registered"
    fake_idp.down = False
    r = await enroll(client, enroll_headers, registered, agent_keypair(AGENT), assertion)
    assert r.status_code == 200 and r.json()["status"] == "enrolled"


async def test_unreconciled_manifest_rejects_with_the_diff(
    client, enroll_headers, admin_headers, fake_idp, principal_assertion_for
) -> None:
    from tests.fixtures.manifests import overbroad_manifest

    r = await client.post(
        "/v1/agents",
        headers=admin_headers,
        json={"name": "wide-agent", "manifest": overbroad_manifest("wide-agent")},
    )
    assert r.status_code in (409, 422), r.text
    agent_id = r.json().get("agent_id")
    if agent_id is None:
        listing = (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
        agent_id = next(a["id"] for a in listing if a["name"] == "wide-agent")
    r = await enroll(
        client,
        enroll_headers,
        agent_id,
        agent_keypair("wide-agent"),
        principal_assertion_for("wide-agent"),
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "reconciliation_rejected"
    assert isinstance(r.json()["error"]["details"]["diff"], list)


# -- challenge lifecycle ------------------------------------------------------------------


async def test_a_challenge_is_single_use(
    client, enroll_headers, registered, fake_idp, principal_assertion_for
) -> None:
    key = agent_keypair(AGENT)
    doc = identity_document(key, principal_assertion=principal_assertion_for(AGENT))
    challenge = (await begin(client, enroll_headers, registered, doc)).json()
    signed = sign_challenge(key, challenge["nonce"])
    first = await complete(client, enroll_headers, registered, challenge["challenge_id"], signed)
    second = await complete(client, enroll_headers, registered, challenge["challenge_id"], signed)
    assert first.status_code == 200 and second.status_code == 401


async def test_an_expired_challenge_is_refused(
    client, enroll_headers, registered, fake_idp, principal_assertion_for, redis_client
) -> None:
    from app.services.enrollment import challenge_key

    key = agent_keypair(AGENT)
    doc = identity_document(key, principal_assertion=principal_assertion_for(AGENT))
    challenge = (await begin(client, enroll_headers, registered, doc)).json()
    await redis_client.delete(challenge_key(challenge["challenge_id"]))  # simulates expiry
    r = await complete(
        client,
        enroll_headers,
        registered,
        challenge["challenge_id"],
        sign_challenge(key, challenge["nonce"]),
    )
    assert r.status_code == 401


async def test_an_unknown_challenge_is_refused(client, enroll_headers, registered) -> None:
    r = await complete(client, enroll_headers, registered, str(uuid.uuid4()), "x.y.z")
    assert r.status_code == 401


# -- re-enrollment ------------------------------------------------------------------------


async def test_quarantined_then_bindable_enrolls(
    client, enroll_headers, registered, fake_idp, principal_assertion_for
) -> None:
    key = agent_keypair(AGENT)
    assert (await enroll(client, enroll_headers, registered, key, None)).json()[
        "status"
    ] == "quarantined"
    r = await enroll(client, enroll_headers, registered, key, principal_assertion_for(AGENT))
    assert r.status_code == 200 and r.json()["status"] == "enrolled"
    assert r.json()["trust_anchor_version"] == 1


async def test_key_rotation_pins_a_new_version_and_supersedes_the_old(
    client, enroll_headers, admin_headers, registered, fake_idp, principal_assertion_for, db_session
) -> None:
    k1 = agent_keypair(AGENT, kid="k1")
    k2 = agent_keypair(AGENT, kid="k2")
    assert (
        await enroll(client, enroll_headers, registered, k1, principal_assertion_for(AGENT))
    ).json()["trust_anchor_version"] == 1
    r = await enroll(client, enroll_headers, registered, k2, principal_assertion_for(AGENT))
    assert r.json()["trust_anchor_version"] == 2
    rows = (
        await db_session.execute(
            text(
                "SELECT version, revoked_at IS NOT NULL AS revoked "
                "FROM trust_anchors ORDER BY version"
            )
        )
    ).all()
    assert [(row.version, row.revoked) for row in rows] == [(1, True), (2, False)]
    identity = (await client.get(f"/v1/agents/{registered}/identity", headers=admin_headers)).json()
    assert identity["jwks"]["keys"][0]["kid"] == "k2" and identity["trust_anchor_version"] == 2


# -- validation and access ---------------------------------------------------------------


async def test_enroll_requires_the_enroller_or_admin_bearer(
    client, enroll_headers, admin_headers, registered
) -> None:
    doc = identity_document(agent_keypair(AGENT))
    assert (
        await client.post(f"/v1/agents/{registered}/enroll", json={"identity_doc": doc})
    ).status_code == 401
    assert (
        await client.post(
            f"/v1/agents/{registered}/enroll",
            headers={"Authorization": "Bearer wrong"},
            json={"identity_doc": doc},
        )
    ).status_code == 401
    assert (await begin(client, admin_headers, registered, doc)).status_code == 201
    assert (await begin(client, enroll_headers, registered, doc)).status_code == 201


async def test_unknown_agent_is_404(client, enroll_headers) -> None:
    doc = identity_document(agent_keypair(AGENT))
    assert (await begin(client, enroll_headers, str(uuid.uuid4()), doc)).status_code == 404


async def test_document_naming_another_agent_is_422(client, enroll_headers, registered) -> None:
    doc = identity_document(agent_keypair("someone-else"))
    r = await begin(client, enroll_headers, registered, doc)
    assert r.status_code == 422


async def test_non_ed25519_and_private_keys_are_rejected(
    client, enroll_headers, registered
) -> None:
    doc = identity_document(agent_keypair(AGENT))
    doc["jwks"]["keys"][0]["kty"] = "RSA"
    assert (await begin(client, enroll_headers, registered, doc)).status_code == 422
    doc = identity_document(agent_keypair(AGENT))
    doc["jwks"]["keys"][0]["d"] = "c2VjcmV0"
    assert (await begin(client, enroll_headers, registered, doc)).status_code == 422


async def test_identity_read_requires_a_reader_and_404s_unknown(
    client, admin_headers, registered
) -> None:
    assert (await client.get(f"/v1/agents/{registered}/identity")).status_code == 401
    assert (
        await client.get(f"/v1/agents/{uuid.uuid4()}/identity", headers=admin_headers)
    ).status_code == 404
    identity = (await client.get(f"/v1/agents/{registered}/identity", headers=admin_headers)).json()
    assert identity["status"] == "registered" and identity["jwks"] is None


async def test_no_nonce_or_assertion_lands_in_any_table(
    client, enroll_headers, registered, fake_idp, principal_assertion_for, db_session
) -> None:
    key = agent_keypair(AGENT)
    assertion = principal_assertion_for(AGENT)
    doc = identity_document(key, principal_assertion=assertion)
    challenge = (await begin(client, enroll_headers, registered, doc)).json()
    await complete(
        client,
        enroll_headers,
        registered,
        challenge["challenge_id"],
        sign_challenge(key, challenge["nonce"]),
    )
    for table in ("agents", "trust_anchors", "audit_decisions"):
        dump = str(
            (await db_session.execute(text(f"SELECT to_jsonb(t) FROM {table} t"))).scalars().all()
        )
        assert challenge["nonce"] not in dump and assertion not in dump, table


# -- by-name identity read, for verifiers that hold only a reader token ------------------------


async def test_a_reader_token_can_read_identity_by_name_but_cannot_list_agents(
    client, enroll_headers, admin_headers, registered, fake_idp, principal_assertion_for, flags
) -> None:
    flags(audit_read_token="reader")
    reader = {"Authorization": "Bearer reader"}
    key = agent_keypair(AGENT)
    await enroll(client, enroll_headers, registered, key, principal_assertion_for(AGENT))

    by_name = await client.get(f"/v1/identity/agents/{AGENT}", headers=reader)
    assert by_name.status_code == 200
    by_id = (await client.get(f"/v1/agents/{registered}/identity", headers=admin_headers)).json()
    assert {k: v for k, v in by_name.json().items() if k != "as_of"} == {
        k: v for k, v in by_id.items() if k != "as_of"
    }

    assert (await client.get("/v1/agents", headers=reader)).status_code == 401  # admin-only
    assert (await client.get("/v1/identity/agents/ghost", headers=reader)).status_code == 404
    assert (await client.get(f"/v1/identity/agents/{AGENT}")).status_code == 401
