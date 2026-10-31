"""A human consents, and that consent pins a policy version."""

from __future__ import annotations

import base64
import json

import pytest

from tests.fixtures.chains import ORCHESTRATOR, chain_docs


def _claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=="))


async def test_consent_creates_a_session_and_returns_the_root_grant(
    client, admin_headers, register_chain
) -> None:
    await register_chain()

    r = await client.post(
        "/v1/consent",
        headers=admin_headers,
        json={"scope": ORCHESTRATOR, "user_sub": "user:alice"},
    )

    assert r.status_code == 201
    body = r.json()
    assert body["scope"] == ORCHESTRATOR
    assert body["user_sub"] == "user:alice"
    assert body["hop_budget"] == 4
    assert body["policy_version"] >= 1
    assert body["session_id"]
    assert body["expires_at"]


async def test_root_grant_is_a_hop_one_token_with_no_act_chain(
    client, admin_headers, register_chain, consent
) -> None:
    await register_chain()
    body = await consent()

    claims = _claims(body["root_grant"])
    assert claims["sub"] == "user:alice"
    assert claims["hop"] == 1
    assert "act" not in claims  # the root of the chain delegates to nobody yet
    assert claims["aud"] == ORCHESTRATOR  # a scope, not a concrete target
    assert claims["session_id"] == body["session_id"]
    assert claims["policy_version"] == body["policy_version"]


async def test_unknown_scope_is_not_found(client, admin_headers) -> None:
    r = await client.post(
        "/v1/consent", headers=admin_headers, json={"scope": "nope", "user_sub": "user:alice"}
    )
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"


async def test_policy_published_after_consent_does_not_move_the_pin(
    client, admin_headers, register_chain, consent
) -> None:
    """A session in flight keeps deciding against the version it pinned."""
    await register_chain()
    body = await consent()
    pinned = body["policy_version"]

    # Publish a new policy version for the same scope.
    r = await client.post(
        "/v1/manifests",
        headers=admin_headers,
        json={"agent": ORCHESTRATOR, "manifest": chain_docs()[ORCHESTRATOR]},
    )
    assert r.status_code == 201

    fresh = await consent()
    assert fresh["policy_version"] > pinned  # the new consent sees the new version
    assert _claims(body["root_grant"])["policy_version"] == pinned  # the old one did not move


async def test_missing_admin_token_is_unauthorized(client, register_chain) -> None:
    await register_chain()
    r = await client.post("/v1/consent", json={"scope": ORCHESTRATOR, "user_sub": "user:alice"})
    assert r.status_code == 401


async def test_bad_admin_token_is_unauthorized(client, register_chain) -> None:
    await register_chain()
    r = await client.post(
        "/v1/consent",
        headers={"Authorization": "Bearer wrong"},
        json={"scope": ORCHESTRATOR, "user_sub": "user:alice"},
    )
    assert r.status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {"user_sub": "user:alice"},  # missing scope
        {"scope": "orchestrator"},  # missing user_sub
        {"scope": "orchestrator", "user_sub": ""},  # empty user_sub
        {"scope": "orchestrator", "user_sub": "u", "surprise": 1},  # unknown field
        {"scope": "orchestrator", "user_sub": "u", "ttl_seconds": 5},  # below the floor
        {"scope": "orchestrator", "user_sub": "u", "ttl_seconds": 999_999},  # above the ceiling
    ],
)
async def test_malformed_body_is_rejected(client, admin_headers, body) -> None:
    r = await client.post("/v1/consent", headers=admin_headers, json=body)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "validation_error"


async def test_ttl_override_is_honoured(client, admin_headers, register_chain, consent) -> None:
    await register_chain()
    short = await consent(ttl_seconds=60)
    default = await consent()
    assert short["expires_at"] < default["expires_at"]


async def test_consent_is_recorded_per_call_not_deduplicated(
    client, admin_headers, register_chain, consent
) -> None:
    """Two approvals are two sessions — consent is an event, not a lookup."""
    await register_chain()
    a = await consent()
    b = await consent()
    assert a["session_id"] != b["session_id"]
    assert a["policy_version"] == b["policy_version"]


async def test_policy_compiled_before_this_phase_is_refused_not_guessed_at(
    client, admin_headers, db_session, register_chain
) -> None:
    """A v1 policy has no per-agent structure, so the PDP could not decide against it.

    Consent must say so and name the remedy, rather than pinning something unenforceable.
    """
    from agentic_auth.repositories import compiled_policies as policies_repo
    from tests.fixtures.chains import compiled_dag

    await register_chain()

    v1_dag = {
        k: v for k, v in compiled_dag().items() if k not in ("dag_schema_version", "nodes", "edges")
    }
    await policies_repo.append_version(
        db_session, scope="legacy-scope", dag=v1_dag, source_manifest_ids=[]
    )
    await db_session.commit()

    r = await client.post(
        "/v1/consent",
        headers=admin_headers,
        json={"scope": "legacy-scope", "user_sub": "user:alice"},
    )

    assert r.status_code == 409
    error = r.json()["error"]
    assert error["code"] == "policy_recompile_required"
    assert error["details"]["scope"] == "legacy-scope"
    assert error["details"]["dag_schema_version"] == 1
    assert error["details"]["required"] == 2
    assert "resubmit" in error["details"]["remedy"]
