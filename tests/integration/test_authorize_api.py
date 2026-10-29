"""The authorize endpoint end to end."""

from __future__ import annotations

import base64
import json

import pytest
from sqlalchemy import text

from tests.fixtures.chains import KB_SEARCH, SUMMARIZER

KB_TOOL = "mcp://kb.internal/search"
USER = "user:alice"


def _claims(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _authorize(client, token, **body):
    # Phase 5: `guarantee` is mandatory on the request with no default. These
    # tests stand in for an in-path enforcement point, which is `full`; a test that cares
    # passes its own.
    body.setdefault("guarantee", "full")
    return await client.post("/v1/authorize", headers=_bearer(token), json=body)


@pytest.fixture
async def rooted(register_chain, consent):
    await register_chain()
    return await consent()


async def test_allowed_hop_returns_a_decision(client, rooted) -> None:
    r = await _authorize(
        client,
        rooted["root_grant"],
        session_id=rooted["session_id"],
        caller=USER,
        target=f"agent://{KB_SEARCH}",
        data_class="kb.internal",
    )
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "allow"
    assert body["hop"] == 1
    assert body["reason"] is None
    assert body["policy_version"] == rooted["policy_version"]


async def test_deny_is_a_two_hundred_with_a_reason_not_an_error(client, rooted) -> None:
    """A deny is a successful decision. Conflating it with an outage would make
    'the PDP said no' indistinguishable from 'the PDP is down'."""
    r = await _authorize(
        client,
        rooted["root_grant"],
        session_id=rooted["session_id"],
        caller=USER,
        target=f"agent://{SUMMARIZER}",  # skips kb-search
        data_class="account.read",
    )
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "deny"
    assert body["reason"] == "EDGE_NOT_IN_DAG"
    assert body["recoverable"] is False
    assert body["target"] == f"agent://{SUMMARIZER}"


async def test_scope_not_consented_is_flagged_recoverable(client, rooted) -> None:
    """Default regime: no consented subset was pinned, so an undeclared class keeps its
    Phase 2 reason. See tests/unit/test_pdp_consent_subset.py for the split."""
    r = await _authorize(
        client,
        rooted["root_grant"],
        session_id=rooted["session_id"],
        caller=USER,
        target=f"agent://{KB_SEARCH}",
        data_class="account.write",
    )
    body = r.json()
    assert body["reason"] == "SCOPE_NOT_CONSENTED"
    assert body["recoverable"] is True


async def test_out_of_scope_tool_is_denied(client, rooted) -> None:
    r = await _authorize(
        client,
        rooted["root_grant"],
        session_id=rooted["session_id"],
        caller=USER,
        target="mcp://ledger.internal/read_ledger",
        data_class="ledger.read",
    )
    assert r.json()["reason"] == "OUT_OF_SCOPE"


async def test_caller_not_matching_the_token_is_denied(client, rooted) -> None:
    r = await _authorize(
        client,
        rooted["root_grant"],
        session_id=rooted["session_id"],
        caller=f"agent://{SUMMARIZER}",  # not who the root grant was issued to
        target=f"agent://{KB_SEARCH}",
        data_class="kb.internal",
    )
    body = r.json()
    assert body["outcome"] == "deny"
    assert body["reason"] == "OUT_OF_SCOPE"


# -- token and session rejections (401, not a decision) ----------------------


async def test_missing_token_is_unauthorized(client, rooted) -> None:
    r = await client.post(
        "/v1/authorize",
        json={
            "session_id": rooted["session_id"],
            "caller": USER,
            "target": f"agent://{KB_SEARCH}",
            "data_class": "kb.internal",
            "guarantee": "full",
        },
    )
    assert r.status_code == 401


async def test_tampered_token_is_unauthorized(client, rooted) -> None:
    from tests.fixtures.tokens import tampered

    bad = tampered(rooted["root_grant"], hop=9)
    r = await _authorize(
        client,
        bad,
        session_id=rooted["session_id"],
        caller=USER,
        target=f"agent://{KB_SEARCH}",
        data_class="kb.internal",
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


async def test_expired_session_is_unauthorized(client, rooted, db_session, redis_client) -> None:
    # Backdate the whole row: ck_sessions_expiry_after_creation refuses an expiry
    # before creation, which is the constraint doing its job.
    await db_session.execute(
        text(
            "UPDATE sessions SET created_at = now() - interval '2 hours', "
            "expires_at = now() - interval '1 hour' WHERE id = :i"
        ),
        {"i": rooted["session_id"]},
    )
    await db_session.commit()
    await redis_client.delete(f"session:{rooted['session_id']}")

    r = await _authorize(
        client,
        rooted["root_grant"],
        session_id=rooted["session_id"],
        caller=USER,
        target=f"agent://{KB_SEARCH}",
        data_class="kb.internal",
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "session_expired"


async def test_unknown_session_is_not_found(client, rooted) -> None:
    r = await _authorize(
        client,
        rooted["root_grant"],
        session_id="00000000-0000-0000-0000-000000000000",
        caller=USER,
        target=f"agent://{KB_SEARCH}",
        data_class="kb.internal",
    )
    assert r.status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {"caller": USER, "target": "agent://kb-search", "data_class": "kb.internal"},
        {"session_id": "s", "target": "agent://kb-search", "data_class": "kb.internal"},
        {"session_id": "s", "caller": USER, "data_class": "kb.internal"},
        {"session_id": "s", "caller": USER, "target": "t", "data_class": "d", "hop_count": 1},
        {"session_id": "s", "caller": USER, "target": "t", "data_class": "d", "taint": "bogus"},
    ],
)
async def test_malformed_body_is_rejected(client, rooted, body) -> None:
    r = await _authorize(client, rooted["root_grant"], **body)
    assert r.status_code == 422


async def test_a_client_supplied_hop_count_is_not_accepted(client, rooted) -> None:
    """Depth under-reporting, structurally: there is no field to lie in."""
    r = await _authorize(
        client,
        rooted["root_grant"],
        session_id=rooted["session_id"],
        caller=USER,
        target=f"agent://{KB_SEARCH}",
        data_class="kb.internal",
        hop_count=1,
    )
    assert r.status_code == 422
    fields = r.json()["error"]["details"]["fields"]
    assert any("hop_count" in f["loc"] for f in fields)


# -- every decision is recorded ----------------------------------------------


async def _decision_rows(db_session, session_id):
    rows = await db_session.execute(
        text(
            "SELECT outcome, deny_reason, hop, enforced, taint, act_chain "
            "FROM audit_decisions WHERE session_id = :i ORDER BY ts"
        ),
        {"i": session_id},
    )
    return rows.mappings().all()


async def test_an_allow_is_recorded(client, rooted, db_session) -> None:
    await _authorize(
        client,
        rooted["root_grant"],
        session_id=rooted["session_id"],
        caller=USER,
        target=KB_TOOL,
        data_class="kb.public",
        taint="untrusted_external",
    )
    rows = await _decision_rows(db_session, rooted["session_id"])
    assert len(rows) == 1
    assert rows[0]["outcome"] == "allow"
    assert rows[0]["deny_reason"] is None
    assert rows[0]["enforced"] is True
    assert rows[0]["taint"] == "untrusted_external"
    assert rows[0]["act_chain"] == [USER]


async def test_a_deny_is_recorded_with_its_reason(client, rooted, db_session) -> None:
    await _authorize(
        client,
        rooted["root_grant"],
        session_id=rooted["session_id"],
        caller=USER,
        target=f"agent://{SUMMARIZER}",
        data_class="account.read",
    )
    rows = await _decision_rows(db_session, rooted["session_id"])
    assert rows[0]["outcome"] == "deny"
    assert rows[0]["deny_reason"] == "EDGE_NOT_IN_DAG"


async def test_repeated_denials_are_recorded_individually(client, rooted, db_session) -> None:
    """The report must reflect real frequency, not a single sample."""
    for _ in range(3):
        await _authorize(
            client,
            rooted["root_grant"],
            session_id=rooted["session_id"],
            caller=USER,
            target=f"agent://{SUMMARIZER}",
            data_class="account.read",
        )
    rows = await _decision_rows(db_session, rooted["session_id"])
    assert len(rows) == 3
