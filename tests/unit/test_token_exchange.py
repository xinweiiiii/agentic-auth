"""Downscoping, single-hop binding and replay — and, from Phase 3, binding every
exchange to the recorded allow decision it spends.

Exercised through the HTTP endpoint because that is where the RFC 8693 grammar lives,
but each test pins one property of the *issued token*, not of the transport.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from agentic_auth.api.v1.token import ACTION_ID_INVALID, ACTION_ID_REQUIRED
from agentic_auth.schemas.token import GRANT_TYPE, JWT_TOKEN_TYPE
from tests.fixtures.chains import KB_SEARCH, NOTIFIER, ORCHESTRATOR, SUMMARIZER
from tests.fixtures.hops import authorize, claims, exchange

USER = "user:alice"
KB_TOOL = "mcp://kb.internal/search"


async def allowed_exchange(client, subject: str, *, resource: str, scope: str, **extra):
    """Decide, then exchange against that recorded decision — the only way a token is issued."""
    decision = (await authorize(client, subject, target=resource, data_class=scope)).json()
    return await exchange(
        client, subject, resource=resource, scope=scope, action_id=decision["action_id"], **extra
    )


@pytest.fixture
async def rooted(register_chain, consent):
    await register_chain()
    return await consent()


# -- downscoping -------------------------------------------------------------


async def test_issued_token_names_exactly_one_target_and_one_data_class(client, rooted) -> None:
    r = await allowed_exchange(
        client, rooted["root_grant"], resource=f"agent://{KB_SEARCH}", scope="kb.internal"
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert body["issued_token_type"] == JWT_TOKEN_TYPE
    assert body["scope"] == "kb.internal"

    c = claims(body["access_token"])
    assert c["aud"] == f"agent://{KB_SEARCH}"
    assert c["resource"] == f"agent://{KB_SEARCH}"
    assert c["scope"] == "kb.internal"  # not the session's whole consented scope


async def test_the_human_never_changes(client, rooted) -> None:
    r = await allowed_exchange(
        client, rooted["root_grant"], resource=f"agent://{KB_SEARCH}", scope="kb.internal"
    )
    assert claims(r.json()["access_token"])["sub"] == USER


async def test_the_delegating_agent_is_nested_outermost(client, rooted) -> None:
    r = await allowed_exchange(
        client, rooted["root_grant"], resource=f"agent://{KB_SEARCH}", scope="kb.internal"
    )
    c = claims(r.json()["access_token"])
    assert c["act"] == {"sub": f"agent://{ORCHESTRATOR}"}
    assert c["hop"] == 2


async def test_act_nests_correctly_for_a_three_deep_chain(client, rooted) -> None:
    t1 = (
        await allowed_exchange(
            client, rooted["root_grant"], resource=f"agent://{KB_SEARCH}", scope="kb.internal"
        )
    ).json()["access_token"]
    t2 = (
        await allowed_exchange(client, t1, resource=f"agent://{SUMMARIZER}", scope="account.read")
    ).json()["access_token"]
    t3 = (
        await allowed_exchange(client, t2, resource=f"agent://{NOTIFIER}", scope="account.write")
    ).json()["access_token"]

    c = claims(t3)
    assert c["hop"] == 4
    assert c["act"] == {
        "sub": f"agent://{SUMMARIZER}",
        "act": {"sub": f"agent://{KB_SEARCH}", "act": {"sub": f"agent://{ORCHESTRATOR}"}},
    }
    assert c["sub"] == USER  # still the human, four hops down


async def test_each_hop_gets_a_distinct_token(client, rooted) -> None:
    t1 = (
        await allowed_exchange(
            client, rooted["root_grant"], resource=f"agent://{KB_SEARCH}", scope="kb.internal"
        )
    ).json()["access_token"]
    t2 = (
        await allowed_exchange(client, t1, resource=f"agent://{SUMMARIZER}", scope="account.read")
    ).json()["access_token"]
    assert len({rooted["root_grant"], t1, t2}) == 3
    assert claims(t1)["jti"] != claims(t2)["jti"]


async def test_a_tool_call_token_is_scoped_to_the_tool(client, rooted) -> None:
    r = await allowed_exchange(client, rooted["root_grant"], resource=KB_TOOL, scope="kb.public")
    c = claims(r.json()["access_token"])
    assert c["aud"] == KB_TOOL
    assert c["scope"] == "kb.public"


# -- single-hop binding ------------------------------------------------------


async def test_a_token_minted_for_a_tool_call_cannot_be_exchanged_again(client, rooted) -> None:
    """It is meant for a resource server. Exchanging it would extend the chain past its end."""
    tool_token = (
        await allowed_exchange(client, rooted["root_grant"], resource=KB_TOOL, scope="kb.public")
    ).json()["access_token"]

    r = await allowed_exchange(
        client, tool_token, resource=f"agent://{SUMMARIZER}", scope="account.read"
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"
    assert "cannot be exchanged" in r.json()["error_description"]


async def test_a_subject_token_can_only_be_spent_once(client, rooted) -> None:
    """Per recorded decision: the same allow cannot be exchanged
    twice. Exchanging the same token for a SECOND decision is fine — see the next test."""
    decision = (
        await authorize(
            client, rooted["root_grant"], target=f"agent://{KB_SEARCH}", data_class="kb.internal"
        )
    ).json()
    first = await exchange(
        client,
        rooted["root_grant"],
        resource=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        action_id=decision["action_id"],
    )
    assert first.status_code == 200

    second = await exchange(
        client,
        rooted["root_grant"],
        resource=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        action_id=decision["action_id"],
    )
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"
    assert "already been exchanged" in second.json()["error_description"]


async def test_one_subject_token_buys_a_token_per_recorded_decision(client, rooted) -> None:
    """Fan-out at a hop: two recorded allows, two narrowed tokens, one subject token."""
    first = await allowed_exchange(
        client, rooted["root_grant"], resource=f"agent://{KB_SEARCH}", scope="kb.internal"
    )
    second = await allowed_exchange(
        client, rooted["root_grant"], resource=KB_TOOL, scope="kb.public"
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert (
        claims(first.json()["access_token"])["jti"] != claims(second.json()["access_token"])["jti"]
    )


async def test_audience_disagreeing_with_resource_is_refused(client, rooted) -> None:
    r = await allowed_exchange(
        client,
        rooted["root_grant"],
        resource=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        audience=f"agent://{SUMMARIZER}",
    )
    assert r.status_code == 403
    assert r.json()["error"] == "invalid_target"


# -- a denied hop yields no token -------------------------------------------


async def test_an_undeclared_edge_yields_no_token(client, rooted) -> None:
    r = await allowed_exchange(
        client, rooted["root_grant"], resource=f"agent://{SUMMARIZER}", scope="account.read"
    )
    assert r.status_code == 400
    assert "access_token" not in r.json()
    assert r.json()["error"] == "invalid_grant"
    assert "was a deny" in r.json()["error_description"]


async def test_an_out_of_scope_tool_yields_no_token(client, rooted) -> None:
    r = await allowed_exchange(
        client,
        rooted["root_grant"],
        resource="mcp://ledger.internal/read_ledger",
        scope="ledger.read",
    )
    assert r.status_code == 400
    assert "access_token" not in r.json()


async def test_a_recorded_allow_that_no_longer_holds_is_re_decided_and_refused(
    client, rooted, db_session
) -> None:
    """Defence in depth. The exchange re-runs the decision rather than trusting the row, so
    even a recorded allow for an undeclared edge buys nothing — and the refusal is recorded."""
    from agentic_auth.repositories import audit_decisions as audit_repo

    root = rooted["root_grant"]
    stale = await audit_repo.append(
        db_session,
        action_id=uuid.uuid4(),
        ts=datetime.now(UTC),
        session_id=uuid.UUID(rooted["session_id"]),
        caller=USER,
        target=f"agent://{SUMMARIZER}",
        data_class="account.read",
        hop=1,
        outcome="allow",
        deny_reason=None,
        recoverable=False,
        enforced=True,
        taint=None,
        taint_source=None,
        privileged=False,
        policy_version=rooted["policy_version"],
        act_chain=[USER],
        acting_agent=ORCHESTRATOR,
        subject_jti=claims(root)["jti"],
        parent_action_id=None,
        chain=None,
        chain_complete=False,
        chain_break="LEGACY_TOKEN",
    )
    await db_session.commit()

    r = await exchange(
        client, root, resource=f"agent://{SUMMARIZER}", scope="account.read", action_id=stale.id
    )
    assert r.status_code == 403
    assert r.json()["error"] == "invalid_target"
    assert "not a declared edge" in r.json()["error_description"]
    assert "access_token" not in r.json()

    rows = (
        (
            await db_session.execute(
                text(
                    "SELECT outcome, deny_reason, caller, target FROM audit_decisions "
                    "WHERE session_id = :i ORDER BY seq"
                ),
                {"i": rooted["session_id"]},
            )
        )
        .mappings()
        .all()
    )
    assert [row["outcome"] for row in rows] == ["allow", "deny"]
    assert rows[1]["deny_reason"] == "EDGE_NOT_IN_DAG"
    assert rows[1]["caller"] == USER
    assert rows[1]["target"] == f"agent://{SUMMARIZER}"


# -- binding to a recorded decision ---------------------------------


async def test_the_issued_token_names_the_decision_that_authorized_it(client, rooted) -> None:
    decision = (
        await authorize(
            client, rooted["root_grant"], target=f"agent://{KB_SEARCH}", data_class="kb.internal"
        )
    ).json()
    r = await exchange(
        client,
        rooted["root_grant"],
        resource=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        action_id=decision["action_id"],
    )
    assert claims(r.json()["access_token"])["action_id"] == decision["action_id"]


async def test_an_exchange_must_name_a_decision(client, rooted) -> None:
    r = await exchange(
        client, rooted["root_grant"], resource=f"agent://{KB_SEARCH}", scope="kb.internal"
    )
    assert r.status_code == 400
    assert r.json() == {"error": "invalid_request", "error_description": ACTION_ID_REQUIRED}


async def test_the_decision_must_be_a_uuid(client, rooted) -> None:
    r = await exchange(
        client,
        rooted["root_grant"],
        resource=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        action_id="not-a-uuid",
    )
    assert r.status_code == 400
    assert r.json() == {"error": "invalid_request", "error_description": ACTION_ID_INVALID}


async def test_the_decision_must_exist(client, rooted) -> None:
    missing = uuid.uuid4()
    r = await exchange(
        client,
        rooted["root_grant"],
        resource=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        action_id=missing,
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"
    assert r.json()["error_description"] == f"no recorded allow decision {missing}"


def _differs(field: str):
    return f"does not authorize this exchange: {field} differs"


async def test_a_decision_for_another_target_is_refused(client, rooted) -> None:
    root = rooted["root_grant"]
    d = (
        await authorize(client, root, target=f"agent://{KB_SEARCH}", data_class="kb.internal")
    ).json()
    r = await exchange(
        client, root, resource=KB_TOOL, scope="kb.internal", action_id=d["action_id"]
    )
    assert r.status_code == 400
    assert _differs("target") in r.json()["error_description"]


async def test_a_decision_for_another_data_class_is_refused(client, rooted) -> None:
    root = rooted["root_grant"]
    d = (
        await authorize(client, root, target=f"agent://{KB_SEARCH}", data_class="kb.internal")
    ).json()
    r = await exchange(
        client, root, resource=f"agent://{KB_SEARCH}", scope="kb.public", action_id=d["action_id"]
    )
    assert r.status_code == 400
    assert _differs("data_class") in r.json()["error_description"]


async def test_a_decision_for_another_hop_is_refused(client, rooted) -> None:
    root = rooted["root_grant"]
    d1 = (
        await authorize(client, root, target=f"agent://{KB_SEARCH}", data_class="kb.internal")
    ).json()
    t1 = (
        await exchange(
            client,
            root,
            resource=f"agent://{KB_SEARCH}",
            scope="kb.internal",
            action_id=d1["action_id"],
        )
    ).json()["access_token"]

    # Hop 1's allow, presented with hop 2's token.
    r = await exchange(
        client,
        t1,
        resource=f"agent://{SUMMARIZER}",
        scope="account.read",
        action_id=d1["action_id"],
    )
    assert r.status_code == 400
    assert _differs("hop") in r.json()["error_description"]


async def test_a_decision_from_another_session_is_refused(client, rooted, consent) -> None:
    other = await consent()
    d = (
        await authorize(
            client, other["root_grant"], target=f"agent://{KB_SEARCH}", data_class="kb.internal"
        )
    ).json()
    r = await exchange(
        client,
        rooted["root_grant"],
        resource=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        action_id=d["action_id"],
    )
    assert r.status_code == 400
    assert _differs("session_id") in r.json()["error_description"]


async def test_a_decision_made_for_a_different_subject_token_is_refused(client, rooted) -> None:
    """Same session, same hop, same target and data class — but not the token that was
    decided. The allow is bound to the exact token presented at authorize."""
    from agentic_auth.api.service_deps import get_token_profile

    root = rooted["root_grant"]
    twin = get_token_profile().mint_root_grant(
        sub=USER,
        scope=ORCHESTRATOR,
        session_id=rooted["session_id"],
        policy_version=rooted["policy_version"],
    )
    d = (
        await authorize(client, root, target=f"agent://{KB_SEARCH}", data_class="kb.internal")
    ).json()

    r = await exchange(
        client, twin, resource=f"agent://{KB_SEARCH}", scope="kb.internal", action_id=d["action_id"]
    )
    assert r.status_code == 400
    assert _differs("subject_jti") in r.json()["error_description"]


async def test_a_refused_exchange_does_not_spend_the_subject_token(client, rooted) -> None:
    root = rooted["root_grant"]
    d = (
        await authorize(client, root, target=f"agent://{KB_SEARCH}", data_class="kb.internal")
    ).json()

    refused = await exchange(
        client, root, resource=f"agent://{KB_SEARCH}", scope="kb.public", action_id=d["action_id"]
    )
    assert refused.status_code == 400

    retried = await exchange(
        client, root, resource=f"agent://{KB_SEARCH}", scope="kb.internal", action_id=d["action_id"]
    )
    assert retried.status_code == 200, retried.text


# -- grammar -----------------------------------------------------------------


async def test_unsupported_grant_type_is_refused(client, rooted) -> None:
    r = await client.post(
        "/v1/token/exchange",
        data={
            "grant_type": "authorization_code",
            "subject_token": rooted["root_grant"],
            "subject_token_type": JWT_TOKEN_TYPE,
            "resource": f"agent://{KB_SEARCH}",
            "scope": "kb.internal",
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "unsupported_grant_type"


async def test_unsupported_subject_token_type_is_refused(client, rooted) -> None:
    r = await client.post(
        "/v1/token/exchange",
        data={
            "grant_type": GRANT_TYPE,
            "subject_token": rooted["root_grant"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "resource": f"agent://{KB_SEARCH}",
            "scope": "kb.internal",
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"


async def test_a_garbage_subject_token_is_refused(client, rooted) -> None:
    r = await exchange(
        client,
        "not-a-token",
        resource=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        action_id=uuid.uuid4(),
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


async def test_a_tampered_subject_token_is_refused(client, rooted) -> None:
    from tests.fixtures.tokens import tampered

    r = await exchange(
        client,
        tampered(rooted["root_grant"], scope="account.write"),
        resource=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        action_id=uuid.uuid4(),
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


# -- the single-use guard must outlive the acceptance window ------------------


async def test_the_replay_guard_outlives_the_window_in_which_the_token_is_accepted(
    client, rooted, redis_client
) -> None:
    """`verify()` accepts a token until `exp + LEEWAY_SECONDS`. A guard sized to the
    token's nominal lifetime dies first and reopens a replay window — with the shipped
    defaults, up to 59 seconds wide. Both existing replay tests spend and re-present
    immediately, so neither can see it; this one inspects the TTL Redis actually holds.
    """
    from agentic_auth.config import get_settings
    from agentic_auth.services.tokens.jwt_profile import LEEWAY_SECONDS
    from agentic_auth.services.tokens.replay import spent_key
    from tests.fixtures.tokens import raw_claims

    decision = (
        await authorize(
            client, rooted["root_grant"], target=f"agent://{KB_SEARCH}", data_class="kb.internal"
        )
    ).json()
    r = await exchange(
        client,
        rooted["root_grant"],
        resource=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        action_id=decision["action_id"],
    )
    assert r.status_code == 200

    # Phase 4: the guard is keyed by the DECISION spent, not the token's jti.
    guard_ttl = await redis_client.ttl(spent_key(decision["action_id"]))
    assert guard_ttl > 0, "the guard was not recorded at all"
    assert raw_claims(rooted["root_grant"])["jti"]  # the token is intact and still usable

    settings = get_settings()
    # Worst case: spent the instant it was minted, so the whole nominal lifetime plus
    # the verifier's leeway still lies ahead.
    assert guard_ttl >= settings.hop_token_ttl_seconds + LEEWAY_SECONDS - 1, (
        f"guard lives {guard_ttl}s but the token is accepted for up to "
        f"{settings.hop_token_ttl_seconds + LEEWAY_SECONDS}s — replay window reopens"
    )


async def test_a_guard_that_cannot_be_written_fails_the_exchange_closed(
    client, rooted, monkeypatch
) -> None:
    """The other three bindings (aud, scope, hop) still hold, but a guarantee that
    quietly degrades is worse than one that refuses."""
    from agentic_auth.services.tokens import replay

    async def _dead(*_a, **_k):
        raise replay.ReplayGuardUnavailable("redis is down")

    monkeypatch.setattr(replay, "consume", _dead)

    r = await allowed_exchange(
        client, rooted["root_grant"], resource=f"agent://{KB_SEARCH}", scope="kb.internal"
    )

    assert r.status_code == 503
    assert "access_token" not in r.json()
