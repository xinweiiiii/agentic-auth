"""What step-up must NOT do (US3; FR-024, FR-027, FR-028, FR-031; SC-010, SC-011).

The happy path is in ``test_stepup.py``. This file is the other half, and arguably the
more important one: a consent prompt that can be put in front of a human for something
that must never be granted is worse than no prompt at all, because it launders a refusal
into an approval the human believes was meaningful.

Every row of the matrix in quickstart.md §7 is here.
"""

from __future__ import annotations

import pytest

from agentic_auth.services.stepup import hash_challenge
from tests.conftest import ADMIN_TOKEN
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    USER,
    bank_docs,
)
from tests.fixtures.hops import authorize, hop, register_agents

WITHHELD_CLASS = "kb.internal"
CONSENTED = ["account.read", "account.write"]

ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture
async def granular(client, admin_headers, flags):
    flags(consent_granularity_enabled=True, step_up_enabled=True)
    # trust_kb OFF, so reading the knowledge base taints — needed for the
    # TAINTED_INTO_PRIVILEGED row of the matrix.
    await register_agents(client, admin_headers, bank_docs(widened=True))


async def _session(client, admin_headers, classes=CONSENTED):
    r = await client.post(
        "/v1/consent",
        headers=admin_headers,
        json={"scope": BANK_ASSISTANT, "user_sub": USER, "data_classes": classes},
    )
    assert r.status_code == 201, r.text
    return r.json()


async def _raise(client, session_id, action_id, headers=None):
    return await client.post(
        "/v1/consent/step-up",
        headers=headers or ADMIN,
        json={"session_id": session_id, "blocked_action_id": action_id},
    )


async def _to_support(client, session):
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    assert t1 is not None
    _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return t1, t2


# -- non-recoverable reasons are never offered a challenge (FR-024, SC-010) ------------


async def test_a_tainted_privileged_refusal_offers_no_challenge(
    client, admin_headers, granular
) -> None:
    """The one that matters most. Injected content steered this call; a consent prompt
    cannot launder it, and offering one would invite a human to approve exactly the
    attack the control exists to stop."""
    session = await _session(
        client, admin_headers, ["account.read", "kb.internal", "account.write"]
    )
    _, support = await _to_support(client, session)
    await authorize(client, support, target="mcp://kb.internal/search", data_class="kb.internal")

    refusal = (
        await authorize(client, support, target=TERMINATE_ACCOUNT, data_class="account.write")
    ).json()
    assert refusal["reason"] == "TAINTED_INTO_PRIVILEGED"
    assert refusal["step_up"] is None, "no prompt may be offered for injected content"

    attempt = await _raise(client, session["session_id"], refusal["action_id"])

    assert attempt.status_code == 422
    assert "not recoverable" in attempt.text


async def test_an_undeclared_edge_offers_no_challenge(client, admin_headers, granular) -> None:
    """A consent prompt cannot invent an edge nobody declared."""
    session = await _session(client, admin_headers)
    refusal = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{SUPPORT_AGENT}",
            data_class="kb.internal",
        )
    ).json()
    assert refusal["reason"] in {"EDGE_NOT_IN_DAG", "SCOPE_NOT_CONSENTED"}

    if refusal["reason"] == "EDGE_NOT_IN_DAG":
        assert refusal["step_up"] is None
        attempt = await _raise(client, session["session_id"], refusal["action_id"])
        assert attempt.status_code == 422


async def test_an_undeclared_data_class_offers_no_challenge(
    client, admin_headers, granular
) -> None:
    """The split in action: with a consented subset in play, a class the manifest never
    declared is OUT_OF_SCOPE and final, not a recoverable near-miss."""
    session = await _session(client, admin_headers)

    refusal = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="nonsense.class",
        )
    ).json()

    assert refusal["reason"] == "OUT_OF_SCOPE"
    assert refusal["recoverable"] is False
    assert refusal["step_up"] is None


async def test_an_allow_cannot_raise_a_challenge(client, admin_headers, granular) -> None:
    session = await _session(client, admin_headers)
    allowed = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
    ).json()
    assert allowed["outcome"] == "allow"

    attempt = await _raise(client, session["session_id"], allowed["action_id"])

    assert attempt.status_code == 422
    assert "nothing to step up" in attempt.text


# -- the ceiling (FR-028) ---------------------------------------------------------------


async def test_a_refusal_in_another_session_is_not_found(client, admin_headers, granular) -> None:
    """A caller must not be able to widen someone else's session by naming its action."""
    mine = await _session(client, admin_headers)
    theirs = await _session(client, admin_headers)
    _, refusal = await _blocked(client, theirs)

    attempt = await _raise(client, mine["session_id"], refusal["action_id"])

    assert attempt.status_code == 404


async def _blocked(client, session):
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    decision = (
        await authorize(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class=WITHHELD_CLASS)
    ).json()
    return t1, decision


# -- single use (FR-027, SC-011) ---------------------------------------------------------


async def test_a_challenge_can_be_answered_only_once(client, admin_headers, granular) -> None:
    session = await _session(client, admin_headers)
    _, refusal = await _blocked(client, session)
    challenge_id = refusal["step_up"]["challenge_id"]

    first = await client.post(
        "/v1/consent/step-up/complete",
        headers=ADMIN,
        json={"challenge_id": challenge_id, "approved": True},
    )
    second = await client.post(
        "/v1/consent/step-up/complete",
        headers=ADMIN,
        json={"challenge_id": challenge_id, "approved": True},
    )

    assert first.status_code == 200
    assert second.status_code == 409, second.text


async def test_an_unknown_challenge_reads_as_expired(client, admin_headers, granular) -> None:
    """Expired and never-existed are indistinguishable from outside, deliberately: a
    caller must not be able to probe which challenge ids were ever real."""
    await _session(client, admin_headers)

    response = await client.post(
        "/v1/consent/step-up/complete",
        headers=ADMIN,
        json={"challenge_id": "never-issued", "approved": True},
    )

    assert response.status_code == 410


async def test_an_expired_challenge_leaves_the_refusal_standing(
    client, admin_headers, granular, redis_client
) -> None:
    session = await _session(client, admin_headers)
    token, refusal = await _blocked(client, session)
    challenge_id = refusal["step_up"]["challenge_id"]

    # Expire it the way time would, without waiting five minutes.
    await redis_client.delete(f"challenge:{challenge_id}")

    answer = await client.post(
        "/v1/consent/step-up/complete",
        headers=ADMIN,
        json={"challenge_id": challenge_id, "approved": True},
    )
    assert answer.status_code == 410

    again = (
        await authorize(client, token, target=f"agent://{SUPPORT_AGENT}", data_class=WITHHELD_CLASS)
    ).json()
    assert again["outcome"] == "deny"


# -- who may approve (research.md R6) ------------------------------------------------------


async def test_the_agents_own_grant_cannot_approve_its_widening(
    client, admin_headers, granular
) -> None:
    """The structural form of "the user approves". An agent that could answer its own
    prompt would make SCOPE_NOT_CONSENTED a formality — an injected instruction would
    simply approve the challenge it triggered."""
    session = await _session(client, admin_headers)
    _, refusal = await _blocked(client, session)

    answer = await client.post(
        "/v1/consent/step-up/complete",
        headers={"Authorization": f"Bearer {session['root_grant']}"},
        json={"challenge_id": refusal["step_up"]["challenge_id"], "approved": True},
    )

    assert answer.status_code == 401
    assert "not sufficient" in answer.text


# -- nothing secret is stored (SC-018) --------------------------------------------------


async def test_the_challenge_value_is_never_stored(
    client, admin_headers, granular, db_session
) -> None:
    """Only its SHA-256 lands in the table. A stored challenge would be a bearer
    credential sitting where anyone with read access could take it."""
    from sqlalchemy import select

    from agentic_auth.models import StepUpGrant

    session = await _session(client, admin_headers)
    _, refusal = await _blocked(client, session)
    challenge_id = refusal["step_up"]["challenge_id"]
    await client.post(
        "/v1/consent/step-up/complete",
        headers=ADMIN,
        json={"challenge_id": challenge_id, "approved": True},
    )

    rows = (await db_session.execute(select(StepUpGrant))).scalars().all()

    assert len(rows) == 1
    assert rows[0].challenge_hash == hash_challenge(challenge_id)
    assert challenge_id not in str(rows[0].__dict__)
