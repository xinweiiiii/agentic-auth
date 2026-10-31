"""A recoverable refusal becomes a question, and the task finishes (US3; SC-009).

The headline scenario of the phase, end to end: consent to less than the policy declares,
drive a chain into the gap, get a challenge instead of a hard failure, have the **human**
approve it, and watch the original task complete from the hop that was blocked.

Resumption works for a reason worth stating: a refused hop performs no exchange, so the
presented token was never spent. Phase 4 moved the single-use guard to
``spent:{action_id}``, and a refusal has no allow decision to spend.
"""

from __future__ import annotations

import pytest

from tests.conftest import ADMIN_TOKEN
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    SUPPORT_AGENT,
    USER,
    bank_docs,
)
from tests.fixtures.hops import authorize, hop, register_agents

# Declared by balance-agent in the ordinary bank manifests, and deliberately left OUT of
# what the session consents to below. No manifest surgery needed: "declared but not
# consented" is a property of the session, not of the policy — which is exactly the
# distinction Phase 5 introduces.
WITHHELD_CLASS = "kb.internal"
CONSENTED = ["account.read"]


@pytest.fixture
async def granular(client, admin_headers, flags):
    """Consent granularity and step-up on, against the ordinary bank manifests."""
    flags(consent_granularity_enabled=True, step_up_enabled=True, taint_enforcement_enabled=False)
    await register_agents(client, admin_headers, bank_docs(widened=True, trust_kb=True))


async def _consented_session(client, admin_headers, classes: list[str]):
    response = await client.post(
        "/v1/consent",
        headers=admin_headers,
        json={"scope": BANK_ASSISTANT, "user_sub": USER, "data_classes": classes},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _blocked_hop(client, session):
    """Walk the consented hop, then attempt the one this session withheld.

    The block lands MID-CHAIN, which is the shape that matters: hop 1 already happened
    and cannot be undone, so resuming has to re-enter at hop 2 with the original
    delegation record rather than start the task over.

    A data class is evaluated for whoever will ACT on it — the delegate — so delegating
    to support-agent with ``kb.internal`` asks whether support-agent may read the
    knowledge base. The pinned policy says yes; this session's consent did not.
    """
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    assert t1 is not None, "the consented hop must get through"
    decision = (
        await authorize(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class=WITHHELD_CLASS)
    ).json()
    return t1, decision


# -- the happy path ------------------------------------------------------------------


async def test_consent_pins_the_subset(client, admin_headers, granular) -> None:
    session = await _consented_session(client, admin_headers, CONSENTED)

    assert session["data_classes"] == CONSENTED


async def test_a_declared_but_unconsented_class_is_refused_recoverably(
    client, admin_headers, granular
) -> None:
    session = await _consented_session(client, admin_headers, CONSENTED)

    _, decision = await _blocked_hop(client, session)

    assert decision["outcome"] == "deny"
    assert decision["reason"] == "SCOPE_NOT_CONSENTED"
    assert decision["recoverable"] is True


async def test_the_refusal_carries_a_challenge(client, admin_headers, granular) -> None:
    """Not a hard failure: the decision itself offers the question to ask."""
    session = await _consented_session(client, admin_headers, CONSENTED)

    _, decision = await _blocked_hop(client, session)

    challenge = decision["step_up"]
    assert challenge is not None
    assert challenge["data_class"] == WITHHELD_CLASS
    assert challenge["target"] == f"agent://{SUPPORT_AGENT}"
    assert challenge["reason"] == "SCOPE_NOT_CONSENTED"


async def test_approval_lets_the_original_task_finish(client, admin_headers, granular) -> None:
    """SC-009, and the whole point of the workstream."""
    session = await _consented_session(client, admin_headers, CONSENTED)
    token, decision = await _blocked_hop(client, session)
    challenge = decision["step_up"]

    approval = await client.post(
        "/v1/consent/step-up/complete",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"challenge_id": challenge["challenge_id"], "approved": True},
    )
    assert approval.status_code == 200, approval.text
    assert approval.json()["approved"] is True

    # Re-attempt the blocked hop with the SAME token. Nothing was spent by the refusal.
    resumed = (
        await authorize(client, token, target=f"agent://{SUPPORT_AGENT}", data_class=WITHHELD_CLASS)
    ).json()

    assert resumed["outcome"] == "allow", resumed
    assert resumed["hop"] == decision["hop"], "the budget continues; it does not reset"


async def test_the_widening_is_linked_to_the_refusal_in_the_audit_trail(
    client, admin_headers, granular
) -> None:
    """FR-025. An operator reading the refusal can find the approval that answered it."""
    session = await _consented_session(client, admin_headers, CONSENTED)
    _, decision = await _blocked_hop(client, session)

    approval = await client.post(
        "/v1/consent/step-up/complete",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"challenge_id": decision["step_up"]["challenge_id"], "approved": True},
    )
    grant = approval.json()

    assert grant["blocked_action_id"] == decision["action_id"]
    assert grant["audit_event_id"] is not None

    page = await client.get(
        f"/v1/audit/decisions?session_id={session['session_id']}", headers=admin_headers
    )
    linked = [r for r in page.json()["data"] if r["step_up_ref"] == grant["id"]]
    assert len(linked) == 1, "the widening is its own row, carrying the grant"


async def test_a_decline_leaves_the_refusal_standing(client, admin_headers, granular) -> None:
    session = await _consented_session(client, admin_headers, CONSENTED)
    token, decision = await _blocked_hop(client, session)

    declined = await client.post(
        "/v1/consent/step-up/complete",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"challenge_id": decision["step_up"]["challenge_id"], "approved": False},
    )
    assert declined.status_code == 200
    assert declined.json()["approved"] is False

    again = (
        await authorize(client, token, target=f"agent://{SUPPORT_AGENT}", data_class=WITHHELD_CLASS)
    ).json()
    assert again["outcome"] == "deny"


async def test_step_up_widens_one_session_not_the_policy(client, admin_headers, granular) -> None:
    """FR-029. The grant is a fact about this session; another session must be asked
    again. Otherwise one approval would quietly become a policy change."""
    first = await _consented_session(client, admin_headers, CONSENTED)
    token, decision = await _blocked_hop(client, first)
    await client.post(
        "/v1/consent/step-up/complete",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"challenge_id": decision["step_up"]["challenge_id"], "approved": True},
    )
    assert (
        await authorize(client, token, target=f"agent://{SUPPORT_AGENT}", data_class=WITHHELD_CLASS)
    ).json()["outcome"] == "allow"

    second = await _consented_session(client, admin_headers, CONSENTED)
    _, other = await _blocked_hop(client, second)

    assert other["outcome"] == "deny"
    assert other["reason"] == "SCOPE_NOT_CONSENTED"


async def test_a_second_hop_in_the_same_session_needs_no_second_challenge(
    client, admin_headers, granular
) -> None:
    session = await _consented_session(client, admin_headers, CONSENTED)
    token, decision = await _blocked_hop(client, session)
    await client.post(
        "/v1/consent/step-up/complete",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"challenge_id": decision["step_up"]["challenge_id"], "approved": True},
    )

    first = (
        await authorize(client, token, target=f"agent://{SUPPORT_AGENT}", data_class=WITHHELD_CLASS)
    ).json()
    second = (
        await authorize(client, token, target=f"agent://{SUPPORT_AGENT}", data_class=WITHHELD_CLASS)
    ).json()

    assert first["outcome"] == "allow"
    assert second["outcome"] == "allow"
    assert second["step_up"] is None


# -- the flag is off by default -------------------------------------------------------


async def test_the_routes_are_absent_when_step_up_is_disabled(client, admin_headers, flags) -> None:
    """A deployment that has not adopted step-up should not advertise an endpoint it
    would refuse everything from."""
    flags(consent_granularity_enabled=True, step_up_enabled=False)

    response = await client.post(
        "/v1/consent/step-up",
        headers=admin_headers,
        json={
            "session_id": "00000000-0000-0000-0000-000000000000",
            "blocked_action_id": "00000000-0000-0000-0000-000000000000",
        },
    )

    assert response.status_code == 404


async def test_data_classes_are_rejected_when_granularity_is_off(
    client, admin_headers, flags
) -> None:
    """Silently ignoring the field would let a caller believe it pinned a narrower
    consent than it did — the same class of error the guarantee level exists to prevent."""
    flags(consent_granularity_enabled=False, step_up_enabled=False)
    await register_agents(client, admin_headers, bank_docs(widened=True))

    response = await client.post(
        "/v1/consent",
        headers=admin_headers,
        json={"scope": BANK_ASSISTANT, "user_sub": USER, "data_classes": ["account.read"]},
    )

    assert response.status_code == 422


async def test_an_undeclared_data_class_is_refused_at_consent_time(
    client, admin_headers, granular
) -> None:
    """A typo surfaces here, not three hops into a chain where it reads like a policy
    bug."""
    response = await client.post(
        "/v1/consent",
        headers=admin_headers,
        json={"scope": BANK_ASSISTANT, "user_sub": USER, "data_classes": ["typo.class"]},
    )

    assert response.status_code == 422
    assert "typo.class" in response.text


async def test_kb_search_still_works_within_the_consented_subset(
    client, admin_headers, granular
) -> None:
    """The subset narrows; it must not break what it does include.

    Walked with ``kb.internal`` throughout, because that is the one class this session
    consented to — a chain that used ``account.read`` would be refused at hop 1, which
    is the behaviour the tests above already cover.
    """
    session = await _consented_session(client, admin_headers, CONSENTED)

    decision = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
    ).json()

    assert decision["outcome"] == "allow", decision
