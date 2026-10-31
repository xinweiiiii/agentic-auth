"""Every response and every row says how strong the enforcement actually was
(US5; FR-016..FR-021; SC-007, SC-008).

The property under test is honesty, not enforcement: nothing here changes whether a call
is allowed. What it changes is whether a deployment can be mistaken for a stronger one
than it is — which is PRD §8.3's "surfaced explicitly … never a silent degrade".
"""

from __future__ import annotations

import pytest

from agentic_auth.boundary.guarantee import Guarantee
from agentic_auth.services.guarantee import consent_only_refusal
from tests.fixtures.bank import BALANCE_AGENT, BANK_ASSISTANT, USER, bank_docs
from tests.fixtures.hops import authorize, register_agents


@pytest.fixture
async def rooted(client, admin_headers, consent):
    await register_agents(client, admin_headers, bank_docs(widened=True, trust_kb=True))
    return await consent(scope=BANK_ASSISTANT, user_sub=USER)


async def _decide(client, token, *, guarantee: str):
    return (
        await authorize(
            client,
            token,
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
            guarantee=guarantee,
        )
    ).json()


# -- the field is always present (FR-016, FR-017, SC-007) -----------------------------


@pytest.mark.parametrize("level", [g.value for g in Guarantee])
async def test_every_level_round_trips_onto_the_response(client, rooted, level) -> None:
    decision = await _decide(client, rooted["root_grant"], guarantee=level)

    assert decision["guarantee"] == level


@pytest.mark.parametrize("level", [g.value for g in Guarantee])
async def test_every_level_lands_on_the_audit_row(client, admin_headers, rooted, level) -> None:
    await _decide(client, rooted["root_grant"], guarantee=level)

    page = await client.get(
        f"/v1/audit/decisions?session_id={rooted['session_id']}", headers=admin_headers
    )
    rows = page.json()["data"]

    assert rows, "the decision should have been recorded"
    assert rows[0]["guarantee_level"] == level


async def test_omitting_the_level_is_refused(client, rooted) -> None:
    """FR-018, enforced by the schema rather than a runtime branch some path could miss.

    A default of `full` here would be the exact failure the field exists to prevent: an
    enforcement point that forgot to say what it is would be recorded as the strongest.
    """
    response = await client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {rooted['root_grant']}"},
        json={
            "session_id": rooted["session_id"],
            "caller": USER,
            "target": f"agent://{BALANCE_AGENT}",
            "data_class": "account.read",
        },
    )

    assert response.status_code == 422
    assert "guarantee" in response.text


async def test_an_unknown_level_is_refused(client, rooted) -> None:
    response = await client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {rooted['root_grant']}"},
        json={
            "session_id": rooted["session_id"],
            "caller": USER,
            "target": f"agent://{BALANCE_AGENT}",
            "data_class": "account.read",
            "guarantee": "mostly",
        },
    )

    assert response.status_code == 422


async def test_a_refusal_also_carries_the_level(client, rooted) -> None:
    """A weak deployment's refusals are as much a part of its record as its allows."""
    decision = (
        await authorize(
            client,
            rooted["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="nonsense.class",
            guarantee="connector",
        )
    ).json()

    assert decision["outcome"] == "deny"
    assert decision["guarantee"] == "connector"


# -- degrade is never silent (FR-019) ---------------------------------------------------


async def test_a_degrade_writes_its_own_event(client, admin_headers, rooted) -> None:
    """It lands in the same timeline as the decisions around it, so an operator reading
    a session sees the change between the hop before and the hop after."""
    await _decide(client, rooted["root_grant"], guarantee="full")
    await _decide(client, rooted["root_grant"], guarantee="consent_only")

    page = await client.get(
        f"/v1/audit/decisions?session_id={rooted['session_id']}", headers=admin_headers
    )
    rows = page.json()["data"]
    degrades = [r for r in rows if r["data_class"] == "-"]

    assert len(degrades) == 1, "exactly one degrade event"
    assert degrades[0]["guarantee_level"] == "consent_only"
    assert degrades[0]["outcome"] == "allow", "nothing was refused; the meaning changed"
    assert degrades[0]["deny_reason"] is None


async def test_starting_weak_is_a_configuration_not_a_degrade(
    client, admin_headers, rooted
) -> None:
    """Writing an event for this would train operators to ignore the one that matters."""
    await _decide(client, rooted["root_grant"], guarantee="consent_only")
    await _decide(client, rooted["root_grant"], guarantee="consent_only")

    page = await client.get(
        f"/v1/audit/decisions?session_id={rooted['session_id']}", headers=admin_headers
    )
    assert [r for r in page.json()["data"] if r["data_class"] == "-"] == []


async def test_strengthening_is_not_a_degrade(client, admin_headers, rooted) -> None:
    await _decide(client, rooted["root_grant"], guarantee="consent_only")
    await _decide(client, rooted["root_grant"], guarantee="full")

    page = await client.get(
        f"/v1/audit/decisions?session_id={rooted['session_id']}", headers=admin_headers
    )
    assert [r for r in page.json()["data"] if r["data_class"] == "-"] == []


# -- the operator view (FR-021) ---------------------------------------------------------


async def test_decisions_are_counted_by_level(client, rooted, metrics_registry) -> None:
    await _decide(client, rooted["root_grant"], guarantee="full")
    await _decide(client, rooted["root_grant"], guarantee="connector")

    def count(level: str) -> float:
        return (
            metrics_registry.registry.get_sample_value(
                "agentic_auth_decisions_by_guarantee_total",
                {"level": level, "outcome": "allow"},
            )
            or 0.0
        )

    assert count("full") >= 1
    assert count("connector") >= 1
    assert count("network") == 0, "nothing ran at a level nobody reported"


# -- consent-only declines rather than approximates (FR-015, SC-008) ---------------------


def test_a_consent_only_deployment_declines_a_per_hop_decision() -> None:
    refusal = consent_only_refusal(Guarantee.CONSENT_ONLY)

    assert refusal is not None
    assert refusal["code"] == "guarantee_insufficient"
    assert "will not approximate" in refusal["message"]


@pytest.mark.parametrize("level", [Guarantee.FULL, Guarantee.CONNECTOR, Guarantee.NETWORK])
def test_every_per_hop_mode_answers_normally(level: Guarantee) -> None:
    assert consent_only_refusal(level) is None
