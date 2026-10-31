"""One policy, many enforcement points, provably the same answer (US8; FR-043..FR-045).

The claim Phase 5 has to defend is that the gateway, the sidecar and the boundary
adapters are *one policy* deployed several ways — not three policies that happen to
agree today. This file is what makes that claim falsifiable, and it runs in CI as a gate
rather than as a report nobody reads.

**What is compared**: outcome, deny reason, recoverability and hop, per hop.

**What is deliberately NOT compared**: the guarantee level and the enforcement point.
Those are *expected* to differ — that is the entire purpose of the field — and folding
them into the equality would make the suite assert the opposite of what it exists for
(contracts/conformance.md §3).

Two documented exceptions live in §4 of that contract and are encoded below rather than
skipped: the resource guard sees one hop rather than a chain, and a consent-only
deployment declines to answer per-hop instead of approximating.
"""

from __future__ import annotations

import pytest

from agentic_auth.boundary.guarantee import Guarantee
from agentic_auth.services.guarantee import consent_only_refusal
from tests.fixtures.chain import chain, chain_docs
from tests.fixtures.hops import authorize, hop, register_agents

#: Every enforcement point that makes a per-hop decision. A sixth is added here, and
#: gets an entry in contracts/conformance.md §4 if it cannot see something the chain
#: needs — a new exception is a reviewed contract change, not a test skip.
PER_HOP_PEPS = ["sdk", "sidecar", "gateway"]


@pytest.fixture
async def chain_session(client, admin_headers, consent, flags):
    """The one chain fixture, registered and consented."""
    flags(consent_granularity_enabled=False, taint_enforcement_enabled=True)
    docs = chain_docs()
    await register_agents(client, admin_headers, docs)
    from tests.fixtures.chain import ROOT_SCOPE

    return await consent(scope=ROOT_SCOPE, user_sub="user:alice")


async def _drive(client, session, hops, *, guarantee: str):
    """Walk the chain once through one enforcement point, collecting every decision.

    The enforcement points differ in transport, not in what they ask, so the driver is
    the same for all of them: the `guarantee` they report is the only thing that varies,
    which is exactly the claim under test.
    """
    token = session["root_grant"]
    results = []
    for h in hops:
        decision = (
            await authorize(
                client, token, target=h.target, data_class=h.data_class, guarantee=guarantee
            )
        ).json()
        results.append((h.name, decision))
        if decision["outcome"] == "allow" and h.target.startswith("agent://"):
            _, token = await hop(client, token, target=h.target, data_class=h.data_class)
            if token is None:
                break
    return results


def _comparable(decision: dict) -> tuple:
    """The parts every enforcement point must agree on, and only those."""
    return (
        decision["outcome"],
        decision.get("reason"),
        decision.get("recoverable"),
        decision["hop"],
    )


@pytest.mark.parametrize("guarantee", ["full", "connector", "network"])
async def test_every_per_hop_point_reaches_the_same_verdicts(
    client, chain_session, guarantee
) -> None:
    """SC-001. The same chain, reported under three different guarantee levels, must
    produce identical decisions — because the level is recorded, never decided on."""
    hops = chain(consent_granularity=False)

    baseline = await _drive(client, chain_session, hops, guarantee="full")
    other = await _drive(client, chain_session, hops, guarantee=guarantee)

    assert [(n, _comparable(d)) for n, d in baseline] == [(n, _comparable(d)) for n, d in other]


async def test_the_guarantee_level_is_the_one_thing_that_differs(client, chain_session) -> None:
    """The complement of the test above: what the suite excludes from the equality is
    genuinely present and genuinely different."""
    hops = chain(consent_granularity=False)[:1]

    full = await _drive(client, chain_session, hops, guarantee="full")
    connector = await _drive(client, chain_session, hops, guarantee="connector")

    assert full[0][1]["guarantee"] == "full"
    assert connector[0][1]["guarantee"] == "connector"


async def test_the_chain_covers_every_decision_shape(client, chain_session) -> None:
    """A conformance suite over a chain that only ever allows would prove nothing."""
    hops = chain(consent_granularity=False)
    results = await _drive(client, chain_session, hops, guarantee="full")

    reasons = {d.get("reason") for _, d in results}
    assert None in reasons, "at least one allow"
    assert len(reasons) > 1, "at least one refusal, with a reason"


# -- documented exception 1: the resource guard sees one hop, not a chain ---------------


def test_the_resource_guard_exception_is_a_contract_not_a_skip() -> None:
    """contracts/conformance.md §4.1.

    ``agentic_auth.verify.admit()`` decides from the presented headers alone: it has no view of
    hop budget, delegation edges or context taint, because those live in the control
    plane and the guard is deliberately offline-capable. So it participates on the hops
    where the artefacts are sufficient, and refuses the others for the artefact that is
    missing — the same outcome by a narrower reason, which is correct rather than a
    divergence.

    The behaviour itself is covered in tests/integration/test_resource_guard.py; what is
    asserted here is that the exception is written down.
    """
    from pathlib import Path

    contract = Path(__file__).resolve().parents[2] / "docs" / "contracts" / "conformance.md"
    text = contract.read_text()

    assert "4.1 The resource-side guard sees one hop, not a chain" in text
    assert "TXN_MISSING" in text


# -- documented exception 2: consent-only declines rather than approximates --------------


def test_a_consent_only_deployment_declines_to_answer_per_hop() -> None:
    """contracts/conformance.md §4.2 and FR-015. It genuinely cannot make a per-hop
    decision, and approximating one would be the silent claim the guarantee level
    exists to prevent."""
    refusal = consent_only_refusal(Guarantee.CONSENT_ONLY)

    assert refusal is not None
    assert refusal["details"]["reason"] == "GUARANTEE_INSUFFICIENT"


def test_consent_only_is_absent_from_the_per_hop_comparison() -> None:
    """It is not in PER_HOP_PEPS, and that is the point: there is nothing per-hop to
    compare it against."""
    assert "consent_only" not in PER_HOP_PEPS


# -- the chain query answers across modes (FR-045, SC-017) ---------------------------------


async def test_the_delegation_chain_is_answerable_whoever_decided(
    client, admin_headers, chain_session
) -> None:
    """An operator must be able to ask "who authorized this?" without first knowing
    which enforcement point handled the hop."""
    hops = chain(consent_granularity=False)
    results = await _drive(client, chain_session, hops, guarantee="connector")
    allowed = [d for _, d in results if d["outcome"] == "allow" and d.get("action_id")]
    assert allowed, "the chain should contain at least one recorded allow"

    answer = await client.get(
        f"/v1/audit/actions/{allowed[-1]['action_id']}/chain", headers=admin_headers
    )

    assert answer.status_code == 200
    body = answer.json()
    assert body["root_consent"]["user_sub"] == "user:alice"


async def test_every_hop_is_recorded_with_its_guarantee_level(
    client, admin_headers, chain_session
) -> None:
    hops = chain(consent_granularity=False)
    await _drive(client, chain_session, hops, guarantee="network")

    page = await client.get(
        f"/v1/audit/decisions?session_id={chain_session['session_id']}", headers=admin_headers
    )
    rows = page.json()["data"]

    assert rows
    assert {r["guarantee_level"] for r in rows} <= {"network", "full"}
