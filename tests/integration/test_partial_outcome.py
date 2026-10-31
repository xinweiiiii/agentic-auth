"""A chain that cannot finish says what it did finish (US3; FR-030, FR-031; SC-012).

The hops that already ran cannot be undone, and some of them had side effects. A bare
failure would leave the caller guessing how far the task got; the difference between "it
failed" and "it read the account but did not close it" is the difference between a
recoverable situation and a support ticket.
"""

from __future__ import annotations

import pytest

from agentic_auth.schemas.authorize import DenyReason
from agentic_auth.sdk import AgenticAuthClient, PolicyDenied
from tests.conftest import ADMIN_TOKEN
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    SUPPORT_AGENT,
    USER,
    bank_docs,
)
from tests.fixtures.hops import register_agents

WITHHELD = "kb.internal"
CONSENTED = ["account.read", "account.write"]


@pytest.fixture
async def sdk(client, admin_headers, flags):
    flags(consent_granularity_enabled=True, step_up_enabled=True, taint_enforcement_enabled=False)
    await register_agents(client, admin_headers, bank_docs(widened=True, trust_kb=True))
    return AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)


async def _session(sdk, classes=CONSENTED):
    return await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER, data_classes=classes)


async def test_a_blocked_chain_names_what_completed(sdk) -> None:
    """The headline of FR-030: hop 1 ran, hop 2 did not, and the caller can tell."""
    session = await _session(sdk)

    grants, outcome = await sdk.run_chain(
        session.context(),
        [
            (f"agent://{BALANCE_AGENT}", "account.read"),
            (f"agent://{SUPPORT_AGENT}", WITHHELD),
        ],
    )

    assert outcome is not None
    assert len(grants) == 1, "exactly one hop got through"
    assert [h.target for h in outcome.completed] == [f"agent://{BALANCE_AGENT}"]
    assert outcome.blocked_target == f"agent://{SUPPORT_AGENT}"
    assert outcome.reason is DenyReason.SCOPE_NOT_CONSENTED


async def test_a_recoverable_partial_outcome_carries_the_challenge(sdk) -> None:
    session = await _session(sdk)

    _, outcome = await sdk.run_chain(
        session.context(),
        [
            (f"agent://{BALANCE_AGENT}", "account.read"),
            (f"agent://{SUPPORT_AGENT}", WITHHELD),
        ],
    )

    assert outcome is not None
    assert outcome.recoverable is True
    assert outcome.challenge is not None
    assert outcome.challenge["data_class"] == WITHHELD


async def test_a_completed_chain_returns_no_partial_outcome(sdk) -> None:
    session = await _session(sdk)

    grants, outcome = await sdk.run_chain(
        session.context(), [(f"agent://{BALANCE_AGENT}", "account.read")]
    )

    assert outcome is None
    assert len(grants) == 1


async def test_a_non_recoverable_block_is_still_a_partial_outcome(sdk) -> None:
    """Not recoverable does not mean not informative. The caller still learns which hops
    took effect before the wall."""
    session = await _session(sdk)

    grants, outcome = await sdk.run_chain(
        session.context(),
        [
            (f"agent://{BALANCE_AGENT}", "account.read"),
            # A DECLARED edge with an undeclared data class, so the data-class check is
            # what refuses rather than the edge check that runs before it.
            (f"agent://{SUPPORT_AGENT}", "nonsense.class"),
        ],
    )

    assert outcome is not None
    assert outcome.recoverable is False
    assert outcome.reason is DenyReason.OUT_OF_SCOPE
    assert outcome.challenge is None
    assert len(grants) == 1


async def test_the_chain_resumes_after_approval(sdk, client) -> None:
    """End to end: block, approve, resume the blocked hop, finish."""
    session = await _session(sdk)
    ctx = session.context()

    grants, outcome = await sdk.run_chain(
        ctx,
        [
            (f"agent://{BALANCE_AGENT}", "account.read"),
            (f"agent://{SUPPORT_AGENT}", WITHHELD),
        ],
    )
    assert outcome is not None and outcome.challenge is not None

    await sdk.approve(outcome.challenge, credential=ADMIN_TOKEN)

    # Resume from the context the last successful hop produced, not from the root.
    resumed = ctx.advanced(grants[0].access_token)
    grant = await sdk.authorize(resumed, target=f"agent://{SUPPORT_AGENT}", data_class=WITHHELD)

    assert grant.access_token


def test_an_exhausted_budget_is_not_recoverable_by_step_up() -> None:
    """FR-031. A consent prompt cannot refill a hop budget, so it must never offer to.

    Asserted against the recoverability table directly rather than by walking a chain
    deep enough to exhaust one: the table is the single source every enforcement point
    reads, so this is the property itself rather than one instance of it.
    """
    from agentic_auth.schemas.authorize import RECOVERABLE

    assert RECOVERABLE[DenyReason.HOP_BUDGET_EXCEEDED] is False
    assert RECOVERABLE[DenyReason.EDGE_NOT_IN_DAG] is False
    assert RECOVERABLE[DenyReason.TAINTED_INTO_PRIVILEGED] is False
    assert RECOVERABLE[DenyReason.OUT_OF_SCOPE] is False
    # Exactly one reason is a step-up candidate, and it is the consent one.
    assert [r for r, ok in RECOVERABLE.items() if ok] == [DenyReason.SCOPE_NOT_CONSENTED]


async def test_policy_denied_still_raises_for_a_single_hop(sdk) -> None:
    """``run_chain`` collects; ``authorize`` still raises. A refusal that is easy to
    ignore is a refusal that gets ignored."""
    session = await _session(sdk)

    with pytest.raises(PolicyDenied) as exc:
        await sdk.authorize(
            session.context(), target=f"agent://{BALANCE_AGENT}", data_class="nonsense.class"
        )

    assert exc.value.reason is DenyReason.OUT_OF_SCOPE
    assert exc.value.challenge is None
