"""Declared vs consented — the split that makes step-up able to grant anything
(US3, T052; research.md R5).

Three cases that were two before Phase 5:

===========================  ===================  ==========================
Situation                    Flag off (default)   Flag on
===========================  ===================  ==========================
not declared in the policy   SCOPE_NOT_CONSENTED  OUT_OF_SCOPE (final)
declared, not consented      cannot occur         SCOPE_NOT_CONSENTED (step-up)
declared and consented       allow                allow
===========================  ===================  ==========================

Every test here runs in both regimes where both are meaningful, because the flag-off
column is the Phase 2-4 contract and it must not move.
"""

from __future__ import annotations

import pytest

from agentic_auth.boundary.guarantee import Guarantee
from agentic_auth.schemas.authorize import AuthorizeRequest, DenyReason
from agentic_auth.services.pdp import decide
from agentic_auth.services.policy_loader import build_index
from agentic_auth.services.tokens.profile import VerifiedToken
from tests.fixtures.chains import KB_SEARCH, ORCHESTRATOR, compiled_dag

SESSION = "s1"
VERSION = 1
USER = "user:alice"


def _index():
    return build_index(compiled_dag(version=VERSION), scope=ORCHESTRATOR, version=VERSION)


def _token() -> VerifiedToken:
    """The root grant, held by the orchestrator at hop 1."""
    return VerifiedToken(
        raw="<verified>",
        sub=USER,
        aud=ORCHESTRATOR,
        scope="kb.public",
        session_id=SESSION,
        policy_version=VERSION,
        hop=1,
        jti="j0",
        expires_at=None,
        act=None,
    )


def _req(target: str, data_class: str) -> AuthorizeRequest:
    return AuthorizeRequest(
        session_id=SESSION,
        caller=USER,
        target=target,
        data_class=data_class,
        guarantee=Guarantee.FULL,
    )


def _decide(request, *, consented=None, step_up=frozenset()):
    return decide(
        _index(),
        request,
        _token(),
        consented_scope=ORCHESTRATOR,
        consented_data_classes=consented,
        step_up=step_up,
    )


DECLARED = "kb.internal"
UNDECLARED = "nonsense.class"
TARGET = f"agent://{KB_SEARCH}"


# -- flag off: exactly Phase 2-4 ------------------------------------------------------


def test_with_no_subset_a_declared_class_is_allowed() -> None:
    assert _decide(_req(TARGET, DECLARED)).allowed


def test_with_no_subset_an_undeclared_class_keeps_its_phase_2_reason() -> None:
    """The contract that shipped. Changing this for an existing deployment would move a
    reason code under it without warning, so the flag-off path must not drift."""
    decision = _decide(_req(TARGET, UNDECLARED))

    assert decision.reason is DenyReason.SCOPE_NOT_CONSENTED
    assert decision.recoverable is True


# -- flag on: the split -----------------------------------------------------------------


def test_declared_and_consented_is_allowed() -> None:
    assert _decide(_req(TARGET, DECLARED), consented=frozenset({DECLARED})).allowed


def test_declared_but_not_consented_is_recoverable() -> None:
    """The case step-up exists for, and the case that could not occur before."""
    decision = _decide(_req(TARGET, DECLARED), consented=frozenset({"something.else"}))

    assert decision.reason is DenyReason.SCOPE_NOT_CONSENTED
    assert decision.recoverable is True
    assert "not consented" in (decision.message or "")


def test_undeclared_is_out_of_scope_and_final() -> None:
    """The heart of the change. An undeclared class must NOT be recoverable, because a
    step-up approval may never grant beyond the pinned manifest (FR-028). Leaving it as
    SCOPE_NOT_CONSENTED is what made the only recoverable reason ungrantable."""
    decision = _decide(_req(TARGET, UNDECLARED), consented=frozenset({DECLARED}))

    assert decision.reason is DenyReason.OUT_OF_SCOPE
    assert decision.recoverable is False
    assert "not declared" in (decision.message or "")


def test_an_empty_consented_set_is_not_the_same_as_none() -> None:
    """`None` means "everything the policy declares"; the empty set means "nothing was
    consented". Collapsing them would silently re-open every session."""
    assert _decide(_req(TARGET, DECLARED), consented=None).allowed

    narrowed = _decide(_req(TARGET, DECLARED), consented=frozenset())
    assert narrowed.reason is DenyReason.SCOPE_NOT_CONSENTED


# -- step-up widens the session ---------------------------------------------------------


def test_a_step_up_grant_allows_the_hop_that_was_refused() -> None:
    request = _req(TARGET, DECLARED)
    consented = frozenset({"something.else"})

    before = _decide(request, consented=consented)
    after = _decide(request, consented=consented, step_up=frozenset({DECLARED}))

    assert before.reason is DenyReason.SCOPE_NOT_CONSENTED
    assert after.allowed


def test_a_step_up_grant_cannot_reach_an_undeclared_class() -> None:
    """Even with the grant present, the manifest is still the ceiling. The declared check
    runs first and does not consult the step-up set at all."""
    decision = _decide(
        _req(TARGET, UNDECLARED),
        consented=frozenset({DECLARED}),
        step_up=frozenset({UNDECLARED}),
    )

    assert decision.reason is DenyReason.OUT_OF_SCOPE
    assert decision.recoverable is False


def test_a_step_up_grant_for_another_class_does_not_help() -> None:
    decision = _decide(
        _req(TARGET, DECLARED),
        consented=frozenset({"something.else"}),
        step_up=frozenset({"yet.another"}),
    )

    assert decision.reason is DenyReason.SCOPE_NOT_CONSENTED


# -- ordering ---------------------------------------------------------------------------


@pytest.mark.parametrize("consented", [None, frozenset({DECLARED})])
def test_an_undeclared_edge_still_beats_the_data_class_check(consented) -> None:
    """The data-class questions come after the route questions in both regimes, so a
    refusal names the edge rather than a downstream symptom of it."""
    decision = _decide(_req("agent://ghost", DECLARED), consented=consented)

    assert decision.reason in {DenyReason.EDGE_NOT_IN_DAG, DenyReason.OUT_OF_SCOPE}
