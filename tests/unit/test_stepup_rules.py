"""The step-up decisions, as a matrix (US3, T051).

Pure functions, so no fixtures and no database: the recoverability table, the manifest
ceiling, and what widening does to a consented set.
"""

from __future__ import annotations

import pytest

from agentic_auth.schemas.authorize import RECOVERABLE, DenyReason
from agentic_auth.services.policy_loader import build_index
from agentic_auth.services.stepup_rules import (
    ceiling_for,
    holder_of,
    recoverable,
    widen,
    within_ceiling,
)
from tests.fixtures.chains import ORCHESTRATOR, compiled_dag

VERSION = 1
KB_SEARCH = "kb-search"


def _index():
    return build_index(compiled_dag(version=VERSION), scope=ORCHESTRATOR, version=VERSION)


# -- recoverability ---------------------------------------------------------------


@pytest.mark.parametrize("reason", list(DenyReason))
def test_recoverable_agrees_with_the_single_table(reason: DenyReason) -> None:
    """One table, read by the PDP, the enforcement points and this flow. If they could
    disagree, a human could be asked to approve something that would be refused anyway —
    or, worse, not asked about something that could have been granted."""
    assert recoverable(reason) is RECOVERABLE[reason]


def test_exactly_one_reason_is_recoverable() -> None:
    assert [r for r in DenyReason if recoverable(r)] == [DenyReason.SCOPE_NOT_CONSENTED]


def test_the_reasons_a_prompt_must_never_be_offered_for() -> None:
    """Each of these is a different kind of "no", and none of them is a near-miss a
    human should be invited to wave through."""
    assert not recoverable(DenyReason.TAINTED_INTO_PRIVILEGED)  # injected content
    assert not recoverable(DenyReason.EDGE_NOT_IN_DAG)  # an edge nobody declared
    assert not recoverable(DenyReason.HOP_BUDGET_EXCEEDED)  # a depth limit
    assert not recoverable(DenyReason.OUT_OF_SCOPE)  # outside the pinned manifest
    assert not recoverable(DenyReason.AGENT_REVOKED)  # a revoked agent
    assert not recoverable(DenyReason.PDP_UNAVAILABLE)  # an outage is not a policy


def test_an_allow_is_not_something_to_recover_from() -> None:
    assert recoverable(None) is False


# -- the ceiling (FR-028) ------------------------------------------------------------


def test_a_declared_class_is_within_the_ceiling() -> None:
    assert within_ceiling(_index(), KB_SEARCH, "kb.internal")


def test_an_undeclared_class_is_not() -> None:
    """The rule that keeps consent from becoming a manifest-authoring interface."""
    assert not within_ceiling(_index(), KB_SEARCH, "nonsense.class")


def test_a_class_declared_for_another_agent_is_not_in_this_ones_ceiling() -> None:
    """The ceiling is per agent. Otherwise approving a class for one agent would quietly
    grant it for every agent in the scope."""
    index = _index()
    others = {
        cls
        for agent, classes in index.data_classes_by_agent.items()
        if agent != KB_SEARCH
        for cls in classes
    } - set(index.data_classes_by_agent.get(KB_SEARCH, ()))
    for cls in others:
        assert not within_ceiling(index, KB_SEARCH, cls), cls


def test_an_unknown_agent_has_an_empty_ceiling() -> None:
    assert ceiling_for(_index(), "ghost") == frozenset()
    assert not within_ceiling(_index(), "ghost", "kb.internal")


def test_the_ceiling_is_what_the_policy_declares() -> None:
    index = _index()
    assert ceiling_for(index, KB_SEARCH) == frozenset(index.data_classes_by_agent[KB_SEARCH])


# -- widening -------------------------------------------------------------------------


def test_widening_adds_the_class() -> None:
    assert widen({"a"}, "b") == frozenset({"a", "b"})


def test_widening_is_idempotent() -> None:
    assert widen({"a", "b"}, "b") == frozenset({"a", "b"})


def test_widening_an_unrestricted_session_stays_unrestricted() -> None:
    """`None` means "everything the policy declares". Turning it into an explicit set
    here would quietly NARROW the session to whatever happened to be listed — a widening
    that removes permissions is the worst possible outcome for this function."""
    assert widen(None, "b") is None


def test_widening_does_not_mutate_the_input() -> None:
    original = {"a"}
    widen(original, "b")
    assert original == {"a"}


# -- who the class is checked for ------------------------------------------------------


def test_a_delegation_is_checked_for_the_delegate() -> None:
    """The same rule `decide()` applies. Checking the ceiling for the caller instead
    would let an approval be granted against the wrong agent's manifest."""
    assert holder_of("agent://kb-search", "orchestrator") == "kb-search"


def test_a_tool_call_is_checked_for_the_caller() -> None:
    assert holder_of("mcp://kb.internal/search", "orchestrator") == "orchestrator"
