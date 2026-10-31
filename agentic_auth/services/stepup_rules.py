"""The step-up decisions, as pure functions.

Everything here is a question with an answer that does not depend on I/O: is this refusal
recoverable at all, is this data class inside the ceiling the pinned manifest sets, and
what does the session's consented set become once a human approves. Keeping them here
means they can be tested as a matrix, and means the service layer contains orchestration
rather than judgement.

The ceiling rule is the one worth reading twice. FR-028: a step-up approval may never
grant a data class the pinned manifest does not declare. That is not a policy preference —
it is what keeps consent from becoming a manifest-authoring interface, which PRD §9.4
reserves for human review of an actual diff.
"""

from __future__ import annotations

from collections.abc import Iterable

from agentic_auth.schemas.authorize import DenyReason, is_recoverable
from agentic_auth.services.policy_loader import PolicyIndex


def recoverable(reason: DenyReason | None) -> bool:
    """Is this refusal a step-up candidate?

    Delegates to the single ``RECOVERABLE`` table in :mod:`agentic_auth.schemas.authorize` rather
    than restating it, so the PDP, the enforcement points and this flow cannot come to
    disagree about what a human is even allowed to be asked.

    ``None`` is an allow, which is not a refusal to recover from.
    """
    return reason is not None and is_recoverable(reason)


def within_ceiling(policy: PolicyIndex, holder: str, data_class: str) -> bool:
    """May a human grant this data class for this agent at all?

    Only if the pinned manifest already declares it. Consent widens *within* the
    manifest; it never extends it (FR-028).
    """
    return policy.declares_data_class(holder, data_class)


def widen(consented: Iterable[str] | None, data_class: str) -> frozenset[str] | None:
    """The session's consented set after a grant.

    ``None`` in means ``None`` out: a session that consented to everything the policy
    declares has nothing left to widen, and turning it into an explicit set here would
    quietly *narrow* it to whatever happened to be listed.
    """
    if consented is None:
        return None
    return frozenset(consented) | {data_class}


def ceiling_for(policy: PolicyIndex, holder: str) -> frozenset[str]:
    """Everything a human could ever grant for this agent — for an operator-facing
    message that says what the options actually are, rather than only what failed."""
    return frozenset(policy.data_classes_by_agent.get(holder, ()))


def holder_of(target: str, caller: str) -> str:
    """Whoever will act on the data class: the delegate if this hop is a delegation,
    otherwise the caller itself.

    The same rule ``decide()`` applies, restated here rather than imported so the service
    cannot accidentally check the ceiling for a different agent than the PDP refused for.
    """
    return target.removeprefix("agent://") if target.startswith("agent://") else caller


__all__ = ["ceiling_for", "holder_of", "recoverable", "widen", "within_ceiling"]
