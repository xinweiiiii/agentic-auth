"""Materializing the delegation chain at write time — pure.

``extend_chain`` decides, once and for all, which chain an audit row carries and whether it
is complete. No I/O, no clock, no exceptions: the audit service reads the parent row and the
clock, and this function only judges them. That is what turns every branch below into a
unit test instead of a database fixture.

A chain is only ever recorded as complete when every link was checked. The parent must be
the row the verified token names, in the same session, exactly one hop earlier. It must be
an allow that delegated to exactly the agent now acting, and its own chain must agree with
the signed ``act`` chain.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

AGENT_PREFIX = "agent://"


class ChainBreak(StrEnum):
    # Written before Phase 3; per-hop detail was never captured.
    LEGACY_RECORD = "LEGACY_RECORD"
    # Presented token minted before the action_id claim existed.
    LEGACY_TOKEN = "LEGACY_TOKEN"
    PARENT_NOT_FOUND = "PARENT_NOT_FOUND"
    PARENT_MISMATCH = "PARENT_MISMATCH"
    # Inherited, not hidden: a broken ancestor keeps every descendant incomplete.
    PARENT_INCOMPLETE = "PARENT_INCOMPLETE"


@dataclass(frozen=True)
class ChainEntry:
    """One hop, exactly as it is stored in ``audit_decisions.chain``."""

    hop: int
    action_id: str
    acting_agent: str | None
    target: str
    target_kind: str
    data_class: str
    decision: str
    deny_reason: str | None
    enforced: bool
    ts: str
    # Phase 4, additive. `subject_jti` is what upward taint propagation keys on;
    # entries written by Phase 3 lack it and are treated as "unknown ancestor".
    subject_jti: str | None = None
    taint: str | None = None
    taint_source: str | None = None
    privileged: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ParentSnapshot:
    """The fields of the parent row this function is allowed to judge."""

    action_id: str
    session_id: str
    hop: int
    outcome: str
    target: str
    chain: list[dict[str, Any]] | None
    chain_complete: bool


@dataclass(frozen=True)
class ChainResult:
    chain: list[dict[str, Any]]
    complete: bool
    break_reason: ChainBreak | None


def _complete(chain: list[dict[str, Any]]) -> ChainResult:
    return ChainResult(chain=chain, complete=True, break_reason=None)


def _broken(chain: list[dict[str, Any]], reason: ChainBreak) -> ChainResult:
    return ChainResult(chain=chain, complete=False, break_reason=reason)


def _links_to(
    parent: ParentSnapshot,
    entry: ChainEntry,
    *,
    session_id: str,
    token_act_chain: list[str],
) -> bool:
    if parent.session_id != session_id:
        return False
    if parent.hop != entry.hop - 1:
        return False
    # A deny or a tool call issues no token, so it can never be the parent of a hop.
    if parent.outcome != "allow":
        return False
    if entry.acting_agent is None or parent.target != f"{AGENT_PREFIX}{entry.acting_agent}":
        return False
    if parent.chain is not None:
        # `act_chain[1:]` are the agents that acted at hops 1..n-1, signed into the token.
        recorded = [hop.get("acting_agent") for hop in parent.chain]
        signed = [actor.removeprefix(AGENT_PREFIX) for actor in token_act_chain[1:]]
        if recorded != signed:
            return False
    return True


def extend_chain(
    parent: ParentSnapshot | None,
    entry: ChainEntry,
    *,
    session_id: str,
    token_action_id: str | None,
    token_next_hop: int,
    token_act_chain: list[str],
) -> ChainResult:
    """The chain for a new row, and whether it is complete. Rules apply in table order."""
    own = [entry.as_dict()]

    # 1. The presented token names no parent action.
    if token_action_id is None:
        if token_next_hop == 1:
            return _complete(own)  # the root grant: this row IS the start of the chain
        return _broken(own, ChainBreak.LEGACY_TOKEN)

    # 2. It names one that does not exist.
    if parent is None:
        return _broken(own, ChainBreak.PARENT_NOT_FOUND)

    # 3. It exists, but does not lead to this hop.
    if not _links_to(parent, entry, session_id=session_id, token_act_chain=token_act_chain):
        return _broken(own, ChainBreak.PARENT_MISMATCH)

    # 4. It leads here, but its own chain was already broken.
    if not parent.chain_complete:
        extended = [*parent.chain, entry.as_dict()] if parent.chain else own
        return _broken(extended, ChainBreak.PARENT_INCOMPLETE)

    # 5. Every link checked.
    return _complete([*(parent.chain or []), entry.as_dict()])
