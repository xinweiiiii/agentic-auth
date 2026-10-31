"""``extend_chain`` — every transition, and the chain invariants."""

from __future__ import annotations

import pytest

from agentic_auth.services.audit_chain import ChainBreak, ChainEntry, ParentSnapshot, extend_chain

SESSION = "5e1c0000-0000-4000-8000-000000000001"
OTHER_SESSION = "5e1c0000-0000-4000-8000-000000000002"
USER = "user:alice"

ENTRY_KEYS = {
    "hop",
    "action_id",
    "acting_agent",
    "target",
    "target_kind",
    "data_class",
    "decision",
    "deny_reason",
    "enforced",
    "ts",
    # Phase 4, additive.
    "subject_jti",
    "taint",
    "taint_source",
    "privileged",
}


def entry(
    hop: int,
    *,
    acting: str | None,
    target: str,
    decision: str = "allow",
    reason: str | None = None,
) -> ChainEntry:
    return ChainEntry(
        hop=hop,
        action_id=f"aaaa0000-0000-4000-8000-{hop:012d}",
        acting_agent=acting,
        target=target,
        target_kind="agent" if target.startswith("agent://") else "tool",
        data_class="kb.internal",
        decision=decision,
        deny_reason=reason,
        enforced=True,
        ts=f"2026-09-13T10:00:0{hop}+00:00",
    )


# The bank chain: bank-assistant -> balance-agent -> support-agent -> terminate_account.
HOP1 = entry(1, acting="bank-assistant", target="agent://balance-agent")
HOP2 = entry(2, acting="balance-agent", target="agent://support-agent")
HOP3_DENY = entry(
    3,
    acting="support-agent",
    target="mcp://accounts.internal/terminate_account",
    decision="deny",
    reason="OUT_OF_SCOPE",
)


def parent_of(
    *entries: ChainEntry,
    complete: bool = True,
    session: str = SESSION,
    chain: bool = True,
    outcome: str | None = None,
) -> ParentSnapshot:
    last = entries[-1]
    return ParentSnapshot(
        action_id=last.action_id,
        session_id=session,
        hop=last.hop,
        outcome=outcome or last.decision,
        target=last.target,
        chain=[e.as_dict() for e in entries] if chain else None,
        chain_complete=complete,
    )


def extend(parent, new, *, action_id="set", next_hop=None, act_chain=None):
    return extend_chain(
        parent,
        new,
        session_id=SESSION,
        token_action_id=None if action_id is None else (parent.action_id if parent else "x"),
        token_next_hop=next_hop if next_hop is not None else new.hop,
        token_act_chain=act_chain if act_chain is not None else _signed_chain(new.hop),
    )


def _signed_chain(hop: int) -> list[str]:
    agents = ["agent://bank-assistant", "agent://balance-agent", "agent://support-agent"]
    return [USER, *agents[: hop - 1]]


# -- rule 1: the token names no parent ------------------------------------------


def test_the_root_grant_starts_a_complete_chain() -> None:
    result = extend(None, HOP1, action_id=None, next_hop=1)
    assert result.complete is True
    assert result.break_reason is None
    assert result.chain == [HOP1.as_dict()]


def test_a_pre_phase_3_token_past_hop_one_is_legacy() -> None:
    result = extend(None, HOP2, action_id=None, next_hop=2)
    assert result.complete is False
    assert result.break_reason is ChainBreak.LEGACY_TOKEN
    assert result.chain == [HOP2.as_dict()]


# -- rule 2: the named parent does not exist --------------------------------------


def test_a_parent_that_does_not_exist_is_not_found() -> None:
    result = extend(None, HOP2)
    assert (result.complete, result.break_reason) == (False, ChainBreak.PARENT_NOT_FOUND)
    assert result.chain == [HOP2.as_dict()]


# -- rule 3: the parent exists but does not lead here -----------------------------


@pytest.mark.parametrize(
    ("parent", "new", "act_chain"),
    [
        pytest.param(parent_of(HOP1, session=OTHER_SESSION), HOP2, None, id="different session"),
        pytest.param(
            parent_of(HOP1),
            entry(3, acting="balance-agent", target="agent://x"),
            None,
            id="not exactly one hop earlier",
        ),
        pytest.param(parent_of(HOP1, outcome="deny"), HOP2, None, id="parent was a deny"),
        pytest.param(
            parent_of(HOP1),
            entry(2, acting="fraud-agent", target="agent://x"),
            None,
            id="parent delegated to a different agent",
        ),
        pytest.param(
            parent_of(HOP1),
            HOP2,
            [USER, "agent://someone-else"],
            id="parent chain disagrees with the signed act chain",
        ),
        pytest.param(
            parent_of(HOP1),
            entry(2, acting=None, target="agent://x"),
            None,
            id="no acting agent to link",
        ),
    ],
)
def test_a_parent_that_does_not_link_is_a_mismatch(parent, new, act_chain) -> None:
    result = extend(parent, new, act_chain=act_chain)
    assert (result.complete, result.break_reason) == (False, ChainBreak.PARENT_MISMATCH)
    assert result.chain == [new.as_dict()]


def test_a_tool_call_can_never_be_a_parent() -> None:
    tool = entry(2, acting="balance-agent", target="mcp://accounts.internal/read_balance")
    result = extend(parent_of(HOP1, tool), HOP3_DENY)
    assert result.break_reason is ChainBreak.PARENT_MISMATCH


# -- rule 4: the parent's own chain was broken ------------------------------------


def test_a_broken_ancestor_keeps_the_break_and_the_known_hops() -> None:
    result = extend(parent_of(HOP1, complete=False), HOP2)
    assert (result.complete, result.break_reason) == (False, ChainBreak.PARENT_INCOMPLETE)
    assert result.chain == [HOP1.as_dict(), HOP2.as_dict()]


def test_a_legacy_parent_with_no_chain_contributes_no_hops() -> None:
    result = extend(parent_of(HOP1, complete=False, chain=False), HOP2)
    assert (result.complete, result.break_reason) == (False, ChainBreak.PARENT_INCOMPLETE)
    assert result.chain == [HOP2.as_dict()]


# -- rule 5: every link checked ---------------------------------------------------


def test_a_linked_parent_extends_the_chain() -> None:
    result = extend(parent_of(HOP1), HOP2)
    assert result.complete is True
    assert result.break_reason is None
    assert result.chain == [HOP1.as_dict(), HOP2.as_dict()]


def test_the_prd_chain_ends_at_the_refused_tool_call() -> None:
    result = extend(parent_of(HOP1, HOP2), HOP3_DENY)
    assert result.complete is True
    chain = result.chain

    # §2.1: consecutive hops, last equals this row.
    assert [h["hop"] for h in chain] == [1, 2, 3]
    assert chain[-1]["action_id"] == HOP3_DENY.action_id
    # §2.1: each hop's acting agent is the agent the previous hop delegated to.
    for previous, current in zip(chain, chain[1:], strict=False):
        assert previous["target"] == f"agent://{current['acting_agent']}"
    # §2.1: only the last hop may be a deny or a tool call.
    assert all(h["decision"] == "allow" and h["target_kind"] == "agent" for h in chain[:-1])
    assert (chain[-1]["decision"], chain[-1]["target_kind"]) == ("deny", "tool")
    # §2.1: no key beyond the documented ones — nothing else can leak into the document.
    assert all(set(h) == ENTRY_KEYS for h in chain)


def test_the_function_does_not_mutate_the_parent_chain() -> None:
    parent = parent_of(HOP1)
    before = [dict(h) for h in parent.chain or []]
    extend(parent, HOP2)
    assert parent.chain == before
