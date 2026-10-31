"""Trace to manifest candidate (US6, T093; FR-034, FR-035, FR-039, FR-041).

Pure, so this is a table rather than a fixture set. The two rules that matter most:
nothing unobserved appears in the proposal, and a run that saw nothing says so instead
of looking like an empty manifest.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agentic_auth.coldstart.propose import (
    MIN_HOP_BUDGET,
    added_by_administrator,
    observe,
    propose,
    was_edited,
)
from agentic_auth.schemas.edge_trace import EdgeTrace

AGENT = "new-agent"
KB = "mcp://kb.internal/search"
BALANCE = "mcp://accounts.internal/read_balance"
TERMINATE = "mcp://accounts.internal/terminate_account"

CLASSES = {KB: "kb.internal", BALANCE: "account.read", TERMINATE: "account.write"}


def _edge(frm: str, to: str, *, allow: int = 1) -> dict:
    kind = "delegation" if to.startswith("agent://") else "tool"
    return {
        "from": frm,
        "to": to,
        "kind": kind,
        "count": allow,
        "outcomes": {"allow": allow, "deny": 0, "observed": 0},
    }


def _trace(*edges: dict, recorder_errors: int = 0) -> EdgeTrace:
    now = datetime.now(UTC)
    return EdgeTrace.model_validate(
        {
            "schema_version": 1,
            "run": {
                "started_at": now.isoformat(),
                "finished_at": now.isoformat(),
                "command": ["pytest"],
                "event_files": ["events.jsonl"],
                "exit_code": 0,
            },
            "edges": list(edges),
            "unattributed": {"count": 0, "by_reason": {}},
            "recorder_errors": recorder_errors,
            "events_total": sum(e["count"] for e in edges),
        }
    )


# -- only what was observed (FR-034) ---------------------------------------------------


def test_the_proposal_lists_every_tool_the_run_invoked() -> None:
    trace = _trace(_edge(AGENT, KB), _edge(AGENT, BALANCE))

    doc = propose(trace, AGENT, run_id="r1", data_classes=CLASSES)

    assert sorted(t["ref"] for t in doc["spec"]["tools"]) == sorted([BALANCE, KB])


def test_the_proposal_lists_nothing_the_run_did_not_invoke() -> None:
    """A generator that rounded up would be writing policy nobody watched the agent
    need, and the human ratifying it could not tell which was which."""
    trace = _trace(_edge(AGENT, KB))

    doc = propose(trace, AGENT, run_id="r1", data_classes=CLASSES)

    refs = {t["ref"] for t in doc["spec"]["tools"]}
    assert TERMINATE not in refs
    assert BALANCE not in refs


def test_another_agents_calls_are_not_attributed_to_this_one() -> None:
    trace = _trace(_edge(AGENT, KB), _edge("someone-else", TERMINATE))

    doc = propose(trace, AGENT, run_id="r1", data_classes=CLASSES)

    assert [t["ref"] for t in doc["spec"]["tools"]] == [KB]


def test_data_classes_come_from_the_calls_that_used_them() -> None:
    trace = _trace(_edge(AGENT, KB), _edge(AGENT, BALANCE))

    doc = propose(trace, AGENT, run_id="r1", data_classes=CLASSES)

    assert doc["spec"]["data_classes"]["reads"] == ["account.read", "kb.internal"]


def test_delegation_edges_become_downstream_agents() -> None:
    trace = _trace(_edge(AGENT, "agent://helper"))

    doc = propose(trace, AGENT, run_id="r1", data_classes=CLASSES)

    assert [d["ref"] for d in doc["spec"]["downstream_agents"]] == ["agent://helper"]


# -- the inferred budget (FR-035) -------------------------------------------------------


def test_a_flat_run_infers_the_minimum_budget() -> None:
    trace = _trace(_edge(AGENT, KB))

    assert propose(trace, AGENT, run_id="r1")["spec"]["hop_budget"] == MIN_HOP_BUDGET


def test_the_budget_follows_the_deepest_observed_chain() -> None:
    trace = _trace(
        _edge(AGENT, "agent://b"),
        _edge("b", "agent://c"),
        _edge("c", KB),
    )

    assert propose(trace, AGENT, run_id="r1")["spec"]["hop_budget"] == 3


def test_a_cyclic_observation_does_not_hang() -> None:
    """The compiler refuses cycles anyway, but a generator that recursed forever on one
    would take the whole run down rather than producing a reviewable proposal."""
    trace = _trace(_edge(AGENT, "agent://b"), _edge("b", f"agent://{AGENT}"))

    assert propose(trace, AGENT, run_id="r1")["spec"]["hop_budget"] >= 2


# -- a run that saw nothing (FR-041) -----------------------------------------------------


def test_an_empty_run_is_marked_rather_than_looking_complete() -> None:
    """An empty manifest and "we watched and saw nothing" are identical documents and
    completely different facts."""
    doc = propose(_trace(), AGENT, run_id="r1")

    assert doc["x-proposal"]["covers_no_behaviour"] is True
    assert doc["spec"]["tools"] == []


def test_a_run_that_saw_something_is_not_marked() -> None:
    doc = propose(_trace(_edge(AGENT, KB)), AGENT, run_id="r1", data_classes=CLASSES)

    assert doc["x-proposal"]["covers_no_behaviour"] is False


# -- provenance carries through (FR-039) ---------------------------------------------------


def test_the_proposal_records_what_was_observed() -> None:
    trace = _trace(_edge(AGENT, KB), _edge(AGENT, "agent://helper"))

    block = propose(trace, AGENT, run_id="run-7", data_classes=CLASSES)["x-proposal"]

    assert block["run_id"] == "run-7"
    assert block["observed"]["tools"] == [KB]
    assert block["observed"]["downstream_agents"] == ["agent://helper"]


def test_an_unedited_proposal_has_nothing_administrator_added() -> None:
    doc = propose(_trace(_edge(AGENT, KB)), AGENT, run_id="r1", data_classes=CLASSES)

    assert added_by_administrator(doc) == {
        "tools": [],
        "data_classes": [],
        "downstream_agents": [],
    }
    assert was_edited(doc) is False


def test_an_administrator_addition_is_distinguishable_from_evidence() -> None:
    """ "A machine watched the agent do this" and "a person thought it was probably
    needed" are very different kinds of evidence, and the record keeps them apart."""
    doc = propose(_trace(_edge(AGENT, KB)), AGENT, run_id="r1", data_classes=CLASSES)
    doc["spec"]["tools"].append(
        {"ref": TERMINATE, "data_classes": ["account.write"], "privileged": True}
    )
    doc["spec"]["data_classes"]["writes"] = ["account.write"]

    added = added_by_administrator(doc)

    assert added["tools"] == [TERMINATE]
    assert added["data_classes"] == ["account.write"]
    assert was_edited(doc) is True


# -- incomplete observation is inherited, not hidden ----------------------------------------


def test_recorder_errors_are_carried_into_the_proposal() -> None:
    """Phase 3 made lost evidence visible rather than letting a trace silently shrink.
    A proposal built on an incomplete trace has to inherit that warning, or observation
    gaps become under-declared manifests that fail closed and look like policy bugs."""
    trace = _trace(_edge(AGENT, KB), recorder_errors=3)

    assert propose(trace, AGENT, run_id="r1")["x-proposal"]["recorder_errors"] == 3


# -- the document is an ordinary manifest ---------------------------------------------------


def test_the_proposal_is_shaped_like_a_manifest() -> None:
    """The compiler reads `spec` and ignores `x-proposal`, so ratification needs no
    translation step that could drift from what the administrator approved."""
    doc = propose(_trace(_edge(AGENT, KB)), AGENT, run_id="r1", data_classes=CLASSES)

    assert doc["apiVersion"] == "agentic-auth/v1"
    assert doc["kind"] == "AgentManifest"
    assert doc["metadata"]["agent"] == AGENT
    assert set(doc["spec"]) == {"tools", "data_classes", "downstream_agents", "hop_budget"}


def test_a_privileged_tool_is_marked_when_the_caller_says_so() -> None:
    """Privilege is the resource owner's declaration, not something observation can
    infer: a call that succeeded tells you nothing about whether it was destructive."""
    trace = _trace(_edge(AGENT, TERMINATE))

    doc = propose(
        trace, AGENT, run_id="r1", data_classes=CLASSES, privileged=frozenset({TERMINATE})
    )

    assert doc["spec"]["tools"][0]["privileged"] is True


def test_observe_returns_the_same_facts_the_document_carries() -> None:
    trace = _trace(_edge(AGENT, KB), _edge(AGENT, "agent://helper"))

    seen = observe(trace, AGENT, data_classes=CLASSES)

    assert seen.tools == (KB,)
    assert seen.downstream_agents == ("agent://helper",)
    assert seen.empty is False
