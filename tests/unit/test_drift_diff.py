"""``diff`` — judging observed edges against declared manifests, purely."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agentic_auth.schemas.edge_trace import (
    DriftInputs,
    EdgeOutcomes,
    EdgeTrace,
    ObservedEdge,
    TraceRun,
    Unattributed,
)
from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.services.drift import declared_graph, diff
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    FRAUD_AGENT,
    KB_SEARCH_TOOL,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    bank_docs,
)

NOW = datetime(2026, 9, 13, 10, 0, tzinfo=UTC)
PATHS = {
    BANK_ASSISTANT: "manifests/bank-assistant.yaml",
    BALANCE_AGENT: "manifests/balance-agent.yaml",
    SUPPORT_AGENT: "manifests/support-agent.yaml",
    FRAUD_AGENT: "manifests/fraud-agent.yaml",
}
INPUTS = DriftInputs(
    manifest_dirs=["manifests"], trace="edge-trace.json", manifests_loaded=4, skipped_files=[]
)


def edge(
    caller: str, target: str, *, allow: int = 0, deny: int = 0, observed: int = 0
) -> ObservedEdge:
    return ObservedEdge(
        from_=caller,
        to=target,
        kind="delegation" if target.startswith("agent://") else "tool",
        count=allow + deny + observed,
        outcomes=EdgeOutcomes(allow=allow, deny=deny, observed=observed),
    )


def trace(
    *edges: ObservedEdge, unattributed: Unattributed | None = None, recorder_errors: int = 0
) -> EdgeTrace:
    return EdgeTrace(
        run=TraceRun(started_at=NOW, finished_at=NOW, command=None, event_files=[], exit_code=0),
        edges=list(edges),
        unattributed=unattributed or Unattributed(),
        recorder_errors=recorder_errors,
        events_total=sum(e.count for e in edges),
    )


def graph_for(**options):
    docs = bank_docs(include_fraud_agent=True, **options)
    return declared_graph({name: AgentManifest.model_validate(doc) for name, doc in docs.items()})


@pytest.fixture(scope="module")
def graph():
    return graph_for()


CLEAN = (
    edge(BANK_ASSISTANT, f"agent://{BALANCE_AGENT}", allow=1),
    edge(BALANCE_AGENT, f"agent://{SUPPORT_AGENT}", allow=1),
    edge(SUPPORT_AGENT, KB_SEARCH_TOOL, allow=1),
)


def test_a_compliant_run_passes(graph) -> None:
    report = diff(trace(*CLEAN), graph, PATHS, inputs=INPUTS)

    assert report.result == "pass"
    assert report.undeclared == []
    assert report.errors == []
    assert report.summary.model_dump() == {
        "edges_observed": 3,
        "edges_declared": 3,
        "edges_undeclared": 0,
        "calls_observed": 3,
        "unattributed_calls": 0,
    }


def test_an_undeclared_tool_is_reported_with_its_consequence_and_fix(graph) -> None:
    report = diff(
        trace(*CLEAN[:2], edge(SUPPORT_AGENT, TERMINATE_ACCOUNT, observed=3)),
        graph,
        PATHS,
        inputs=INPUTS,
    )

    assert report.result == "drift"
    [finding] = report.undeclared
    assert (finding.from_, finding.to, finding.kind) == (SUPPORT_AGENT, TERMINATE_ACCOUNT, "tool")
    assert finding.count == 3
    assert finding.verdict == "UNDECLARED_TOOL"
    assert finding.runtime_reason == "OUT_OF_SCOPE"
    assert finding.manifest_path == PATHS[SUPPORT_AGENT]
    # The fix advice must name what to change and where: the agent, the exact tool, the field
    # and the file. A hint missing any of them sends a developer looking.
    for expected in (SUPPORT_AGENT, TERMINATE_ACCOUNT, "spec.tools", PATHS[SUPPORT_AGENT]):
        assert expected in finding.hint, f"hint does not name {expected!r}: {finding.hint}"


def test_an_undeclared_delegation_is_reported(graph) -> None:
    report = diff(
        trace(CLEAN[0], edge(BALANCE_AGENT, f"agent://{FRAUD_AGENT}", observed=1)),
        graph,
        PATHS,
        inputs=INPUTS,
    )

    [finding] = report.undeclared
    assert finding.verdict == "UNDECLARED_DELEGATION"
    assert finding.runtime_reason == "EDGE_NOT_IN_DAG"
    assert finding.kind == "delegation"
    for expected in (BALANCE_AGENT, f"agent://{FRAUD_AGENT}", "spec.downstream_agents"):
        assert expected in finding.hint, f"hint does not name {expected!r}: {finding.hint}"


def test_an_unknown_agent_is_reported_without_a_manifest(graph) -> None:
    report = diff(
        trace(*CLEAN, edge("ghost", KB_SEARCH_TOOL, observed=1)), graph, PATHS, inputs=INPUTS
    )

    [finding] = report.undeclared
    assert finding.verdict == "UNKNOWN_AGENT"
    assert finding.manifest_path is None
    assert "ghost" in finding.hint


def test_every_undeclared_edge_is_reported_once_in_a_stable_order(graph) -> None:
    offenders = (
        edge(SUPPORT_AGENT, TERMINATE_ACCOUNT, observed=1),
        edge(BALANCE_AGENT, f"agent://{FRAUD_AGENT}", observed=2),
        edge(BANK_ASSISTANT, TERMINATE_ACCOUNT, deny=1),
    )

    forward = diff(trace(*CLEAN, *offenders), graph, PATHS, inputs=INPUTS)
    backward = diff(trace(*reversed(offenders), *reversed(CLEAN)), graph, PATHS, inputs=INPUTS)

    assert [(u.from_, u.to) for u in forward.undeclared] == [
        (BALANCE_AGENT, f"agent://{FRAUD_AGENT}"),
        (BANK_ASSISTANT, TERMINATE_ACCOUNT),
        (SUPPORT_AGENT, TERMINATE_ACCOUNT),
    ]
    assert forward.model_dump() == backward.model_dump()  # deterministic regardless of input order


def test_a_run_with_no_edges_is_an_error_not_a_pass(graph) -> None:
    report = diff(trace(), graph, PATHS, inputs=INPUTS)
    assert report.result == "error"
    assert [e.code for e in report.errors] == ["NO_EDGES_OBSERVED"]


def test_lost_events_are_an_error_even_when_every_edge_is_declared(graph) -> None:
    report = diff(trace(*CLEAN, recorder_errors=1), graph, PATHS, inputs=INPUTS)
    assert report.result == "error"
    assert [e.code for e in report.errors] == ["TRACE_RECORDER_ERRORS"]


def test_unattributed_calls_warn_without_failing(graph) -> None:
    report = diff(
        trace(*CLEAN, unattributed=Unattributed(count=2, by_reason={"UPSTREAM_NOT_MAPPED": 2})),
        graph,
        PATHS,
        inputs=INPUTS,
    )
    assert report.result == "pass"
    [warning] = report.warnings
    assert warning.code == "UNATTRIBUTED_CALLS"
    assert "UPSTREAM_NOT_MAPPED: 2" in warning.message


def test_widening_the_manifest_turns_drift_into_a_pass() -> None:
    drifted = trace(*CLEAN[:2], edge(SUPPORT_AGENT, TERMINATE_ACCOUNT, observed=1))
    assert diff(drifted, graph_for(), PATHS, inputs=INPUTS).result == "drift"
    assert diff(drifted, graph_for(widened=True), PATHS, inputs=INPUTS).result == "pass"
