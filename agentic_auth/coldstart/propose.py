"""From an observation run to a manifest candidate — pure (FR-034, FR-035, FR-041).

Takes Phase 3's :class:`~agentic_auth.schemas.edge_trace.EdgeTrace` and folds it into an
``AgentManifest`` document. No I/O, no clock, no database: everything it needs is in the
trace, which is what lets the whole generator be tested as a table.

Two rules it must not break.

**Nothing that was not observed appears in the proposal.** A generator that helpfully
rounded up — adding the sibling tool, the obvious data class — would be writing policy
nobody watched the agent need, and the human ratifying it would have no way to tell
which entries were evidence and which were guesswork. Every entry is recorded under
``x-proposal.observed`` for exactly that reason (FR-039).

**A run that saw nothing produces a proposal that says so.** An empty manifest and "we
observed no behaviour" look identical in the document and mean completely different
things; ``covers_no_behaviour`` is what tells them apart (FR-041).

``recorder_errors`` is carried through untouched. Phase 3 made lost evidence visible
rather than letting a trace silently shrink, and a proposal derived from an incomplete
trace has to inherit that warning — otherwise observation gaps become under-declared
manifests, which fail closed at runtime and look like policy bugs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentic_auth.schemas.edge_trace import EdgeTrace, ObservedEdge

API_VERSION = "agentic-auth/v1"
KIND = "AgentManifest"

AGENT_PREFIX = "agent://"
#: ``EdgeTrace`` calls an agent-to-agent edge a delegation, not an "agent" edge.
DELEGATION = "delegation"

#: Floor for an inferred budget. A one-hop run should not pin a manifest that cannot
#: delegate at all — the budget is inferred from evidence, and absence of evidence for
#: depth is not evidence of a depth limit.
MIN_HOP_BUDGET = 1


@dataclass(frozen=True)
class Observed:
    """Exactly what the run saw, and nothing else."""

    tools: tuple[str, ...] = ()
    data_classes: tuple[str, ...] = ()
    downstream_agents: tuple[str, ...] = ()
    deepest_chain: int = MIN_HOP_BUDGET
    recorder_errors: int = 0

    @property
    def empty(self) -> bool:
        return not (self.tools or self.data_classes or self.downstream_agents)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tools": list(self.tools),
            "data_classes": list(self.data_classes),
            "downstream_agents": list(self.downstream_agents),
        }


def observe(
    trace: EdgeTrace, agent: str, *, data_classes: dict[str, str] | None = None
) -> Observed:
    """What ``agent`` was seen to do in this run.

    ``data_classes`` maps a target ref to the data class the call used, which the edge
    trace does not carry — it records edges, not classes. The sandbox supplies it from
    the calls it recorded; without it the proposal declares tools with no classes, which
    would not reconcile, so the sandbox always passes it.
    """
    mapping = data_classes or {}
    tools: set[str] = set()
    downstream: set[str] = set()

    for edge in trace.edges:
        if edge.from_ != agent:
            continue
        if edge.kind == DELEGATION:
            downstream.add(edge.to)
        else:
            tools.add(edge.to)

    classes = {mapping[ref] for ref in tools if ref in mapping}
    return Observed(
        tools=tuple(sorted(tools)),
        data_classes=tuple(sorted(classes)),
        downstream_agents=tuple(sorted(downstream)),
        deepest_chain=_deepest_chain(trace.edges, agent),
        recorder_errors=trace.recorder_errors,
    )


def _deepest_chain(edges: list[ObservedEdge], root: str) -> int:
    """The longest delegation path observed, following agent edges only (FR-035).

    Cycle-safe: an agent that delegated back to one already on the path stops that
    branch rather than recursing forever. A cyclic observation is not a reason to hang,
    and the compiler refuses cycles anyway.
    """
    graph: dict[str, set[str]] = {}
    for edge in edges:
        if edge.kind == DELEGATION:
            graph.setdefault(edge.from_, set()).add(edge.to.removeprefix(AGENT_PREFIX))

    def walk(node: str, seen: frozenset[str]) -> int:
        best = 1
        for nxt in graph.get(node, ()):
            if nxt in seen:
                continue
            best = max(best, 1 + walk(nxt, seen | {nxt}))
        return best

    return max(MIN_HOP_BUDGET, walk(root, frozenset({root})))


def propose(
    trace: EdgeTrace,
    agent: str,
    *,
    run_id: str,
    data_classes: dict[str, str] | None = None,
    privileged: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """The proposal document: an ordinary manifest plus an ``x-proposal`` block.

    The manifest half is what the compiler will read if a human ratifies it. The
    ``x-proposal`` half is provenance: which entries came from observation, how deep the
    deepest chain went, and whether the run saw anything at all. The compiler ignores it
    (it reads ``spec`` only), and ratification keeps it so "observed" and
    "administrator-added" stay distinguishable forever (FR-039).
    """
    seen = observe(trace, agent, data_classes=data_classes)
    mapping = data_classes or {}

    tools = [
        {
            "ref": ref,
            "data_classes": [mapping[ref]] if ref in mapping else [],
            "privileged": ref in privileged,
        }
        for ref in seen.tools
    ]

    return {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {"agent": agent},
        "spec": {
            "tools": tools,
            "data_classes": {"reads": list(seen.data_classes), "writes": []},
            "downstream_agents": [
                {"ref": ref, "max_hop_depth": seen.deepest_chain} for ref in seen.downstream_agents
            ],
            "hop_budget": seen.deepest_chain,
        },
        "x-proposal": {
            "run_id": run_id,
            "observed": seen.as_dict(),
            "deepest_chain": seen.deepest_chain,
            "recorder_errors": seen.recorder_errors,
            # FR-041. An empty manifest and "we watched and saw nothing" look identical
            # in the document and mean completely different things.
            "covers_no_behaviour": seen.empty,
        },
    }


def added_by_administrator(document: dict[str, Any]) -> dict[str, list[str]]:
    """What is in the ``spec`` that the run never observed (FR-039).

    Editing a proposal before ratifying it is allowed and often right — a human knows
    things the run did not show. What must not happen is losing track of which is which,
    because "a machine watched the agent do this" and "a person thought this was
    probably needed" are very different kinds of evidence.
    """
    proposal = document.get("x-proposal") or {}
    observed = proposal.get("observed") or {}
    spec = document.get("spec") or {}

    spec_tools = {t.get("ref") for t in spec.get("tools", [])}
    spec_downstream = {d.get("ref") for d in spec.get("downstream_agents", [])}
    spec_classes = set(spec.get("data_classes", {}).get("reads", [])) | set(
        spec.get("data_classes", {}).get("writes", [])
    )

    return {
        "tools": sorted(spec_tools - set(observed.get("tools", []))),
        "data_classes": sorted(spec_classes - set(observed.get("data_classes", []))),
        "downstream_agents": sorted(spec_downstream - set(observed.get("downstream_agents", []))),
    }


def was_edited(document: dict[str, Any]) -> bool:
    """True when a human changed the proposal before ratifying it. Reported as a metric:
    a high rate means the generator is missing things people keep having to add."""
    return any(added_by_administrator(document).values())


__all__ = [
    "MIN_HOP_BUDGET",
    "Observed",
    "added_by_administrator",
    "observe",
    "propose",
    "was_edited",
]
