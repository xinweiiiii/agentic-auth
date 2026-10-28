"""Compose reconciled manifests into a versioned scope→capability DAG.

- downstream-agent edges are resolved transitively
- the effective hop budget on any path is the minimum declared along it
  (agent ``hop_budget`` values and edge ``max_hop_depth`` values)
- data classes for a multi-parent agent are the union across paths
- delegation cycles are rejected
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.errors import DagCycleError
from app.schemas.manifest import AgentManifest


def _agent_name(uri: str) -> str:
    return uri.removeprefix("agent://")


# Bumped when the compiled-DAG JSONB shape changes. The runtime PDP requires >= 2:
# v1 flattened `tools` across the whole closure, so it cannot answer "may THIS agent
# call THIS target" or "is B->C a declared edge". v1 policies must be recompiled.
#
# v3 (Phase 4) is additive: each node carries `taint_policy` (with `trusted_sources`
# materialized to the declared downstream agents when the manifest omits it) and each tool
# entry carries `binding_params`. A v2 policy still loads, with the documented defaults.
DAG_SCHEMA_VERSION = 3


@dataclass
class CompiledScope:
    scope: str
    tools: list[dict]
    data_classes: dict[str, list[str]]
    downstream_agents: list[str]
    hop_budget: int
    paths: list[dict]
    unresolved_downstream: list[str] = field(default_factory=list)
    source_agents: list[str] = field(default_factory=list)
    # v2: per-agent capability, keyed by agent name. `tools` above stays the
    # flattened union (the human-readable scope catalog reads it).
    nodes: dict[str, dict] = field(default_factory=dict)
    # v2: the direct declared delegation edges inside this closure.
    edges: list[dict] = field(default_factory=list)

    def to_dag(self) -> dict:
        return {
            "dag_schema_version": DAG_SCHEMA_VERSION,
            "scope": self.scope,
            "tools": self.tools,
            "data_classes": self.data_classes,
            "downstream_agents": self.downstream_agents,
            "hop_budget": self.hop_budget,
            "paths": self.paths,
            "unresolved_downstream": self.unresolved_downstream,
            "source_agents": self.source_agents,
            "nodes": self.nodes,
            "edges": self.edges,
        }


class DagCompiler:
    # `mutmut run` leaves 10 equivalent mutants here: the unused sentinel value of
    # BLACK, the `edges.get(node, [])` fallbacks (every node is always a key), and the
    # defensive `if nxt in path` branch (unreachable once `_reject_cycles` has run).
    def compile(self, manifests: dict[str, AgentManifest]) -> dict[str, CompiledScope]:
        edges: dict[str, list[tuple[str, int]]] = {}
        for name, m in manifests.items():
            edges[name] = [(_agent_name(d.ref), d.max_hop_depth) for d in m.spec.downstream_agents]

        self._reject_cycles(edges)

        return {name: self._compile_scope(name, manifests, edges) for name in manifests}

    # -- cycle detection ---------------------------------------------------

    def _reject_cycles(self, edges: dict[str, list[tuple[str, int]]]) -> None:
        WHITE, GREY, BLACK = 0, 1, 2
        color = dict.fromkeys(edges, WHITE)
        stack: list[str] = []

        def visit(node: str) -> None:
            color[node] = GREY
            stack.append(node)
            for nxt, _ in edges.get(node, []):
                if nxt not in color:  # unresolved downstream — not a cycle risk here
                    continue
                if color[nxt] == GREY:
                    cycle = stack[stack.index(nxt) :] + [nxt]
                    raise DagCycleError(
                        "delegation cycle detected: " + " -> ".join(cycle),
                        {"cycle": cycle},
                    )
                if color[nxt] == WHITE:
                    visit(nxt)
            stack.pop()
            color[node] = BLACK

        for node in edges:
            if color[node] == WHITE:
                visit(node)

    # -- per-scope closure ------------------------------------------------

    def _compile_scope(
        self,
        root: str,
        manifests: dict[str, AgentManifest],
        edges: dict[str, list[tuple[str, int]]],
    ) -> CompiledScope:
        root_manifest = manifests[root]
        reachable: set[str] = set()
        unresolved: set[str] = set()
        paths: list[dict] = []

        def walk(node: str, path: list[str], budget: int) -> None:
            reachable.add(node)
            node_budget = min(budget, manifests[node].spec.hop_budget)
            for nxt, edge_cap in edges.get(node, []):
                if nxt not in manifests:
                    unresolved.add(nxt)
                    continue
                if nxt in path:  # already guarded by cycle check; defensive
                    continue
                next_budget = min(node_budget, edge_cap)
                new_path = [*path, nxt]
                paths.append(
                    {
                        "path": [f"agent://{p}" for p in new_path],
                        "effective_hop_budget": next_budget,
                    }
                )
                walk(nxt, new_path, next_budget)

        walk(root, [root], root_manifest.spec.hop_budget)

        tools: dict[str, dict] = {}
        reads: set[str] = set()
        writes: set[str] = set()
        nodes: dict[str, dict] = {}
        edge_list: list[dict] = []
        for name in sorted(reachable):
            m = manifests[name]
            node_tools: list[dict] = [
                {
                    "ref": t.ref,
                    "data_classes": sorted(t.data_classes),
                    "privileged": t.privileged,
                    # v3: None = whole body binds (Phase 4, contracts/canonicalization.md §2)
                    "binding_params": list(t.binding_params) if t.binding_params else None,
                }
                for t in sorted(m.spec.tools, key=lambda t: t.ref)
            ]
            for node_tool in node_tools:
                tools[str(node_tool["ref"])] = node_tool
            reads.update(m.spec.data_classes.reads)
            writes.update(m.spec.data_classes.writes)

            policy = m.spec.taint_policy
            # The default is materialized here so the runtime never has to know it: an agent
            # that lists no trusted sources trusts exactly its declared downstream agents.
            trusted = (
                list(policy.trusted_sources)
                if policy.trusted_sources is not None
                else [d.ref for d in m.spec.downstream_agents]
            )
            nodes[name] = {
                "tools": node_tools,
                "data_classes": {
                    "reads": sorted(m.spec.data_classes.reads),
                    "writes": sorted(m.spec.data_classes.writes),
                },
                "hop_budget": m.spec.hop_budget,
                "taint_policy": {
                    "trusted_sources": trusted,
                    "block_tainted_into": list(policy.block_tainted_into),
                },
            }
            # Only edges whose target is registered and reachable are declared. An
            # unresolved downstream stays out, so delegating to it denies with
            # EDGE_NOT_IN_DAG rather than resolving against a node that isn't there.
            for nxt, edge_cap in edges.get(name, []):
                if nxt in reachable:
                    edge_list.append({"from": name, "to": nxt, "max_hop_depth": edge_cap})

        return CompiledScope(
            scope=root,
            tools=[tools[k] for k in sorted(tools)],
            data_classes={"reads": sorted(reads), "writes": sorted(writes)},
            downstream_agents=[d.ref for d in root_manifest.spec.downstream_agents],
            hop_budget=root_manifest.spec.hop_budget,
            paths=paths,
            unresolved_downstream=sorted(f"agent://{u}" for u in unresolved),
            source_agents=sorted(reachable),
            nodes=nodes,
            edges=edge_list,
        )
