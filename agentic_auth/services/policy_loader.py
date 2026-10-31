"""Load a pinned compiled policy and index it for O(1) runtime lookups.

Two things matter here. First, the index is built once per ``(scope, version)`` and cached
— the PDP is on a 15 ms per-hop budget and cannot afford to scan lists. Second, a policy
compiled before the runtime plane existed is **refused**, not guessed at: v1 flattened
tools across the whole closure, so "may this agent call this target" has no answer in it,
and inventing one would be exactly the silent-pass failure this product exists to prevent.
"""

from __future__ import annotations

import contextlib
import fnmatch
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agentic_auth.errors import NotFoundError, PolicyRecompileRequired
from agentic_auth.schemas.manifest import MAX_HOP_BUDGET

# The index half of this module is pure and is what the drift check imports, from an install
# with no database driver or Redis client. Only `load` and `latest_version` touch storage, so
# their dependencies are imported there (tests/packaging/test_import_boundaries.py).
if TYPE_CHECKING:
    from redis.asyncio import Redis
    from sqlalchemy.ext.asyncio import AsyncSession

    from agentic_auth.services.dag_compiler import CompiledScope

REQUIRED_DAG_SCHEMA_VERSION = 2


def _key(scope: str, version: int) -> str:
    return f"policy:{scope}:{version}"


def _agent_name(uri: str) -> str:
    return uri.removeprefix("agent://")


@dataclass(frozen=True)
class PolicyIndex:
    """A compiled policy, arranged for the questions the PDP actually asks."""

    scope: str
    version: int
    hop_budget: int
    # agent -> the tool refs that agent itself declared
    tools_by_agent: dict[str, set[str]] = field(default_factory=dict)
    # agent -> the data classes that agent declared (reads | writes)
    data_classes_by_agent: dict[str, set[str]] = field(default_factory=dict)
    # (from, to) -> the edge's own declared cap
    edges: dict[tuple[str, str], int] = field(default_factory=dict)
    # a delegation path of agent names -> its effective (running-minimum) hop budget
    path_budgets: dict[tuple[str, ...], int] = field(default_factory=dict)
    agents: frozenset[str] = frozenset()
    # -- Phase 4 ---------------------------------------------
    # agent -> the tool refs it declared privileged
    privileged_tools_by_agent: dict[str, set[str]] = field(default_factory=dict)
    # (agent, tool ref) -> RFC 6901 pointers, or None for "whole body binds"
    binding_by_tool: dict[tuple[str, str], list[str] | None] = field(default_factory=dict)
    # agent -> globs over target refs it trusts (materialized defaults included)
    trusted_sources_by_agent: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # agent -> "privileged" | target glob | data-class glob a tainted context may not call
    protected_by_agent: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def declares_tool(self, agent: str, tool_ref: str) -> bool:
        return tool_ref in self.tools_by_agent.get(agent, ())

    def declares_data_class(self, agent: str, data_class: str) -> bool:
        return data_class in self.data_classes_by_agent.get(agent, ())

    def has_edge(self, caller: str, target: str) -> bool:
        return (caller, target) in self.edges

    # -- Phase 4 predicates -------------------------------------------------------

    def is_privileged(self, agent: str, tool_ref: str) -> bool:
        return tool_ref in self.privileged_tools_by_agent.get(agent, ())

    def binding_params(self, agent: str, tool_ref: str) -> list[str] | None:
        """The pointers that bind a privileged tool's parameters; ``None`` = whole body."""
        return self.binding_by_tool.get((agent, tool_ref))

    def is_trusted_source(self, agent: str, target: str) -> bool:
        """Is a result from ``target`` trusted_internal for ``agent``? Unmatched = untrusted."""
        return any(
            fnmatch.fnmatchcase(target, glob)
            for glob in self.trusted_sources_by_agent.get(agent, ())
        )

    def is_protected(self, agent: str, target: str, data_class: str) -> bool:
        """May a tainted ``agent`` NOT call ``target`` with ``data_class``?"""
        for rule in self.protected_by_agent.get(agent, ("privileged",)):
            if rule == "privileged":
                if self.is_privileged(agent, target):
                    return True
            elif fnmatch.fnmatchcase(target, rule) or fnmatch.fnmatchcase(data_class, rule):
                return True
        return False

    def budget_for_path(self, path: tuple[str, ...]) -> int:
        """The effective budget along a delegation path.

        The single-agent path is the root's own budget; anything else must have been
        compiled, and an uncompiled path has no budget to offer.
        """
        if len(path) <= 1:
            return self.hop_budget
        return self.path_budgets.get(path, 0)


def build_index(dag: dict, *, scope: str, version: int) -> PolicyIndex:
    schema_version = dag.get("dag_schema_version", 1)
    if schema_version < REQUIRED_DAG_SCHEMA_VERSION:
        raise PolicyRecompileRequired(
            f"scope {scope!r} was compiled before runtime enforcement; recompile required",
            {
                "scope": scope,
                "version": version,
                "dag_schema_version": schema_version,
                "required": REQUIRED_DAG_SCHEMA_VERSION,
                "remedy": "resubmit the manifest to compile a new policy version",
            },
        )

    nodes: dict[str, dict] = dag.get("nodes", {})
    tools_by_agent = {
        name: {t["ref"] for t in node.get("tools", [])} for name, node in nodes.items()
    }
    data_classes_by_agent = {
        name: set(node.get("data_classes", {}).get("reads", []))
        | set(node.get("data_classes", {}).get("writes", []))
        for name, node in nodes.items()
    }
    edges = {(e["from"], e["to"]): e["max_hop_depth"] for e in dag.get("edges", [])}
    path_budgets = {
        tuple(_agent_name(p) for p in entry["path"]): entry["effective_hop_budget"]
        for entry in dag.get("paths", [])
    }
    taint = _taint_fields(nodes, edges)

    return PolicyIndex(
        scope=scope,
        version=version,
        hop_budget=dag["hop_budget"],
        tools_by_agent=tools_by_agent,
        data_classes_by_agent=data_classes_by_agent,
        edges=edges,
        path_budgets=path_budgets,
        agents=frozenset(nodes),
        **taint,
    )


def _taint_fields(nodes: Mapping[str, dict], edges: Mapping[tuple[str, str], int]) -> dict:
    """The Phase 4 index fields, with the documented defaults for a v2 policy: a node without
    a ``taint_policy`` trusts its declared downstream agents and protects its privileged
    tools; a tool without ``binding_params`` binds the whole body."""
    privileged: dict[str, set[str]] = {}
    binding: dict[tuple[str, str], list[str] | None] = {}
    trusted: dict[str, tuple[str, ...]] = {}
    protected: dict[str, tuple[str, ...]] = {}
    for name, node in nodes.items():
        privileged[name] = {t["ref"] for t in node.get("tools", []) if t.get("privileged")}
        for t in node.get("tools", []):
            if t.get("privileged"):
                pointers = t.get("binding_params")
                binding[(name, t["ref"])] = list(pointers) if pointers else None
        policy = node.get("taint_policy")
        if policy is None:
            downstream = tuple(f"agent://{to}" for (frm, to) in edges if frm == name)
            trusted[name] = downstream
            protected[name] = ("privileged",)
        else:
            trusted[name] = tuple(policy.get("trusted_sources", ()))
            protected[name] = tuple(policy.get("block_tainted_into", ("privileged",)))
    return {
        "privileged_tools_by_agent": privileged,
        "binding_by_tool": binding,
        "trusted_sources_by_agent": trusted,
        "protected_by_agent": protected,
    }


GRAPH_SCOPE = "*"


def build_graph_index(compiled: Mapping[str, CompiledScope]) -> PolicyIndex:
    """One index over every agent in a set of compiled scopes — for the offline drift check.

    A runtime index answers for one consented scope and holds only what is reachable from
    it. The drift check asks a wider question — is this edge declared *anywhere* in the
    supplied manifests — so it unions every scope's per-agent ``nodes`` and ``edges``. The
    predicates on :class:`PolicyIndex` are unchanged, which is what keeps the CI verdict and
    the runtime verdict the same function. Path budgets are not merged:
    budgets are a runtime property of a route, not an edge, and the drift check does not
    report them.
    """
    tools_by_agent: dict[str, set[str]] = {}
    data_classes_by_agent: dict[str, set[str]] = {}
    edges: dict[tuple[str, str], int] = {}
    for scope in compiled.values():
        for name, node in scope.nodes.items():
            tools_by_agent[name] = {t["ref"] for t in node.get("tools", [])}
            data_classes_by_agent[name] = set(node.get("data_classes", {}).get("reads", [])) | set(
                node.get("data_classes", {}).get("writes", [])
            )
        for edge in scope.edges:
            edges[(edge["from"], edge["to"])] = edge["max_hop_depth"]

    all_nodes: dict[str, dict] = {}
    for scope in compiled.values():
        all_nodes.update(scope.nodes)
    return PolicyIndex(
        scope=GRAPH_SCOPE,
        version=0,
        hop_budget=MAX_HOP_BUDGET,
        tools_by_agent=tools_by_agent,
        data_classes_by_agent=data_classes_by_agent,
        edges=edges,
        path_budgets={},
        agents=frozenset(tools_by_agent),
        **_taint_fields(all_nodes, edges),
    )


async def load(db: AsyncSession, redis: Redis | None, scope: str, version: int) -> PolicyIndex:
    """Load a pinned policy. Redis is a cache only — losing it costs latency, never
    correctness, and never turns a deny into an allow."""
    from agentic_auth.repositories import compiled_policies as policies_repo

    if redis is not None:
        with contextlib.suppress(Exception):
            cached = await redis.get(_key(scope, version))
            if cached is not None:
                return build_index(json.loads(cached), scope=scope, version=version)

    row = await policies_repo.get_version(db, scope, version)
    if row is None:
        raise NotFoundError(f"no compiled policy for scope {scope!r} version {version}")

    index = build_index(row.dag, scope=scope, version=version)
    if redis is not None:
        # Immutable per (scope, version), so there is no TTL and nothing to invalidate.
        with contextlib.suppress(Exception):
            await redis.set(_key(scope, version), json.dumps(row.dag))
    return index


async def latest_version(db: AsyncSession, scope: str) -> int | None:
    from agentic_auth.repositories import compiled_policies as policies_repo

    return await policies_repo.latest_version_number(db, scope)
