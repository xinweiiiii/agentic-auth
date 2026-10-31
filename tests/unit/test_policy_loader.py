"""Loading and indexing a pinned compiled policy."""

from __future__ import annotations

import pytest

from agentic_auth.errors import PolicyRecompileRequired
from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.services.dag_compiler import DagCompiler
from agentic_auth.services.policy_loader import (
    REQUIRED_DAG_SCHEMA_VERSION,
    build_graph_index,
    build_index,
)


def _manifest(agent: str, *, hop_budget: int, downstream=None, reads=None, writes=None):
    return AgentManifest.model_validate(
        {
            "apiVersion": "agentic-auth/v1",
            "kind": "AgentManifest",
            "metadata": {"agent": agent},
            "spec": {
                "tools": [{"ref": f"mcp://{agent}.internal/do", "data_classes": [f"{agent}.read"]}],
                "data_classes": {"reads": reads or [f"{agent}.read"], "writes": writes or []},
                "downstream_agents": downstream or [],
                "hop_budget": hop_budget,
            },
        }
    )


def _dag() -> dict:
    manifests = {
        "orchestrator": _manifest(
            "orchestrator", hop_budget=4, downstream=[{"ref": "agent://a", "max_hop_depth": 3}]
        ),
        "a": _manifest("a", hop_budget=3, downstream=[{"ref": "agent://b", "max_hop_depth": 2}]),
        "b": _manifest("b", hop_budget=2),
    }
    return DagCompiler().compile(manifests)["orchestrator"].to_dag()


@pytest.fixture
def index():
    return build_index(_dag(), scope="orchestrator", version=7)


def test_v1_policy_is_refused_not_guessed_at() -> None:
    v1 = {k: v for k, v in _dag().items() if k not in ("dag_schema_version", "nodes", "edges")}
    with pytest.raises(PolicyRecompileRequired) as exc:
        build_index(v1, scope="orchestrator", version=3)

    details = exc.value.details
    assert details["scope"] == "orchestrator"
    assert details["version"] == 3
    assert details["dag_schema_version"] == 1
    assert details["required"] == REQUIRED_DAG_SCHEMA_VERSION
    assert "resubmit" in details["remedy"]


def test_tools_are_attributed_to_the_agent_that_declared_them(index) -> None:
    assert index.declares_tool("a", "mcp://a.internal/do")
    # the flattened v1 union would have said yes to this; v2 says no
    assert not index.declares_tool("a", "mcp://b.internal/do")
    assert not index.declares_tool("orchestrator", "mcp://b.internal/do")


def test_unknown_agent_declares_nothing(index) -> None:
    assert not index.declares_tool("ghost", "mcp://a.internal/do")
    assert not index.declares_data_class("ghost", "a.read")


def test_data_classes_union_reads_and_writes() -> None:
    manifests = {
        "solo": _manifest("solo", hop_budget=2, reads=["solo.read"], writes=["solo.write"])
    }
    idx = build_index(DagCompiler().compile(manifests)["solo"].to_dag(), scope="solo", version=1)
    assert idx.declares_data_class("solo", "solo.read")
    assert idx.declares_data_class("solo", "solo.write")
    assert not idx.declares_data_class("solo", "other")


def test_edges_are_directional(index) -> None:
    assert index.has_edge("orchestrator", "a")
    assert index.has_edge("a", "b")
    assert not index.has_edge("b", "a")  # reverse is not declared
    assert not index.has_edge("orchestrator", "b")  # transitive is not a direct edge


def test_path_budget_is_the_running_minimum(index) -> None:
    assert index.budget_for_path(("orchestrator",)) == 4
    assert index.budget_for_path(("orchestrator", "a")) == 3
    assert index.budget_for_path(("orchestrator", "a", "b")) == 2


def test_uncompiled_path_has_no_budget(index) -> None:
    """An undeclared route yields 0, so any hop along it exceeds its budget."""
    assert index.budget_for_path(("orchestrator", "b")) == 0
    assert index.budget_for_path(("orchestrator", "a", "b", "ghost")) == 0


def test_index_lists_the_closure(index) -> None:
    assert index.agents == frozenset({"orchestrator", "a", "b"})
    assert index.hop_budget == 4
    assert index.version == 7


def test_the_graph_index_spans_every_scope_for_the_drift_check() -> None:
    """Every agent in the supplied manifests, not just what one scope can reach."""
    manifests = {
        "orchestrator": _manifest(
            "orchestrator", hop_budget=4, downstream=[{"ref": "agent://a", "max_hop_depth": 3}]
        ),
        "a": _manifest("a", hop_budget=3, downstream=[{"ref": "agent://b", "max_hop_depth": 2}]),
        "b": _manifest("b", hop_budget=2),
        "solo": _manifest("solo", hop_budget=2),
        "dangling": _manifest(
            "dangling", hop_budget=2, downstream=[{"ref": "agent://missing", "max_hop_depth": 1}]
        ),
    }

    graph = build_graph_index(DagCompiler().compile(manifests))

    assert graph.agents == frozenset({"orchestrator", "a", "b", "solo", "dangling"})
    assert graph.declares_tool("solo", "mcp://solo.internal/do")  # reachable from no other scope
    assert graph.has_edge("orchestrator", "a") and graph.has_edge("a", "b")
    assert not graph.has_edge("dangling", "missing")  # an unregistered delegate is not declared


# -- Phase 4: privileged, binding, trusted sources, protected targets ------------------


def _v3_dag() -> dict:
    manifests = {
        "orchestrator": _manifest(
            "orchestrator", hop_budget=4, downstream=[{"ref": "agent://a", "max_hop_depth": 3}]
        ),
        "a": AgentManifest.model_validate(
            {
                "apiVersion": "agentic-auth/v1",
                "kind": "AgentManifest",
                "metadata": {"agent": "a"},
                "spec": {
                    "tools": [
                        {"ref": "mcp://kb.internal/search", "data_classes": ["kb.read"]},
                        {
                            "ref": "mcp://accounts.internal/terminate",
                            "data_classes": ["account.write"],
                            "privileged": True,
                            "binding_params": ["/account_id"],
                        },
                        {"ref": "mcp://ledger.internal/post", "data_classes": ["ledger.write"]},
                    ],
                    "data_classes": {
                        "reads": ["kb.read"],
                        "writes": ["account.write", "ledger.write"],
                    },
                    "downstream_agents": [],
                    "hop_budget": 3,
                    "taint_policy": {
                        "trusted_sources": ["mcp://accounts.internal/*"],
                        "block_tainted_into": ["privileged", "*.write"],
                    },
                },
            }
        ),
    }
    return DagCompiler().compile(manifests)["orchestrator"].to_dag()


@pytest.fixture
def v3():
    return build_index(_v3_dag(), scope="orchestrator", version=9)


def test_privileged_and_binding_are_per_agent_per_tool(v3) -> None:
    assert v3.is_privileged("a", "mcp://accounts.internal/terminate")
    assert not v3.is_privileged("a", "mcp://kb.internal/search")
    assert not v3.is_privileged("orchestrator", "mcp://accounts.internal/terminate")
    assert v3.binding_params("a", "mcp://accounts.internal/terminate") == ["/account_id"]
    assert v3.binding_params("a", "mcp://kb.internal/search") is None


def test_trusted_sources_are_globs_and_unmatched_is_untrusted(v3) -> None:
    assert v3.is_trusted_source("a", "mcp://accounts.internal/read_balance")
    assert not v3.is_trusted_source("a", "mcp://kb.internal/search")
    assert not v3.is_trusted_source("ghost", "mcp://accounts.internal/read_balance")


def test_default_trusted_sources_are_the_declared_downstream_agents(v3) -> None:
    assert v3.is_trusted_source("orchestrator", "agent://a")
    assert not v3.is_trusted_source("orchestrator", "agent://b")
    assert not v3.is_trusted_source("orchestrator", "mcp://kb.internal/search")


def test_protected_covers_privileged_and_data_class_globs(v3) -> None:
    assert v3.is_protected("a", "mcp://accounts.internal/terminate", "account.write")
    assert v3.is_protected("a", "mcp://ledger.internal/post", "ledger.write")  # *.write glob
    assert not v3.is_protected("a", "mcp://kb.internal/search", "kb.read")
    # orchestrator has the default policy: only its (non-existent) privileged tools
    assert not v3.is_protected("orchestrator", "mcp://ledger.internal/post", "ledger.write")


def test_a_v2_policy_loads_with_the_phase_4_defaults() -> None:
    """Strip v3 fields, stamp version 2: the runtime keeps working with documented defaults."""
    dag = _v3_dag()
    dag["dag_schema_version"] = 2
    for node in dag["nodes"].values():
        node.pop("taint_policy")
        for t in node["tools"]:
            t.pop("binding_params")
    idx = build_index(dag, scope="orchestrator", version=2)
    assert idx.is_privileged("a", "mcp://accounts.internal/terminate")
    assert idx.binding_params("a", "mcp://accounts.internal/terminate") is None  # whole body
    assert idx.is_trusted_source("orchestrator", "agent://a")  # downstream default
    assert not idx.is_trusted_source("a", "mcp://accounts.internal/read_balance")
    assert idx.is_protected("a", "mcp://accounts.internal/terminate", "account.write")
    assert not idx.is_protected("a", "mcp://ledger.internal/post", "ledger.write")
