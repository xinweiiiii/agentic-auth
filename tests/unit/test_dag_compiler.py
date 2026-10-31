"""DagCompiler — transitive budget, cycle rejection, data-class union."""

from __future__ import annotations

import pytest

from agentic_auth.errors import DagCycleError
from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.services.dag_compiler import DagCompiler


def _manifest(
    agent: str, *, hop_budget: int, tools=None, downstream=None, reads=None
) -> AgentManifest:
    return AgentManifest.model_validate(
        {
            "apiVersion": "agentic-auth/v1",
            "kind": "AgentManifest",
            "metadata": {"agent": agent},
            "spec": {
                "tools": tools
                or [{"ref": f"mcp://{agent}.internal/do", "data_classes": [f"{agent}.read"]}],
                "data_classes": {"reads": reads or [f"{agent}.read"], "writes": []},
                "downstream_agents": downstream or [],
                "hop_budget": hop_budget,
            },
        }
    )


def _chain() -> dict[str, AgentManifest]:
    return {
        "orchestrator": _manifest(
            "orchestrator",
            hop_budget=5,
            downstream=[{"ref": "agent://a", "max_hop_depth": 4}],
        ),
        "a": _manifest("a", hop_budget=4, downstream=[{"ref": "agent://b", "max_hop_depth": 2}]),
        "b": _manifest("b", hop_budget=3),
    }


def test_transitive_closure_and_min_hop_budget() -> None:
    compiled = DagCompiler().compile(_chain())
    root = compiled["orchestrator"]
    assert root.scope == "orchestrator"
    assert root.hop_budget == 5
    assert set(root.source_agents) == {"orchestrator", "a", "b"}
    assert root.downstream_agents == ["agent://a"]
    # tools of b appear in the orchestrator's expansion, with their keys intact
    b_tool = [t for t in root.tools if t["ref"] == "mcp://b.internal/do"][0]
    assert b_tool["data_classes"] == ["b.read"]
    assert b_tool["privileged"] is False
    # path orchestrator -> a -> b: min(5, 4, edge 4, 4, edge 2, 3) == 2
    deep = [
        p for p in root.paths if p["path"] == ["agent://orchestrator", "agent://a", "agent://b"]
    ][0]
    assert deep["effective_hop_budget"] == 2
    # the single-hop path keeps the tighter of (root budget, edge cap)
    shallow = [p for p in root.paths if p["path"] == ["agent://orchestrator", "agent://a"]][0]
    assert shallow["effective_hop_budget"] == 4


def test_compiled_shape_keys() -> None:
    root = DagCompiler().compile(_chain())["orchestrator"]
    assert set(root.data_classes) == {"reads", "writes"}
    assert root.data_classes["writes"] == []
    assert set(root.data_classes["reads"]) == {"orchestrator.read", "a.read", "b.read"}


def test_data_class_union_across_parents() -> None:
    manifests = {
        "orchestrator": _manifest(
            "orchestrator",
            hop_budget=5,
            downstream=[
                {"ref": "agent://a", "max_hop_depth": 3},
                {"ref": "agent://shared", "max_hop_depth": 3},
            ],
        ),
        "a": _manifest(
            "a", hop_budget=4, downstream=[{"ref": "agent://shared", "max_hop_depth": 2}]
        ),
        "shared": _manifest("shared", hop_budget=3, reads=["shared.read"]),
    }
    compiled = DagCompiler().compile(manifests)
    reads = compiled["orchestrator"].data_classes["reads"]
    assert {"orchestrator.read", "a.read", "shared.read"} <= set(reads)


def test_cycle_rejected_with_agents_named() -> None:
    manifests = _chain()
    manifests["b"] = _manifest(
        "b", hop_budget=3, downstream=[{"ref": "agent://orchestrator", "max_hop_depth": 2}]
    )
    with pytest.raises(DagCycleError) as exc:
        DagCompiler().compile(manifests)
    assert "orchestrator" in str(exc.value)
    assert exc.value.details is not None and "cycle" in exc.value.details


def test_unresolved_downstream_flagged_not_dropped() -> None:
    manifests = {
        "orchestrator": _manifest(
            "orchestrator",
            hop_budget=5,
            downstream=[
                {"ref": "agent://ghost", "max_hop_depth": 2},
                {"ref": "agent://ghost2", "max_hop_depth": 2},
            ],
        )
    }
    compiled = DagCompiler().compile(manifests)
    assert compiled["orchestrator"].unresolved_downstream == ["agent://ghost", "agent://ghost2"]


def test_cycle_still_detected_when_an_unresolved_edge_comes_first() -> None:
    """The cycle walk must not `break` on an unresolved edge and miss a later real one."""
    manifests = {
        "a": _manifest(
            "a",
            hop_budget=4,
            downstream=[
                {"ref": "agent://ghost", "max_hop_depth": 2},
                {"ref": "agent://b", "max_hop_depth": 2},
            ],
        ),
        "b": _manifest("b", hop_budget=3, downstream=[{"ref": "agent://a", "max_hop_depth": 2}]),
    }
    with pytest.raises(DagCycleError):
        DagCompiler().compile(manifests)
