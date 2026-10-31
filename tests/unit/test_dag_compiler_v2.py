"""DagCompiler v2 — per-agent ``nodes`` and explicit ``edges``.

v1 flattened ``tools`` across the whole closure, so it could say that *some* agent may
call a tool but not *which*. The PDP needs per-caller capability and a direct edge set;
these tests pin both, and pin that the v1 keys did not change meaning.
"""

from __future__ import annotations

from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.services.dag_compiler import DAG_SCHEMA_VERSION, DagCompiler


def _manifest(
    agent: str, *, hop_budget: int, tools=None, downstream=None, reads=None, writes=None
) -> AgentManifest:
    return AgentManifest.model_validate(
        {
            "apiVersion": "agentic-auth/v1",
            "kind": "AgentManifest",
            "metadata": {"agent": agent},
            "spec": {
                "tools": tools
                or [{"ref": f"mcp://{agent}.internal/do", "data_classes": [f"{agent}.read"]}],
                "data_classes": {"reads": reads or [f"{agent}.read"], "writes": writes or []},
                "downstream_agents": downstream or [],
                "hop_budget": hop_budget,
            },
        }
    )


def _chain() -> dict[str, AgentManifest]:
    """orchestrator -> a -> b, the shape every runtime test builds on."""
    return {
        "orchestrator": _manifest(
            "orchestrator", hop_budget=5, downstream=[{"ref": "agent://a", "max_hop_depth": 4}]
        ),
        "a": _manifest("a", hop_budget=4, downstream=[{"ref": "agent://b", "max_hop_depth": 2}]),
        "b": _manifest("b", hop_budget=3),
    }


def test_dag_carries_schema_version() -> None:
    dag = DagCompiler().compile(_chain())["orchestrator"].to_dag()
    assert dag["dag_schema_version"] == DAG_SCHEMA_VERSION == 3


def test_nodes_hold_only_each_agents_own_tools() -> None:
    """The whole point of v2: `tools` is the union, `nodes[x].tools` is x's own."""
    root = DagCompiler().compile(_chain())["orchestrator"]

    assert set(root.nodes) == {"orchestrator", "a", "b"}
    # the flattened union still holds all three
    assert {t["ref"] for t in root.tools} == {
        "mcp://orchestrator.internal/do",
        "mcp://a.internal/do",
        "mcp://b.internal/do",
    }
    # but each node holds exactly one — its own
    assert [t["ref"] for t in root.nodes["a"]["tools"]] == ["mcp://a.internal/do"]
    assert [t["ref"] for t in root.nodes["b"]["tools"]] == ["mcp://b.internal/do"]
    assert [t["ref"] for t in root.nodes["orchestrator"]["tools"]] == [
        "mcp://orchestrator.internal/do"
    ]


def test_nodes_carry_own_data_classes_and_budget_not_the_union() -> None:
    manifests = _chain()
    manifests["b"] = _manifest("b", hop_budget=3, reads=["b.read"], writes=["b.write"])
    root = DagCompiler().compile(manifests)["orchestrator"]

    assert root.nodes["b"]["hop_budget"] == 3
    assert root.nodes["b"]["data_classes"] == {"reads": ["b.read"], "writes": ["b.write"]}
    # a's node is untouched by b's declarations
    assert root.nodes["a"]["data_classes"] == {"reads": ["a.read"], "writes": []}
    assert root.nodes["a"]["hop_budget"] == 4
    # the scope-level union still aggregates across the closure
    assert root.data_classes["writes"] == ["b.write"]


def test_edges_are_the_direct_declared_delegations() -> None:
    root = DagCompiler().compile(_chain())["orchestrator"]
    assert root.edges == [
        {"from": "a", "to": "b", "max_hop_depth": 2},
        {"from": "orchestrator", "to": "a", "max_hop_depth": 4},
    ]


def test_edge_preserves_its_own_declared_cap_not_the_path_minimum() -> None:
    """`edges` carries the raw declaration; `paths` carries the running minimum."""
    root = DagCompiler().compile(_chain())["orchestrator"]

    a_to_b = [e for e in root.edges if e["from"] == "a"][0]
    assert a_to_b["max_hop_depth"] == 2

    deep = [
        p for p in root.paths if p["path"] == ["agent://orchestrator", "agent://a", "agent://b"]
    ][0]
    assert deep["effective_hop_budget"] == 2  # min(5, 4, 4, 2, 3)


def test_unresolved_downstream_is_not_a_declared_edge() -> None:
    """A delegation to an unregistered agent must deny, not resolve against a phantom node."""
    manifests = {
        "orchestrator": _manifest(
            "orchestrator",
            hop_budget=5,
            downstream=[{"ref": "agent://ghost", "max_hop_depth": 2}],
        )
    }
    root = DagCompiler().compile(manifests)["orchestrator"]

    assert root.unresolved_downstream == ["agent://ghost"]
    assert root.edges == []
    assert "ghost" not in root.nodes


def test_multi_parent_agent_appears_once_in_nodes_with_two_edges_in() -> None:
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
    root = DagCompiler().compile(manifests)["orchestrator"]

    assert len([n for n in root.nodes if n == "shared"]) == 1
    edges_into_shared = sorted(e["from"] for e in root.edges if e["to"] == "shared")
    assert edges_into_shared == ["a", "orchestrator"]


def test_scope_compiled_for_a_leaf_has_nodes_but_no_edges() -> None:
    compiled = DagCompiler().compile(_chain())
    leaf = compiled["b"]
    assert set(leaf.nodes) == {"b"}
    assert leaf.edges == []
    assert leaf.to_dag()["dag_schema_version"] == 3


def test_v1_keys_retain_their_meaning() -> None:
    """v2 is additive. Nothing existing changed shape."""
    dag = DagCompiler().compile(_chain())["orchestrator"].to_dag()
    for key in (
        "scope",
        "tools",
        "data_classes",
        "downstream_agents",
        "hop_budget",
        "paths",
        "unresolved_downstream",
        "source_agents",
    ):
        assert key in dag, key
    assert dag["scope"] == "orchestrator"
    assert dag["hop_budget"] == 5
    assert dag["downstream_agents"] == ["agent://a"]


def test_node_tools_are_ordered_deterministically() -> None:
    """A compiled policy is stored and version-pinned, so its byte content must not
    depend on manifest ordering. Every other fixture declares one tool per agent, which
    makes the sort a no-op — this one has two, deliberately out of order.
    """
    manifests = {
        "multi": _manifest(
            "multi",
            hop_budget=2,
            tools=[
                {"ref": "mcp://z.internal/last", "data_classes": ["z.read"]},
                {"ref": "mcp://a.internal/first", "data_classes": ["a.read"]},
            ],
            reads=["z.read", "a.read"],
        )
    }
    node = DagCompiler().compile(manifests)["multi"].nodes["multi"]

    assert [t["ref"] for t in node["tools"]] == [
        "mcp://a.internal/first",
        "mcp://z.internal/last",
    ]


def test_a_multi_tool_agent_declares_both_and_only_both() -> None:
    manifests = {
        "multi": _manifest(
            "multi",
            hop_budget=2,
            tools=[
                {"ref": "mcp://z.internal/last", "data_classes": ["z.read"]},
                {"ref": "mcp://a.internal/first", "data_classes": ["a.read"]},
            ],
            reads=["z.read", "a.read"],
        ),
        "other": _manifest("other", hop_budget=2),
    }
    compiled = DagCompiler().compile(manifests)["multi"]
    assert {t["ref"] for t in compiled.nodes["multi"]["tools"]} == {
        "mcp://a.internal/first",
        "mcp://z.internal/last",
    }
    assert "other" not in compiled.nodes  # unreachable agents stay out


# -- Phase 4 (v3): taint_policy and binding_params are compiled per node -----------


def test_v3_materializes_the_default_trusted_sources_to_declared_downstream_agents() -> None:
    root = DagCompiler().compile(_chain())["orchestrator"]
    assert root.nodes["orchestrator"]["taint_policy"] == {
        "trusted_sources": ["agent://a"],
        "block_tainted_into": ["privileged"],
    }
    assert root.nodes["b"]["taint_policy"] == {
        "trusted_sources": [],
        "block_tainted_into": ["privileged"],
    }


def test_v3_compiles_an_explicit_taint_policy_and_binding_params_verbatim() -> None:
    manifests = _chain()
    manifests["b"] = AgentManifest.model_validate(
        {
            "apiVersion": "agentic-auth/v1",
            "kind": "AgentManifest",
            "metadata": {"agent": "b"},
            "spec": {
                "tools": [
                    {
                        "ref": "mcp://b.internal/do",
                        "data_classes": ["b.write"],
                        "privileged": True,
                        "binding_params": ["/account_id"],
                    }
                ],
                "data_classes": {"reads": [], "writes": ["b.write"]},
                "downstream_agents": [],
                "hop_budget": 3,
                "taint_policy": {
                    "trusted_sources": ["mcp://kb.internal/*"],
                    "block_tainted_into": ["privileged", "*.write"],
                },
            },
        }
    )
    node = DagCompiler().compile(manifests)["orchestrator"].nodes["b"]
    assert node["taint_policy"] == {
        "trusted_sources": ["mcp://kb.internal/*"],
        "block_tainted_into": ["privileged", "*.write"],
    }
    assert node["tools"][0]["binding_params"] == ["/account_id"]


def test_v3_non_privileged_tools_carry_a_null_binding() -> None:
    root = DagCompiler().compile(_chain())["orchestrator"]
    assert all(t["binding_params"] is None for t in root.nodes["a"]["tools"])
