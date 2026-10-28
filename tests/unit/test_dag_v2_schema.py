"""Drift guard: compiler output must satisfy the checked-in DAG v3 contract (Phase 2 T008,
Phase 4 T013).

Mirrors Phase 1's manifest-schema drift test. If the compiler starts emitting a shape the
contract does not describe — or stops emitting one it promises — this fails rather than
letting the PDP and the contract quietly disagree.
"""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from app.schemas.manifest import AgentManifest
from app.services.dag_compiler import DagCompiler
from tests.fixtures.contracts import contract_path

SCHEMA_PATH = contract_path("dag-v3.schema.json")
SCHEMA_V2_PATH = SCHEMA_PATH.with_name("dag-v2.schema.json")


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _manifest(agent: str, *, hop_budget: int, downstream=None, privileged: bool = False):
    return AgentManifest.model_validate(
        {
            "apiVersion": "agentic-auth/v1",
            "kind": "AgentManifest",
            "metadata": {"agent": agent},
            "spec": {
                "tools": [
                    {
                        "ref": f"mcp://{agent}.internal/do",
                        "data_classes": [f"{agent}.read"],
                        "privileged": privileged,
                    }
                ],
                "data_classes": {"reads": [f"{agent}.read"], "writes": []},
                "downstream_agents": downstream or [],
                "hop_budget": hop_budget,
            },
        }
    )


def _compile(manifests: dict, scope: str) -> dict:
    """Compile and stamp the version the repository layer assigns on append."""
    dag = DagCompiler().compile(manifests)[scope].to_dag()
    return {**dag, "version": 1}


def test_chain_dag_validates(validator: Draft202012Validator) -> None:
    manifests = {
        "orchestrator": _manifest(
            "orchestrator", hop_budget=4, downstream=[{"ref": "agent://a", "max_hop_depth": 3}]
        ),
        "a": _manifest("a", hop_budget=3, downstream=[{"ref": "agent://b", "max_hop_depth": 2}]),
        "b": _manifest("b", hop_budget=2, privileged=True),
    }
    errors = sorted(validator.iter_errors(_compile(manifests, "orchestrator")), key=str)
    assert errors == [], [f"{list(e.absolute_path)}: {e.message}" for e in errors]


def test_leaf_dag_validates(validator: Draft202012Validator) -> None:
    """A scope with no downstream still satisfies the contract — empty edges, one node."""
    manifests = {"solo": _manifest("solo", hop_budget=1)}
    dag = _compile(manifests, "solo")
    assert dag["edges"] == []
    errors = sorted(validator.iter_errors(dag), key=str)
    assert errors == [], [f"{list(e.absolute_path)}: {e.message}" for e in errors]


def test_dag_with_unresolved_downstream_validates(validator: Draft202012Validator) -> None:
    manifests = {
        "orchestrator": _manifest(
            "orchestrator", hop_budget=3, downstream=[{"ref": "agent://ghost", "max_hop_depth": 2}]
        )
    }
    dag = _compile(manifests, "orchestrator")
    assert dag["unresolved_downstream"] == ["agent://ghost"]
    errors = sorted(validator.iter_errors(dag), key=str)
    assert errors == [], [f"{list(e.absolute_path)}: {e.message}" for e in errors]


def test_contract_rejects_a_v1_dag(validator: Draft202012Validator) -> None:
    """The guard has teeth: a pre-Phase-2 artifact must not validate."""
    dag = _compile({"solo": _manifest("solo", hop_budget=1)}, "solo")
    for dropped in ("dag_schema_version", "nodes", "edges"):
        v1 = {k: v for k, v in dag.items() if k != dropped}
        assert list(validator.iter_errors(v1)), f"dropping {dropped!r} should fail validation"


def test_contract_rejects_a_future_schema_version(validator: Draft202012Validator) -> None:
    dag = _compile({"solo": _manifest("solo", hop_budget=1)}, "solo")
    assert list(validator.iter_errors({**dag, "dag_schema_version": 4}))


def test_v3_is_additive_over_v2() -> None:
    """Strip the v3 additions and stamp version 2: the untouched v2 contract must accept it.
    That is what lets the runtime keep loading Phase 2/3 policies unchanged."""
    v2 = Draft202012Validator(json.loads(SCHEMA_V2_PATH.read_text()))
    dag = _compile({"solo": _manifest("solo", hop_budget=1, privileged=True)}, "solo")
    downgraded = {**dag, "dag_schema_version": 2}
    downgraded["nodes"] = {
        name: {k: v for k, v in node.items() if k != "taint_policy"}
        for name, node in dag["nodes"].items()
    }
    for node in downgraded["nodes"].values():
        node["tools"] = [
            {k: v for k, v in t.items() if k != "binding_params"} for t in node["tools"]
        ]
    downgraded["tools"] = [
        {k: v for k, v in t.items() if k != "binding_params"} for t in dag["tools"]
    ]
    errors = sorted(v2.iter_errors(downgraded), key=str)
    assert errors == [], [f"{list(e.absolute_path)}: {e.message}" for e in errors]
