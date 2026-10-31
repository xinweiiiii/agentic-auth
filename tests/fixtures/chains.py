"""The four-agent delegation chain every runtime test builds on.

    user:alice
      └─ orchestrator (budget 4) ─> kb-search ─> summarizer ─> notifier

Tool refs point at the hosts the fake discovery source advertises
(``tests/fixtures/discovery/server.py``), so these manifests reconcile cleanly against it.
"""

from __future__ import annotations

from typing import Any

from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.services.dag_compiler import DagCompiler

ORCHESTRATOR = "orchestrator"
KB_SEARCH = "kb-search"
SUMMARIZER = "summarizer"
NOTIFIER = "notifier"

CHAIN_AGENTS = [ORCHESTRATOR, KB_SEARCH, SUMMARIZER, NOTIFIER]


def manifest_doc(
    agent: str,
    *,
    hop_budget: int,
    tools: list[dict] | None = None,
    downstream: list[dict] | None = None,
    reads: list[str] | None = None,
    writes: list[str] | None = None,
) -> dict[str, Any]:
    tools = tools or [
        {"ref": "mcp://kb.internal/search", "data_classes": ["kb.public"], "privileged": False}
    ]
    declared: set[str] = set()
    for t in tools:
        declared.update(t["data_classes"])
    return {
        "apiVersion": "agentic-auth/v1",
        "kind": "AgentManifest",
        "metadata": {"agent": agent},
        "spec": {
            "tools": tools,
            "data_classes": {
                "reads": sorted(set(reads or declared)),
                "writes": sorted(set(writes or [])),
            },
            "downstream_agents": downstream or [],
            "hop_budget": hop_budget,
        },
    }


def chain_docs(*, include_kb_edge: bool = True) -> dict[str, dict[str, Any]]:
    """The 4-agent chain as manifest documents.

    ``include_kb_edge=False`` drops orchestrator -> kb-search, which is how the drift
    test produces an observed delegation the compiled DAG does not declare.
    """
    return {
        ORCHESTRATOR: manifest_doc(
            ORCHESTRATOR,
            hop_budget=4,
            tools=[
                {
                    "ref": "mcp://kb.internal/search",
                    "data_classes": ["kb.public"],
                    "privileged": False,
                }
            ],
            downstream=(
                [{"ref": f"agent://{KB_SEARCH}", "max_hop_depth": 4}] if include_kb_edge else []
            ),
        ),
        KB_SEARCH: manifest_doc(
            KB_SEARCH,
            hop_budget=4,
            tools=[
                {
                    "ref": "mcp://kb.internal/search",
                    "data_classes": ["kb.internal"],
                    "privileged": False,
                }
            ],
            downstream=[{"ref": f"agent://{SUMMARIZER}", "max_hop_depth": 4}],
        ),
        SUMMARIZER: manifest_doc(
            SUMMARIZER,
            hop_budget=4,
            tools=[
                {
                    "ref": "mcp://accounts.internal/read_account",
                    "data_classes": ["account.read"],
                    "privileged": False,
                }
            ],
            downstream=[{"ref": f"agent://{NOTIFIER}", "max_hop_depth": 4}],
        ),
        NOTIFIER: manifest_doc(
            NOTIFIER,
            hop_budget=4,
            tools=[
                {
                    "ref": "mcp://accounts.internal/close_account",
                    "data_classes": ["account.write"],
                    "privileged": True,
                }
            ],
        ),
    }


def chain_manifests(*, include_kb_edge: bool = True) -> dict[str, AgentManifest]:
    return {
        name: AgentManifest.model_validate(doc)
        for name, doc in chain_docs(include_kb_edge=include_kb_edge).items()
    }


def compiled_dag(scope: str = ORCHESTRATOR, *, include_kb_edge: bool = True, version: int = 1):
    """Compile the chain in-process — no database required."""
    compiled = DagCompiler().compile(chain_manifests(include_kb_edge=include_kb_edge))
    return {**compiled[scope].to_dag(), "version": version}


def shallow_dag(hop_budget: int = 2, version: int = 1) -> dict:
    """A chain whose budget runs out partway, for hop-budget tests."""
    docs = chain_manifests()
    manifests = dict(docs)
    manifests[SUMMARIZER] = AgentManifest.model_validate(
        manifest_doc(
            SUMMARIZER,
            hop_budget=hop_budget,
            tools=[
                {
                    "ref": "mcp://accounts.internal/read_account",
                    "data_classes": ["account.read"],
                    "privileged": False,
                }
            ],
            downstream=[{"ref": f"agent://{NOTIFIER}", "max_hop_depth": hop_budget}],
        )
    )
    compiled = DagCompiler().compile(manifests)
    return {**compiled[ORCHESTRATOR].to_dag(), "version": version}
