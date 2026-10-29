"""``classify_edge`` — the one edge rule, and what each verdict means at runtime."""

from __future__ import annotations

import pytest

from app.schemas.authorize import DenyReason
from app.schemas.manifest import AgentManifest
from app.services.drift import declared_graph
from app.services.edge_rules import RUNTIME_REASON, EdgeVerdict, classify_edge, delegate_of
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    FRAUD_AGENT,
    KB_SEARCH_TOOL,
    READ_BALANCE,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    bank_docs,
)


@pytest.fixture(scope="module")
def graph():
    docs = bank_docs(include_fraud_agent=True)
    return declared_graph({name: AgentManifest.model_validate(doc) for name, doc in docs.items()})


@pytest.mark.parametrize(
    ("caller", "target", "verdict"),
    [
        pytest.param(SUPPORT_AGENT, KB_SEARCH_TOOL, EdgeVerdict.DECLARED, id="declared tool"),
        pytest.param(BALANCE_AGENT, READ_BALANCE, EdgeVerdict.DECLARED, id="declared tool 2"),
        pytest.param(
            BANK_ASSISTANT,
            f"agent://{BALANCE_AGENT}",
            EdgeVerdict.DECLARED,
            id="declared delegation",
        ),
        pytest.param(
            SUPPORT_AGENT, TERMINATE_ACCOUNT, EdgeVerdict.UNDECLARED_TOOL, id="undeclared tool"
        ),
        pytest.param(
            BALANCE_AGENT,
            f"agent://{FRAUD_AGENT}",
            EdgeVerdict.UNDECLARED_DELEGATION,
            id="registered agent, no declared edge",
        ),
        pytest.param(
            BALANCE_AGENT,
            "agent://nobody",
            EdgeVerdict.UNDECLARED_DELEGATION,
            id="delegation to an agent with no manifest",
        ),
        pytest.param(
            BALANCE_AGENT,
            KB_SEARCH_TOOL,
            EdgeVerdict.UNDECLARED_TOOL,
            id="tool declared only by a different agent",
        ),
        pytest.param("ghost", KB_SEARCH_TOOL, EdgeVerdict.UNKNOWN_AGENT, id="unknown caller"),
        pytest.param(None, KB_SEARCH_TOOL, EdgeVerdict.UNKNOWN_AGENT, id="unattributed caller"),
        pytest.param(
            SUPPORT_AGENT,
            f"agent://{BANK_ASSISTANT}",
            EdgeVerdict.UNDECLARED_DELEGATION,
            id="edges are directional",
        ),
    ],
)
def test_classify_edge(graph, caller, target, verdict) -> None:
    assert classify_edge(graph, caller, target) is verdict


def test_every_refusing_verdict_names_its_runtime_reason() -> None:
    assert set(RUNTIME_REASON) == set(EdgeVerdict) - {EdgeVerdict.DECLARED}
    assert RUNTIME_REASON[EdgeVerdict.UNDECLARED_DELEGATION] is DenyReason.EDGE_NOT_IN_DAG
    assert RUNTIME_REASON[EdgeVerdict.UNDECLARED_TOOL] is DenyReason.OUT_OF_SCOPE
    assert RUNTIME_REASON[EdgeVerdict.UNKNOWN_AGENT] is DenyReason.OUT_OF_SCOPE


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("agent://kb-search", "kb-search"),
        ("mcp://kb.internal/search", None),
        ("agent-ish://kb-search", None),
    ],
)
def test_delegate_of(target, expected) -> None:
    assert delegate_of(target) == expected
