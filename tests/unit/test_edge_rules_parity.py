"""CI and the runtime agree on every edge.

For every agent reachable from the consented scope and every candidate target, the drift
check's verdict (a graph index over the manifests) and the PDP's decision (the scope's
pinned policy index) must agree: an edge is reported undeclared **if and only if** the
runtime refuses it with that verdict's runtime reason.

Tokens are built so the edge check is the only thing that can refuse: the chain reaches the
caller along declared edges, and the data class is one the relevant agent declares.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from typing import Any

import pytest

from agentic_auth.boundary.guarantee import Guarantee
from agentic_auth.schemas.authorize import AuthorizeRequest, DenyReason
from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.services.dag_compiler import DagCompiler
from agentic_auth.services.drift import declared_graph
from agentic_auth.services.edge_rules import RUNTIME_REASON, EdgeVerdict, classify_edge, delegate_of
from agentic_auth.services.pdp import decide
from agentic_auth.services.policy_loader import PolicyIndex, build_index
from agentic_auth.services.tokens.profile import VerifiedToken
from tests.fixtures import tokens
from tests.fixtures.bank import BANK_ASSISTANT, bank_docs
from tests.fixtures.chains import ORCHESTRATOR, chain_docs

SESSION = "s1"
VERSION = 1
EDGE_REASONS = {DenyReason.OUT_OF_SCOPE, DenyReason.EDGE_NOT_IN_DAG}
PROFILE = tokens.profile()

SCENARIOS: dict[str, tuple[dict[str, dict[str, Any]], str]] = {
    "bank": (bank_docs(include_fraud_agent=True), BANK_ASSISTANT),
    "bank-widened": (bank_docs(widened=True, include_fraud_agent=True), BANK_ASSISTANT),
    "chain": (chain_docs(), ORCHESTRATOR),
    "chain-without-kb-edge": (chain_docs(include_kb_edge=False), ORCHESTRATOR),
}


def _manifests(docs: dict[str, dict[str, Any]]) -> dict[str, AgentManifest]:
    return {name: AgentManifest.model_validate(doc) for name, doc in docs.items()}


def _cases() -> Iterator[Any]:
    for scenario, (docs, root) in SCENARIOS.items():
        manifests = _manifests(docs)
        tools = sorted({t.ref for m in manifests.values() for t in m.spec.tools})
        targets = [
            *tools,
            "mcp://unknown.internal/tool",
            *(f"agent://{name}" for name in sorted(manifests)),
            "agent://ghost",
        ]
        reachable = DagCompiler().compile(manifests)[root].source_agents
        for caller in reachable:
            for target in targets:
                yield pytest.param(scenario, caller, target, id=f"{scenario}:{caller}->{target}")


def _path_to(policy: PolicyIndex, root: str, agent: str) -> tuple[str, ...]:
    queue: deque[tuple[str, ...]] = deque([(root,)])
    seen = {root}
    while queue:
        path = queue.popleft()
        if path[-1] == agent:
            return path
        for source, destination in sorted(policy.edges):
            if source == path[-1] and destination not in seen:
                seen.add(destination)
                queue.append((*path, destination))
    raise AssertionError(f"{agent} is not reachable from {root}")


def _token(policy: PolicyIndex, root: str, caller: str) -> VerifiedToken:
    if caller == root:
        raw = tokens.root_grant(PROFILE, scope=root, session_id=SESSION, version=VERSION)
    else:
        path = _path_to(policy, root, caller)
        raw = tokens.hop_token(
            PROFILE,
            target=f"agent://{caller}",
            session_id=SESSION,
            version=VERSION,
            delegates=path[:-1],
        )
    return PROFILE.verify(raw)


def _data_class(manifests: dict[str, AgentManifest], caller: str, target: str) -> str:
    """A data class the agent that will act on it declares, so a data-class refusal
    cannot stand in for (or mask) an edge verdict.

    Since Phase 5 an undeclared class answers OUT_OF_SCOPE rather than
    SCOPE_NOT_CONSENTED when a consented subset is in play — which is an edge-shaped
    reason, so picking a declared class matters more than it did, not less."""
    holder = delegate_of(target)
    agent = manifests.get(holder) if holder else None
    agent = agent or manifests[caller]
    declared = sorted(set(agent.spec.data_classes.reads) | set(agent.spec.data_classes.writes))
    return declared[0]


@pytest.mark.parametrize(("scenario", "caller", "target"), list(_cases()))
def test_ci_and_runtime_agree_on_every_edge(scenario: str, caller: str, target: str) -> None:
    docs, root = SCENARIOS[scenario]
    manifests = _manifests(docs)
    graph = declared_graph(manifests)
    scope = DagCompiler().compile(manifests)[root]
    policy = build_index(scope.to_dag(), scope=root, version=VERSION)

    token = _token(policy, root, caller)
    request = AuthorizeRequest(
        session_id=SESSION,
        caller=token.presenter,
        target=target,
        data_class=_data_class(manifests, caller, target),
        guarantee=Guarantee.FULL,
    )

    verdict = classify_edge(graph, caller, target)
    decision = decide(policy, request, token, consented_scope=root)

    if verdict is EdgeVerdict.DECLARED:
        assert decision.reason not in EDGE_REASONS, (
            f"CI says declared, runtime refused with {decision.reason}: {decision.message}"
        )
    else:
        assert decision.reason is RUNTIME_REASON[verdict], (
            f"CI says {verdict}, runtime said {decision.outcome}/{decision.reason}: "
            f"{decision.message}"
        )


def test_an_unknown_agent_is_refused_the_same_way() -> None:
    manifests = _manifests(bank_docs())
    graph = declared_graph(manifests)
    scope = DagCompiler().compile(manifests)[BANK_ASSISTANT]
    policy = build_index(scope.to_dag(), scope=BANK_ASSISTANT, version=VERSION)
    target = "mcp://kb.internal/search"

    verdict = classify_edge(graph, "ghost", target)
    raw = tokens.hop_token(
        PROFILE,
        target="agent://ghost",
        session_id=SESSION,
        version=VERSION,
        delegates=(BANK_ASSISTANT,),
    )
    decision = decide(
        policy,
        AuthorizeRequest(
            session_id=SESSION,
            caller="agent://ghost",
            target=target,
            data_class="kb.internal",
            guarantee=Guarantee.FULL,
        ),
        PROFILE.verify(raw),
        consented_scope=BANK_ASSISTANT,
    )

    assert verdict is EdgeVerdict.UNKNOWN_AGENT
    assert decision.reason is RUNTIME_REASON[verdict]
