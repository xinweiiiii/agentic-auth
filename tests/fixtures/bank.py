"""The PRD §2.3 scenario, as fixtures (Phase 3, extended in Phase 4).

    user:alice consents to bank-assistant
      └─ bank-assistant ─> balance-agent ─> support-agent ─> terminate_account

``terminate_account`` is declared only in the *widened* manifests, as a **privileged** tool
bound on ``/account_id`` (Phase 4). support-agent's ``taint_policy`` leaves the knowledge
base OUT of ``trusted_sources`` unless ``trust_kb=True``, so a KB read taints its context —
the PRD injection scenario. Everything here reuses ``manifest_doc`` from the Phase 2 chain
fixtures, and every tool ref points at a host the fake discovery source advertises, so all
variants reconcile cleanly.
"""

from __future__ import annotations

from typing import Any

from tests.fixtures.chains import manifest_doc

USER = "user:alice"

BANK_ASSISTANT = "bank-assistant"
BALANCE_AGENT = "balance-agent"
SUPPORT_AGENT = "support-agent"
FRAUD_AGENT = "fraud-agent"
BANK_AGENTS = [BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT]

KB_SEARCH_TOOL = "mcp://kb.internal/search"
READ_BALANCE = "mcp://accounts.internal/read_balance"
TERMINATE_ACCOUNT = "mcp://accounts.internal/terminate_account"
READ_LEDGER = "mcp://ledger.internal/read_ledger"

# (caller, target, data_class) — the caller is whoever HOLDS the token at that hop.
Call = tuple[str, str, str]

_TO_SUPPORT: list[Call] = [
    (USER, f"agent://{BALANCE_AGENT}", "account.read"),
    (f"agent://{BALANCE_AGENT}", f"agent://{SUPPORT_AGENT}", "kb.internal"),
]
# The injected "also close the account": an undeclared tool edge at hop 3.
DRIFTED_CALLS: list[Call] = [
    *_TO_SUPPORT,
    (f"agent://{SUPPORT_AGENT}", TERMINATE_ACCOUNT, "account.write"),
]
CLEAN_CALLS: list[Call] = [
    *_TO_SUPPORT,
    (f"agent://{SUPPORT_AGENT}", KB_SEARCH_TOOL, "kb.internal"),
]
# Phase 4: the PRD §2.2 injection. support-agent reads the KB (untrusted for it) and then
# attempts the privileged terminate_account, both at hop 3 with the same token.
INJECTION_CALLS: list[Call] = [
    *_TO_SUPPORT,
    (f"agent://{SUPPORT_AGENT}", KB_SEARCH_TOOL, "kb.internal"),
    (f"agent://{SUPPORT_AGENT}", TERMINATE_ACCOUNT, "account.write"),
]
TERMINATE_PARAMS: dict[str, Any] = {"account_id": "acc-42", "reason": "fraud", "notify": True}
TERMINATE_BINDING = ["/account_id"]

# An undeclared delegation: balance-agent -> fraud-agent is not an edge anyone declared.
FRAUD_CALLS: list[Call] = [
    (USER, f"agent://{BALANCE_AGENT}", "account.read"),
    (f"agent://{BALANCE_AGENT}", f"agent://{FRAUD_AGENT}", "ledger.read"),
]


def bank_docs(
    *,
    widened: bool = False,
    include_fraud_agent: bool = False,
    trust_kb: bool = False,
    binding: list[str] | None = TERMINATE_BINDING,
) -> dict[str, dict[str, Any]]:
    """The bank scenario as manifest documents, keyed by agent name.

    ``widened=True`` declares ``terminate_account`` on support-agent — the "widen the
    manifest" branch of the drift loop, and the privileged tool Phase 4 binds.
    ``include_fraud_agent=True`` registers fraud-agent without declaring any edge to it.
    ``trust_kb=True`` lists the KB in support-agent's trusted sources, so reading it does
    NOT taint. ``binding`` is terminate_account's ``binding_params`` (None = whole body).
    """
    support_tools = [{"ref": KB_SEARCH_TOOL, "data_classes": ["kb.internal"], "privileged": False}]
    support_writes: list[str] = []
    if widened:
        terminate: dict[str, Any] = {
            "ref": TERMINATE_ACCOUNT,
            "data_classes": ["account.write"],
            "privileged": True,
        }
        if binding is not None:
            terminate["binding_params"] = list(binding)
        support_tools.append(terminate)
        support_writes = ["account.write"]

    docs = {
        BANK_ASSISTANT: manifest_doc(
            BANK_ASSISTANT,
            hop_budget=4,
            tools=[{"ref": KB_SEARCH_TOOL, "data_classes": ["kb.public"], "privileged": False}],
            downstream=[{"ref": f"agent://{BALANCE_AGENT}", "max_hop_depth": 4}],
        ),
        BALANCE_AGENT: manifest_doc(
            BALANCE_AGENT,
            hop_budget=4,
            tools=[{"ref": READ_BALANCE, "data_classes": ["account.read"], "privileged": False}],
            downstream=[{"ref": f"agent://{SUPPORT_AGENT}", "max_hop_depth": 4}],
        ),
        SUPPORT_AGENT: manifest_doc(
            SUPPORT_AGENT,
            hop_budget=4,
            tools=support_tools,
            reads=["kb.internal"],
            writes=support_writes,
        ),
    }
    if trust_kb:
        docs[SUPPORT_AGENT]["spec"]["taint_policy"] = {"trusted_sources": ["mcp://kb.internal/*"]}
    if include_fraud_agent:
        docs[FRAUD_AGENT] = manifest_doc(
            FRAUD_AGENT,
            hop_budget=4,
            tools=[{"ref": READ_LEDGER, "data_classes": ["ledger.read"], "privileged": False}],
        )
    return docs


def leaf_first(docs: dict[str, dict[str, Any]]) -> list[str]:
    """Registration order: every downstream agent before the agent that delegates to it,
    so each reference resolves at compile time instead of landing in
    ``unresolved_downstream``."""
    ordered: list[str] = []

    def visit(name: str) -> None:
        if name in ordered or name not in docs:
            return
        for downstream in docs[name]["spec"]["downstream_agents"]:
            visit(downstream["ref"].removeprefix("agent://"))
        ordered.append(name)

    for name in sorted(docs):
        visit(name)
    return ordered


def deep_chain_docs(depth: int = 5) -> tuple[dict[str, dict[str, Any]], list[Call]]:
    """A linear chain producing exactly ``depth`` decisions: ``depth - 1`` delegations and
    a final tool call. Returns ``(docs, calls)``; the scope root is ``deep-1``."""
    names = [f"deep-{i}" for i in range(1, depth + 1)]
    budget = max(depth + 2, 4)
    docs: dict[str, dict[str, Any]] = {}
    for index, name in enumerate(names):
        downstream = (
            [{"ref": f"agent://{names[index + 1]}", "max_hop_depth": budget}]
            if index + 1 < len(names)
            else []
        )
        docs[name] = manifest_doc(
            name,
            hop_budget=budget,
            tools=[{"ref": KB_SEARCH_TOOL, "data_classes": ["kb.internal"], "privileged": False}],
            downstream=downstream,
        )

    calls: list[Call] = [(USER, f"agent://{names[1]}", "kb.internal")]
    for index in range(1, depth - 1):
        calls.append((f"agent://{names[index]}", f"agent://{names[index + 1]}", "kb.internal"))
    calls.append((f"agent://{names[-1]}", KB_SEARCH_TOOL, "kb.internal"))
    return docs, calls
