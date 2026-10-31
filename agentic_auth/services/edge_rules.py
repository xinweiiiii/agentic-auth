"""The edge rule — shared, verbatim, by the runtime PDP and the offline drift check.

"May this agent call this target?" has exactly one implementation in the codebase. The PDP
asks it before every hop (``agentic_auth/services/pdp.py``); ``agentic-auth drift check`` asks it
for
every edge a test run observed (``agentic_auth/services/drift.py``). Two implementations of one rule
is precisely the divergence the CI check exists to rule out, so there is one.

Pure: a policy index and an edge in, a verdict out.
"""

from __future__ import annotations

from enum import StrEnum

from agentic_auth.schemas.authorize import DenyReason
from agentic_auth.services.policy_loader import PolicyIndex

AGENT_PREFIX = "agent://"


class EdgeVerdict(StrEnum):
    DECLARED = "DECLARED"
    # The caller is not an agent any supplied manifest declares.
    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    # The caller does not itself declare this tool.
    UNDECLARED_TOOL = "UNDECLARED_TOOL"
    # The caller has no declared delegation edge to this agent.
    UNDECLARED_DELEGATION = "UNDECLARED_DELEGATION"


# What the runtime refuses with, for each verdict that is not DECLARED. The drift report
# prints this so a developer sees the production consequence of the edge they just added.
RUNTIME_REASON: dict[EdgeVerdict, DenyReason] = {
    EdgeVerdict.UNKNOWN_AGENT: DenyReason.OUT_OF_SCOPE,
    EdgeVerdict.UNDECLARED_TOOL: DenyReason.OUT_OF_SCOPE,
    EdgeVerdict.UNDECLARED_DELEGATION: DenyReason.EDGE_NOT_IN_DAG,
}


def delegate_of(target: str) -> str | None:
    """The bare agent name for a delegation target, or ``None`` for a tool ref."""
    return target.removeprefix(AGENT_PREFIX) if target.startswith(AGENT_PREFIX) else None


def classify_edge(index: PolicyIndex, caller_agent: str | None, target: str) -> EdgeVerdict:
    if caller_agent is None or caller_agent not in index.agents:
        return EdgeVerdict.UNKNOWN_AGENT

    delegate = delegate_of(target)
    if delegate is not None:
        # A delegation must be a declared edge. An edge to an agent whose manifest was never
        # registered is not compiled into `edges`, so it is undeclared here too.
        if index.has_edge(caller_agent, delegate):
            return EdgeVerdict.DECLARED
        return EdgeVerdict.UNDECLARED_DELEGATION

    # A tool call: the caller must declare the tool itself. Reaching it through another
    # agent's declaration would let any agent borrow any other agent's tools.
    if index.declares_tool(caller_agent, target):
        return EdgeVerdict.DECLARED
    return EdgeVerdict.UNDECLARED_TOOL
