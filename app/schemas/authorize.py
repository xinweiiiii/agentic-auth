"""Per-hop authorization: the deny vocabulary, the request, and the decision.

Note what is absent: there is no ``hop_count`` field anywhere in this module. Delegation
depth is derived from the verified ``act`` chain of the presented token. A caller-supplied
integer is attacker-controlled, and accepting one alongside the signed value would only
create a question about which wins.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.boundary.guarantee import Guarantee


class Taint(StrEnum):
    TRUSTED_INTERNAL = "trusted_internal"
    UNTRUSTED_EXTERNAL = "untrusted_external"


class DenyReason(StrEnum):
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    HOP_BUDGET_EXCEEDED = "HOP_BUDGET_EXCEEDED"
    EDGE_NOT_IN_DAG = "EDGE_NOT_IN_DAG"
    SCOPE_NOT_CONSENTED = "SCOPE_NOT_CONSENTED"
    PDP_UNAVAILABLE = "PDP_UNAVAILABLE"
    TOKEN_SERVICE_UNAVAILABLE = "TOKEN_SERVICE_UNAVAILABLE"
    # Returned, never stored: it exists precisely because the record could not be written.
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    # Phase 4. Effective taint is untrusted_external and the target is protected. A consent
    # prompt cannot launder injected content, so it is never recoverable.
    TAINTED_INTO_PRIVILEGED = "TAINTED_INTO_PRIVILEGED"
    # Phase 4. The holder, or an agent on the chain, has a revoked trust anchor.
    AGENT_REVOKED = "AGENT_REVOKED"
    # Phase 4. identity_required is on and the holder has no live trust anchor.
    AGENT_NOT_ENROLLED = "AGENT_NOT_ENROLLED"


# Recoverability is a property of the reason, not a per-call judgement, so the PDP, the
# sidecar and the SDK can never disagree about it. Only SCOPE_NOT_CONSENTED is a step-up
# candidate; a consent prompt cannot widen a hop budget or invent an undeclared edge.
RECOVERABLE: dict[DenyReason, bool] = {
    DenyReason.OUT_OF_SCOPE: False,
    DenyReason.HOP_BUDGET_EXCEEDED: False,
    DenyReason.EDGE_NOT_IN_DAG: False,
    DenyReason.SCOPE_NOT_CONSENTED: True,
    DenyReason.PDP_UNAVAILABLE: False,
    DenyReason.TOKEN_SERVICE_UNAVAILABLE: False,
    DenyReason.AUDIT_UNAVAILABLE: False,
    DenyReason.TAINTED_INTO_PRIVILEGED: False,
    DenyReason.AGENT_REVOKED: False,
    DenyReason.AGENT_NOT_ENROLLED: False,
}

# What policy decided, versus what could not be decided or recorded. Observe mode may let a
# POLICY reason through — that is its whole purpose. It must never let an INFRASTRUCTURE
# reason through: that would forward an outage as if it were a prediction.
POLICY_REASONS: frozenset[DenyReason] = frozenset(
    {
        DenyReason.OUT_OF_SCOPE,
        DenyReason.HOP_BUDGET_EXCEEDED,
        DenyReason.EDGE_NOT_IN_DAG,
        DenyReason.SCOPE_NOT_CONSENTED,
        # Predictable from configuration and state, not outages — so observe mode may
        # forward them, recorded `enforced=false`, exactly like OUT_OF_SCOPE.
        DenyReason.TAINTED_INTO_PRIVILEGED,
        DenyReason.AGENT_REVOKED,
        DenyReason.AGENT_NOT_ENROLLED,
    }
)
INFRASTRUCTURE_REASONS: frozenset[DenyReason] = frozenset(
    {
        DenyReason.PDP_UNAVAILABLE,
        DenyReason.TOKEN_SERVICE_UNAVAILABLE,
        DenyReason.AUDIT_UNAVAILABLE,
    }
)
assert set(DenyReason) == POLICY_REASONS | INFRASTRUCTURE_REASONS, "unclassified deny reason"
assert not POLICY_REASONS & INFRASTRUCTURE_REASONS, "a reason cannot be both"


def is_recoverable(reason: DenyReason) -> bool:
    return RECOVERABLE[reason]


class StepUpChallenge(BaseModel):
    """The challenge handed back on a recoverable deny.

    Defined here rather than in ``app.schemas.stepup`` to keep ``AuthorizeDecision``'s
    imports acyclic: the step-up schemas import the deny vocabulary from this module.
    """

    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(description="Single use. Only its SHA-256 is ever stored.")
    session_id: str
    blocked_hop: int = Field(ge=1)
    blocked_action_id: uuid.UUID
    data_class: str
    target: str
    reason: DenyReason
    expires_at: datetime


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    caller: str = Field(max_length=255, description="agent://<name>, or user:<sub> at hop 1")
    target: str = Field(max_length=512, description="mcp://host/tool, or agent://<name>")
    data_class: str = Field(max_length=128, description="exactly one data class")
    taint: Taint | None = Field(
        default=None,
        description=(
            "Agent-reported label. ADDITIVE ONLY: it can raise the effective taint the "
            "decision uses, never lower it. The control plane derives the rest."
        ),
    )
    guarantee: Guarantee = Field(
        description=(
            "How strong the enforcement at this point actually is. Reported by the "
            "enforcement point, exactly like `enforced`, and NEVER an input to the "
            "decision. **Deliberately no default**: a PEP that omits it gets a 422, "
            "which is how the rule ('refuse to emit a decision whose guarantee level "
            "cannot be determined') is enforced by the schema rather than by a runtime "
            "branch some path could miss."
        ),
    )
    enforced: bool = Field(
        default=True,
        description=(
            "Reported by the enforcement point: will it act on a deny, or is it in "
            "observe mode? An allow is always recorded as enforced, since it is "
            "forwarded either way — so `enforced=false` means exactly 'would have been "
            "blocked'. NEVER an input to the decision itself: the PDP is mode-blind, "
            "which is what makes the observe-mode report a trustworthy prediction of "
            "enforcement."
        ),
    )


class AuthorizeDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: str  # "allow" | "deny"
    hop: int = Field(ge=1, description="Derived from the verified act chain")
    policy_version: int
    session_id: str
    reason: DenyReason | None = None
    recoverable: bool | None = None
    target: str | None = None
    taint: Taint | None = Field(
        default=None,
        description="The EFFECTIVE taint the decision was made under, not an echo of the request.",
    )
    taint_source: str | None = Field(
        default=None, description="The target that introduced the taint into this context."
    )
    privileged: bool = Field(
        default=False, description="The target is privileged in the session's pinned policy."
    )
    transaction_required: bool = Field(
        default=False,
        description="privileged AND transaction tokens enabled: mint POST /v1/token/transaction "
        "before calling the resource.",
    )
    message: str | None = Field(
        default=None, description="Human-readable detail; never the machine contract"
    )
    action_id: uuid.UUID | None = Field(
        default=None,
        description="The audit row for this decision. Required by the token exchange. "
        "Null only when the decision could not be recorded.",
    )
    acting_agent: str | None = Field(
        default=None,
        description="The verified token holder. Null for a token minted for a tool call.",
    )
    recorded: bool = Field(
        default=True,
        description="The audit row was committed before this response was sent.",
    )
    guarantee: Guarantee | None = Field(
        default=None,
        description=(
            "Echoed from the request and written to the audit row. Null only on a "
            "response rendered before the request was parsed."
        ),
    )
    step_up: StepUpChallenge | None = Field(
        default=None,
        description=(
            "Present only on a RECOVERABLE deny with step-up enabled: the challenge to "
            "put to the consenting human. A non-recoverable deny never carries one, so a "
            "client cannot offer a prompt for something that can never be granted."
        ),
    )

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"
