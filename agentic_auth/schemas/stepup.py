"""Step-up consent — turning a recoverable refusal into a question (FR-022..FR-031).

See ``docs/contracts/stepup.openapi.yaml``.

One shape to notice: :class:`StepUpRequest` carries only the session and the audit row of
the refusal. The data class, the target, the hop and the reason are all **read from that
row**, never accepted from the caller. A caller that could name its own data class would
be writing its own consent, which is the whole thing this flow exists to prevent.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from agentic_auth.schemas.authorize import DenyReason, StepUpChallenge

__all__ = [
    "PartialOutcome",
    "StepUpChallenge",
    "StepUpChallengeRead",
    "StepUpComplete",
    "StepUpGrantRead",
    "StepUpRequest",
]

# The challenge shape lives in agentic_auth.schemas.authorize so AuthorizeDecision can carry one
# without importing this module. Re-exported here because this is where a reader looks.
StepUpChallengeRead = StepUpChallenge


class StepUpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: uuid.UUID
    blocked_action_id: uuid.UUID = Field(
        description=(
            "The audit row of the refusal. Everything else — data class, target, hop, "
            "reason — is read from that row, never from the caller."
        )
    )


class StepUpComplete(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=1, max_length=128)
    approved: bool


class StepUpGrantRead(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: uuid.UUID
    session_id: uuid.UUID
    blocked_action_id: uuid.UUID
    data_class: str
    target: str
    approved: bool
    approved_by: str | None = None
    approved_at: datetime | None = None
    declined_at: datetime | None = None
    # The linked audit row recording the widening (FR-025). Null on a decline, and on an
    # approval whose event could not be written — which is visible rather than silent.
    audit_event_id: uuid.UUID | None = None


class CompletedHop(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hop: int = Field(ge=1)
    target: str
    action_id: uuid.UUID


class PartialOutcome(BaseModel):
    """What a chain that cannot resume gives back (FR-030).

    Names the hops that already ran, because some of them had side effects and the caller
    is the only one who can reason about those. A bare failure would leave them guessing
    how far the task got.
    """

    model_config = ConfigDict(extra="forbid")

    completed_hops: list[CompletedHop] = Field(default_factory=list)
    blocked_hop: int = Field(ge=1)
    blocked_target: str
    reason: DenyReason
    recoverable: bool
