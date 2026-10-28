"""Consent: the human act that roots all downstream authority."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

MIN_SESSION_TTL = 60
MAX_SESSION_TTL = 86_400
# A bound on the consented subset. Generous — a real scope declares a handful — but a
# request is attacker-shaped input and an unbounded list is an unbounded array column.
MAX_CONSENTED_DATA_CLASSES = 256


class ConsentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: str = Field(max_length=255, min_length=1)
    # Asserted by the integrator in this phase. Binding it to a verified IdP identity is
    # Phase 4's identity work.
    user_sub: str = Field(max_length=255, min_length=1)
    ttl_seconds: int | None = Field(default=None, ge=MIN_SESSION_TTL, le=MAX_SESSION_TTL)
    # Phase 5. The subset of the pinned policy's data classes this consent covers.
    #
    # Omitted (the default) means "everything the policy declares", which is exactly
    # Phase 2-4 semantics — so every existing caller is unaffected. Supplying a subset is
    # what makes SCOPE_NOT_CONSENTED mean "the human did not approve this" rather than
    # "the manifest never declared it", and therefore what makes step-up able to grant
    # anything at all (research.md R5).
    #
    # Validated against the pinned policy at consent time, not at first use: a typo
    # should surface to the integrator immediately, not as a refusal three hops into a
    # chain. Rejected entirely unless `consent_granularity_enabled`.
    data_classes: list[str] | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_CONSENTED_DATA_CLASSES,
        description=(
            "Subset of the pinned policy's data classes to consent to. Omit for all of "
            "them. Every entry must be declared by some agent in the compiled scope."
        ),
    )


class ConsentRead(BaseModel):
    """What the integrator gets back. ``root_grant`` is the hop-1 token."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    root_grant: str
    policy_version: int
    scope: str
    user_sub: str
    hop_budget: int
    expires_at: datetime
    # Phase 5. What was actually pinned: null means every class the policy declares.
    data_classes: list[str] | None = None


class SessionRead(BaseModel):
    """The session without any token material — for reads and diagnostics."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    scope: str
    user_sub: str
    policy_version: int
    hop_budget: int
    created_at: datetime
    expires_at: datetime
    data_classes: list[str] | None = None
