"""The audit plane's read models — see contracts/audit-plane.openapi.yaml.

Separate read shapes for the single-action chain and (later) the history list, per
CLAUDE.md. Nothing here is ever written back: audit data has no create or update schema,
because nothing creates or updates it through the API.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializationInfo,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from app.boundary.guarantee import Guarantee
from app.schemas.authorize import DenyReason
from app.services.audit_chain import ChainBreak


class RootConsent(BaseModel):
    """The human at the start of every chain, and what they approved."""

    model_config = ConfigDict(extra="forbid")

    user_sub: str
    scope: str
    consented_at: datetime
    session_id: uuid.UUID


class ChainBreakRead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    at_hop: int = Field(ge=1, description="The first hop whose link could not be established")
    reason: ChainBreak


class TransactionFingerprint(BaseModel):
    """The FR-042 fingerprint of a privileged call's transaction token: the binding digest
    and lifetime, never the token. Joined from ``transaction_tokens`` on ``action_id``."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    params_hash: str
    binding: list[str] | None
    issued_at: datetime
    expires_at: datetime


class ChainHop(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hop: int = Field(ge=1)
    action_id: uuid.UUID | None
    acting_agent: str | None
    target: str | None
    target_kind: Literal["tool", "agent"] | None
    data_class: str | None
    decision: Literal["allow", "deny"] | None
    deny_reason: DenyReason | None
    enforced: bool | None
    ts: datetime | None
    # Phase 4, additive. Absent on hops written before it (reported as null / false).
    subject_jti: str | None = None
    taint: Literal["trusted_internal", "untrusted_external"] | None = None
    taint_source: str | None = None
    privileged: bool = False
    # Only the queried action's own hop can carry this (the join is on ITS row); null
    # elsewhere and for non-privileged or never-minted calls.
    transaction: TransactionFingerprint | None = None
    # Phase 5, additive. How strong the enforcement actually was for this hop. A row
    # written before the field exists reads as `full` — accurate rather than a guess,
    # because every enforcement point that produced one was per-hop.
    guarantee_level: Guarantee = Guarantee.FULL
    step_up_ref: uuid.UUID | None = None
    # True only on hops of a legacy record whose detail was never captured. Omitted
    # otherwise, so a complete chain carries no field suggesting anything is missing.
    unavailable: bool = False

    @model_serializer(mode="wrap")
    def _omit_available(
        self, handler: SerializerFunctionWrapHandler, _info: SerializationInfo
    ) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if not self.unavailable:
            data.pop("unavailable", None)
        return data


class ChainRead(BaseModel):
    """One recorded action's full delegation path, from one row plus its session."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    action_id: uuid.UUID
    complete: bool
    # `break` is a Python keyword; the wire name is still `break`.
    chain_break: ChainBreakRead | None = Field(
        default=None, serialization_alias="break", validation_alias="break"
    )
    root_consent: RootConsent
    policy_version: int
    chain: list[ChainHop] = Field(min_length=1)


# -- decision history ---------------------------------------------------------------


class AuditDecisionFilter(BaseModel):
    """Every filter ``GET /v1/audit/decisions`` accepts. Unknown parameters are refused."""

    model_config = ConfigDict(extra="forbid")

    session_id: uuid.UUID | None = None
    agent: str | None = Field(default=None, max_length=255, description="Verified acting agent")
    outcome: Literal["allow", "deny"] | None = None
    deny_reason: DenyReason | None = None
    enforced: bool | None = None
    target_kind: Literal["tool", "agent"] | None = None
    since: datetime | None = None
    until: datetime | None = None
    # Phase 4
    taint: Literal["trusted_internal", "untrusted_external"] | None = None
    privileged: bool | None = None
    # Phase 5. "Show me everything that ran below full guarantee" is the operator question
    # FR-021 exists to answer, and it needs to be answerable over history, not only as a
    # live counter.
    guarantee_level: Guarantee | None = None
    step_up_ref: uuid.UUID | None = None

    @field_validator("since", "until")
    @classmethod
    def _timezone_aware(cls, value: datetime | None) -> datetime | None:
        # A naive timestamp would be compared against UTC rows under an assumed zone.
        if value is not None and value.tzinfo is None:
            raise ValueError("must include a timezone")
        return value

    @model_validator(mode="after")
    def _ordered(self) -> AuditDecisionFilter:
        if self.since is not None and self.until is not None and self.since > self.until:
            raise ValueError("since must not be after until")
        return self


class AuditDecisionListItem(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: uuid.UUID
    ts: datetime
    session_id: uuid.UUID
    acting_agent: str | None
    caller: str
    target: str
    target_kind: Literal["tool", "agent"]
    data_class: str
    hop: int
    outcome: Literal["allow", "deny"]
    deny_reason: DenyReason | None
    enforced: bool
    policy_version: int
    chain_complete: bool
    # Phase 4, additive; null / false on rows written before it.
    taint: Literal["trusted_internal", "untrusted_external"] | None = None
    taint_source: str | None = None
    privileged: bool = False
    transaction: TransactionFingerprint | None = None
    # Phase 5, additive. NULL in the column reads as `full` (see ChainHop).
    guarantee_level: Guarantee = Guarantee.FULL
    step_up_ref: uuid.UUID | None = None

    @field_validator("guarantee_level", mode="before")
    @classmethod
    def _legacy_rows_are_full(cls, value: object) -> object:
        """A NULL column is a pre-Phase-5 row, and every one of those came from the
        sidecar or the control plane's own path — both per-hop. Reading it as `full` is
        accurate; leaving it null would make honest old rows look suspicious."""
        return Guarantee.FULL if value is None else value


class AuditPageInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    next_cursor: str | None
    limit: int
    # The high-water mark this iteration is fixed to. Null only when nothing is recorded.
    as_of_seq: int | None


class AuditDecisionPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: list[AuditDecisionListItem]
    page: AuditPageInfo
