"""``sessions`` — the unit of consented authority.

Immutable after insert. No column is ever updated: that is what keeps the PDP stateless,
since nothing accumulates across hops and a session read is a pure lookup.

**Phase 5 does not change that.** Step-up widens a session, but it does so by appending a
``step_up_grants`` row and a Redis set entry that the decision reads alongside the taint
hash and the revoked set — never by updating this table. Mutating a row here would
invalidate ``session:{id}`` mid-flight and give the PDP a second source of truth for a
decision input (research.md R6).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    ARRAY,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base, TimestampCreated, UUIDPrimaryKey


class Session(UUIDPrimaryKey, TimestampCreated, Base):
    __tablename__ = "sessions"
    __table_args__ = (
        # A session can only pin a policy version that exists.
        ForeignKeyConstraint(
            ["scope", "policy_version"],
            ["compiled_policies.scope", "compiled_policies.version"],
            name="fk_sessions_compiled_policy",
        ),
        CheckConstraint("hop_budget >= 1", name="ck_sessions_hop_budget_positive"),
        CheckConstraint("expires_at > created_at", name="ck_sessions_expiry_after_creation"),
        CheckConstraint("user_sub <> ''", name="ck_sessions_user_sub_nonempty"),
        Index("ix_sessions_expires_at", "expires_at"),
    )

    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    user_sub: Mapped[str] = mapped_column(String(255), nullable=False)
    # Pinned at consent. Every decision in this session resolves against it, even if a
    # newer policy version is published mid-chain.
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    hop_budget: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Phase 5. The subset of the pinned policy's data classes this consent covers.
    #
    # NULL means "every data class the pinned policy declares", which is exactly Phase 2-4
    # semantics — so there is no backfill and no existing row changes meaning. A non-null
    # array is validated against the pinned policy at consent time, not at first use, so a
    # typo surfaces to the integrator immediately instead of as a refusal three hops in.
    #
    # Still immutable: step-up appends a `step_up_grants` row, it does not extend this
    # array (research.md R5, R6).
    consented_data_classes: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(128)), nullable=True
    )
