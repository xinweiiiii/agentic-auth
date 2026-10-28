"""``manifests`` — append-only, server-versioned agent manifests."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import Uuid

from app.models import Base, TimestampCreated, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.reconciliation_report import ReconciliationReport

MANIFEST_STATUSES = ("reconciled", "needs_review", "rejected", "proposed")

# Phase 5. A proposal is inert: it is never compiled, so no session can pin it and no
# decision can resolve against it. Every read path that feeds a decision filters it out
# (research.md R12).
STATUS_PROPOSED = "proposed"
RESOLVABLE_STATUSES = ("reconciled", "needs_review", "rejected")


class Manifest(UUIDPrimaryKey, TimestampCreated, Base):
    __tablename__ = "manifests"
    __table_args__ = (
        UniqueConstraint("agent_id", "version", name="uq_manifests_agent_version"),
        CheckConstraint("version >= 1", name="ck_manifests_version_positive"),
        CheckConstraint(
            # Phase 5 adds 'proposed': an observation-derived candidate that governs
            # nothing. Inertness is a read-path property, not a constraint — a proposed
            # row is never compiled, so no session can pin it (research.md R12).
            "status IN ('reconciled', 'needs_review', 'rejected', 'proposed')",
            name="ck_manifests_status",
        ),
        CheckConstraint(
            "status <> 'reconciled' OR override_reason IS NULL OR override_reason <> ''",
            name="ck_manifests_override_reason_nonempty",
        ),
        CheckConstraint("attested_by <> ''", name="ck_manifests_attested_by_nonempty"),
        # Phase 5. An approval always names who approved it; an anonymous ratification is
        # not a human decision.
        CheckConstraint(
            "(ratified_by IS NULL) = (ratified_at IS NULL)",
            name="ck_manifests_ratifier_iff_ratified",
        ),
        # An observation-derived manifest is either still proposed or has been ratified.
        # A hand-written manifest has neither a run nor a ratifier and stays legal.
        CheckConstraint(
            "proposed_from_run_id IS NULL OR ratified_at IS NOT NULL OR status = 'proposed'",
            name="ck_manifests_proposal_pending_or_ratified",
        ),
        # One proposal per run, and therefore one ratification (FR-040).
        Index(
            "uq_manifests_proposed_from_run",
            "proposed_from_run_id",
            unique=True,
            postgresql_where=("proposed_from_run_id IS NOT NULL"),
        ),
    )

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    doc: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    attested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    override_reason: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # Phase 5. The sandbox run this manifest was proposed from, or NULL for a
    # hand-written one. Ratification is recorded here rather than in a second table, so
    # "what the administrator approved" and "what got pinned" are one row that cannot
    # differ (research.md R12).
    proposed_from_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("sandbox_runs.id", name="fk_manifests_proposed_from_run"),
        nullable=True,
    )
    ratified_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ratified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    agent: Mapped[Agent] = relationship(back_populates="manifests")
    reconciliation_report: Mapped[ReconciliationReport | None] = relationship(
        back_populates="manifest", uselist=False
    )
