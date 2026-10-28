"""``sandbox_runs`` — one bounded observation of an agent that has no manifest yet.

Deliberately **not** append-only, unlike the other Phase 4/5 record tables: a run
legitimately transitions ``running -> completed``. The durability guarantee lives on the
artefact the run produces — a ratified manifest is immutable — not on the observation.

Two invariants are in the database:

- **One run at a time per agent.** A partial unique index on ``agent_id WHERE status =
  'running'``. Two concurrent traces racing to become one proposal is a correctness
  problem, not a capacity one, so the second start is a ``409``.
- **A run is open exactly while it has no end.** ``(status = 'running') = (ended_at IS
  NULL)``, so a crashed run cannot sit as ``completed`` with nothing recorded.

``recorder_errors`` is carried out of the ``EdgeTrace``. Non-zero means observation was
incomplete, so the proposal may be narrower than the agent's real behaviour — and the
proposal says so rather than silently under-declaring.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.models import Base, UUIDPrimaryKey

STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_DEADLINE_EXCEEDED = "deadline_exceeded"
STATUS_FAILED = "failed"

STATUSES = (STATUS_RUNNING, STATUS_COMPLETED, STATUS_DEADLINE_EXCEEDED, STATUS_FAILED)


class SandboxRun(UUIDPrimaryKey, Base):
    __tablename__ = "sandbox_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'completed', 'deadline_exceeded', 'failed')",
            name="ck_sandbox_runs_status",
        ),
        CheckConstraint(
            "(status = 'running') = (ended_at IS NULL)",
            name="ck_sandbox_runs_open_iff_no_end",
        ),
        CheckConstraint("deadline_at > started_at", name="ck_sandbox_runs_deadline_after_start"),
        CheckConstraint("recorder_errors >= 0", name="ck_sandbox_runs_recorder_errors_nonneg"),
        # One run at a time per agent. Partial, so completed runs accumulate freely.
        Index(
            "uq_sandbox_runs_one_running_per_agent",
            "agent_id",
            unique=True,
            postgresql_where=("status = 'running'"),
        ),
        Index("ix_sandbox_runs_agent_started", "agent_id", "started_at"),
    )

    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("agents.id"), nullable=False
    )
    # 24, not 16: "deadline_exceeded" is 17 characters. A column too narrow for its own
    # longest legal value is a bug that only shows up on the unhappy path.
    status: Mapped[str] = mapped_column(String(24), nullable=False, default=STATUS_RUNNING)
    # The scope the run is driven under — a synthetic all-allow scope, not a real one.
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # started_at + sandbox_run_deadline_seconds. The run ends here whether or not the
    # agent stopped (FR-033).
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # The folded EdgeTrace. NULL while running.
    trace: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    recorder_errors: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    @property
    def open(self) -> bool:
        return self.status == STATUS_RUNNING
