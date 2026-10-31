"""``step_up_grants`` — one append-only row per answered step-up challenge.

A widening a human approved is a security fact, and a security fact that can be edited is
not evidence. Same trigger shape as ``audit_decisions`` and ``transaction_tokens``; the
runtime role holds ``SELECT, INSERT`` only.

Three things this table makes true in the database rather than in code:

- **A grant is an approval or a decline, never both and never neither.**
- **An approval always names who approved it.** An anonymous widening is not consent.
- **A challenge can be answered once.** ``UNIQUE (challenge_hash)`` is the durable twin of
  the Redis ``GETDEL``: even if the cache were lost and a challenge replayed, the second
  insert is an ``IntegrityError``.

**The ceiling is enforced before the insert, not here.** ``data_class`` is checked against
``PolicyIndex.data_classes_by_agent`` in :mod:`agentic_auth.services.stepup`, so a row outside the
pinned policy cannot exist. A check constraint could not express it: the policy
lives in another table, versioned per session.

The challenge value itself is never stored — only its SHA-256.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from agentic_auth.models import Base, UUIDPrimaryKey
from agentic_auth.models.types import TZDateTime, install_append_only

# Duplicated, frozen, in migrations/versions/0005_stepup_coldstart_guarantee.py.
# tests/unit/test_audit_ddl.py fails if the two drift apart.
STEP_UP_APPEND_ONLY_SQL = (
    """CREATE OR REPLACE FUNCTION step_up_grants_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'step_up_grants is append-only' USING ERRCODE = '55000';
END;
$$""",
    """CREATE TRIGGER step_up_grants_no_update_delete
BEFORE UPDATE OR DELETE ON step_up_grants
FOR EACH ROW EXECUTE FUNCTION step_up_grants_append_only()""",
)

WRITER_GRANTS_SQL_0005 = (
    "GRANT SELECT, INSERT ON step_up_grants TO agentic_auth_writer",
    # A run legitimately transitions running -> completed, so this one is updatable.
    "GRANT SELECT, INSERT, UPDATE ON sandbox_runs TO agentic_auth_writer",
)


class StepUpGrant(UUIDPrimaryKey, Base):
    __tablename__ = "step_up_grants"
    __table_args__ = (
        CheckConstraint(
            "(approved_at IS NULL) <> (declined_at IS NULL)",
            name="ck_step_up_grants_approved_xor_declined",
        ),
        CheckConstraint(
            "(approved_by IS NULL) = (approved_at IS NULL)",
            name="ck_step_up_grants_approver_iff_approved",
        ),
        CheckConstraint("data_class <> ''", name="ck_step_up_grants_data_class_nonempty"),
        Index("ix_step_up_grants_session_created", "session_id", "created_at"),
    )

    session_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("sessions.id"), nullable=False
    )
    # The refusal that raised the challenge. This is the audit link: the widening event
    # carries `step_up_ref` back to this row, and this row points at the deny it answers.
    blocked_action_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("audit_decisions.id", name="fk_step_up_grants_blocked_action"),
        nullable=False,
    )
    # What was granted. Always within the pinned policy's ceiling; see the module docstring.
    data_class: Mapped[str] = mapped_column(String(128), nullable=False)
    # The blocked hop's target, so an operator reading the row does not have to join.
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    # SHA-256 (hex) of the challenge id. The challenge itself never lands anywhere durable.
    challenge_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # The consenting human's sub. NULL on a decline.
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    declined_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, server_default=func.now(), nullable=False
    )

    @property
    def approved(self) -> bool:
        return self.approved_at is not None


install_append_only(StepUpGrant.__table__, STEP_UP_APPEND_ONLY_SQL)
