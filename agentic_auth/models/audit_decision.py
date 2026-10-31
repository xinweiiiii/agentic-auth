"""``audit_decisions`` — one append-only row per authorization decision.

Phase 2's ``decisions`` table, renamed and extended in Phase 3 (migration 0003). ``id`` is
the action id. Three things hold for every row, forever:

- **Nothing updates or deletes it.** A trigger rejects ``UPDATE`` and ``DELETE`` for every
  role, the table owner included, and the runtime role holds only ``SELECT, INSERT``. The
  trigger is also attached below via ``after_create``, so the ``create_all()`` test schema
  enforces exactly what the migration does.
- **Its chain is decided once.** ``chain`` is materialized at write time from the parent row
  named by the verified token's ``action_id`` claim; ``chain_complete`` never changes after.
- **It carries no secrets.** No token, credential, or payload is a column.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    UniqueConstraint,
    event,
    func,
    select,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from agentic_auth.models import Base, UUIDPrimaryKey
from agentic_auth.models.types import PortableJSON, TZDateTime, install_append_only

TARGET_KIND_AGENT = "agent"
TARGET_KIND_TOOL = "tool"

# The SQL below is duplicated, frozen, in migrations/versions/0003_audit_decisions.py.
# tests/unit/test_audit_ddl.py fails if the two drift apart.
APPEND_ONLY_SQL = (
    """CREATE OR REPLACE FUNCTION audit_decisions_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_decisions is append-only' USING ERRCODE = '55000';
END;
$$""",
    """CREATE TRIGGER audit_decisions_no_update_delete
BEFORE UPDATE OR DELETE ON audit_decisions
FOR EACH ROW EXECUTE FUNCTION audit_decisions_append_only()""",
)

WRITER_ROLE_SQL = """DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agentic_auth_writer') THEN
        CREATE ROLE agentic_auth_writer NOLOGIN;
    END IF;
END
$$"""

WRITER_GRANTS_SQL = (
    "GRANT USAGE ON SCHEMA public TO agentic_auth_writer",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON agents, manifests, compiled_policies, "
    "reconciliation_reports TO agentic_auth_writer",
    "GRANT SELECT, INSERT ON sessions TO agentic_auth_writer",
    "GRANT SELECT, INSERT ON audit_decisions TO agentic_auth_writer",
)


def target_kind_of(target: str) -> str:
    """Derived from the target itself — never accepted from a caller."""
    return TARGET_KIND_AGENT if target.startswith("agent://") else TARGET_KIND_TOOL


class AuditDecision(UUIDPrimaryKey, Base):
    __tablename__ = "audit_decisions"
    __table_args__ = (
        CheckConstraint("outcome IN ('allow', 'deny')", name="ck_audit_decisions_outcome"),
        # An allow can never carry a reason; a deny can never lack one.
        CheckConstraint(
            "(outcome = 'deny') = (deny_reason IS NOT NULL)",
            name="ck_audit_decisions_reason_iff_deny",
        ),
        CheckConstraint("hop >= 1", name="ck_audit_decisions_hop_positive"),
        CheckConstraint("target_kind IN ('tool', 'agent')", name="ck_audit_decisions_target_kind"),
        CheckConstraint(
            "NOT chain_complete OR chain IS NOT NULL",
            name="ck_audit_decisions_complete_has_chain",
        ),
        # Incomplete always says why; complete never carries a reason.
        CheckConstraint(
            "chain_complete = (chain_break IS NULL)",
            name="ck_audit_decisions_break_iff_incomplete",
        ),
        CheckConstraint(
            "hop > 1 OR parent_action_id IS NULL", name="ck_audit_decisions_root_has_no_parent"
        ),
        UniqueConstraint("seq", name="uq_audit_decisions_seq"),
        Index("ix_audit_decisions_session_seq", "session_id", "seq"),
        Index("ix_audit_decisions_acting_agent_seq", "acting_agent", "seq"),
        Index("ix_audit_decisions_outcome_seq", "outcome", "seq"),
        Index("ix_audit_decisions_outcome_enforced", "outcome", "enforced"),
        Index("ix_audit_decisions_ts", "ts"),
        Index("ix_audit_decisions_parent_action_id", "parent_action_id"),
    )
    # `seq` and `ts` are server-generated; fetch them with the INSERT so no lazy load is
    # ever attempted on an async session.
    __mapper_args__ = {"eager_defaults": True}

    # Monotonic insertion order — the pagination key.
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), nullable=False)
    session_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("sessions.id"), nullable=False
    )
    ts: Mapped[datetime] = mapped_column(TZDateTime, server_default=func.now(), nullable=False)
    # Request `caller` as sent (`user:<sub>` at hop 1).
    caller: Mapped[str] = mapped_column(String(255), nullable=False)
    # The verified token holder. NULL for a tool-call token and for every legacy row.
    acting_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    target_kind: Mapped[str] = mapped_column(String(8), nullable=False)
    data_class: Mapped[str] = mapped_column(String(128), nullable=False)
    # Derived from the verified act chain, never from a caller-supplied value.
    hop: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(8), nullable=False)
    deny_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    recoverable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # False in observe mode. Makes every record unambiguous about what actually happened.
    enforced: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Phase 4: the EFFECTIVE taint the decision was made under (trusted_internal |
    # untrusted_external), or NULL when unknown. Before Phase 4 it echoed the request.
    taint: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The target that introduced the taint into this context, or NULL.
    taint_source: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # The target was privileged in the pinned policy.
    privileged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # Denormalized from the session so a record reads standalone.
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # The verified actors at decision time: [human, previous actors...].
    act_chain: Mapped[list[Any]] = mapped_column(PortableJSON, nullable=False)
    # `jti` of the presented token. The exchange binds to it. NULL on legacy rows.
    subject_jti: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parent_action_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("audit_decisions.id", name="fk_audit_decisions_parent_action"),
        nullable=True,
    )
    chain: Mapped[list[dict[str, Any]] | None] = mapped_column(PortableJSON, nullable=True)
    chain_complete: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    chain_break: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Phase 5: how strong the enforcement actually was for this decision — one of
    # full | connector | network | consent_only. Reported by the enforcement point on the
    # request, exactly as `enforced` is, and never an input to the decision.
    #
    # NULL is only ever a legacy row, and is READ AS `full`. That is accurate rather than
    # a guess: every row written before migration 0005 came from the sidecar or the
    # control plane's own path, both of which are per-hop.
    #
    # There is deliberately no NOT NULL constraint — adding one would require rewriting
    # legacy rows, which the append-only trigger forbids. The not-null property is
    # enforced at the write path instead, where the value comes off a StrEnum with no
    # default, so a PEP that omits it gets a 422.
    guarantee_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Which deployment wrote the row: the control plane (`server`) or an embedded instance
    # inside the calling process (`embedded`, development and testing only). Additive; every
    # row written before the column existed came from a server.
    deployment: Mapped[str] = mapped_column(
        String(16), nullable=False, default="server", server_default="server"
    )
    # Set on the audit event that records a step-up widening, pointing at the grant that
    # authorized it. NULL on every ordinary decision.
    step_up_ref: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("step_up_grants.id", name="fk_audit_decisions_step_up"),
        nullable=True,
    )


install_append_only(AuditDecision.__table__, APPEND_ONLY_SQL)


@event.listens_for(AuditDecision, "before_insert")
def _assign_seq_on_sqlite(_mapper: Any, connection: Any, target: AuditDecision) -> None:
    """SQLite has no identity column that is not the primary key, so the embedded store
    numbers rows itself. Safe because every embedded transaction begins IMMEDIATE, so no two
    writers ever read the same maximum (agentic_auth/embedded/store.py). PostgreSQL keeps
    ``GENERATED ALWAYS``, which would refuse an explicit value — hence the dialect check."""
    if connection.dialect.name != "sqlite" or target.seq is not None:
        return
    target.seq = connection.scalar(select(func.coalesce(func.max(AuditDecision.seq), 0) + 1))
