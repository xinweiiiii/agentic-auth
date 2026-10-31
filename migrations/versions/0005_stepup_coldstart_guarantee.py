"""step-up consent, cold-start proposals and guarantee level

Revision ID: 0005_stepup_coldstart_guarantee
Revises: 0004_identity_taint_transactions
Create Date: 2026-09-27

Additive throughout.
**No existing row changes meaning**, which is what lets the whole Phase 1-4 suite pass
unchanged on this schema with every Phase 5 flag off:

1. ``step_up_grants``: append-only, one row per answered challenge.
2. ``sandbox_runs``: bounded observation of an agent with no manifest. NOT append-only —
   a run legitimately transitions ``running -> completed``.
3. ``sessions`` gains ``consented_data_classes``. NULL means "every data class the pinned
   policy declares", which is exactly Phase 2-4 semantics, so there is no backfill.
4. ``audit_decisions`` gains ``guarantee_level`` and ``step_up_ref``. NULL guarantee is a
   legacy row and is read as ``full`` — accurate, because every row written before this
   migration came from a per-hop enforcement point.
5. ``manifests`` gains the ``proposed`` status and ratification provenance.
6. Least-privilege grants for the runtime role.

Note on ordering: ``step_up_grants`` must exist before ``audit_decisions.step_up_ref``
references it, and ``sandbox_runs`` before ``manifests.proposed_from_run_id``.

``downgrade()`` drops every step-up grant and every observation run. The
``agentic_auth_writer`` role is left in place, as in 0004.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_stepup_coldstart_guarantee"
down_revision = "0004_identity_taint_transactions"
branch_labels = None
depends_on = None

# Frozen copy of the constant in agentic_auth/models/step_up_grant.py.
# tests/unit/test_audit_ddl.py asserts they are identical.
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
    "GRANT SELECT, INSERT, UPDATE ON sandbox_runs TO agentic_auth_writer",
)

_MANIFEST_STATUS_OLD = "status IN ('reconciled', 'needs_review', 'rejected')"
_MANIFEST_STATUS_NEW = "status IN ('reconciled', 'needs_review', 'rejected', 'proposed')"


def upgrade() -> None:
    # 1. step_up_grants -------------------------------------------------------
    op.create_table(
        "step_up_grants",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("session_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("blocked_action_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("data_class", sa.String(128), nullable=False),
        sa.Column("target", sa.String(512), nullable=False),
        # SHA-256 of the challenge id. The challenge value never lands anywhere durable.
        sa.Column("challenge_hash", sa.String(64), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("declined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"]),
        sa.ForeignKeyConstraint(
            ["blocked_action_id"],
            ["audit_decisions.id"],
            name="fk_step_up_grants_blocked_action",
        ),
        sa.UniqueConstraint("challenge_hash", name="uq_step_up_grants_challenge_hash"),
        sa.CheckConstraint(
            "(approved_at IS NULL) <> (declined_at IS NULL)",
            name="ck_step_up_grants_approved_xor_declined",
        ),
        sa.CheckConstraint(
            "(approved_by IS NULL) = (approved_at IS NULL)",
            name="ck_step_up_grants_approver_iff_approved",
        ),
        sa.CheckConstraint("data_class <> ''", name="ck_step_up_grants_data_class_nonempty"),
    )
    op.create_index(
        "ix_step_up_grants_session_created", "step_up_grants", ["session_id", "created_at"]
    )
    for statement in STEP_UP_APPEND_ONLY_SQL:
        op.execute(statement)

    # 2. sandbox_runs ---------------------------------------------------------
    op.create_table(
        "sandbox_runs",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("agent_id", sa.Uuid(as_uuid=True), nullable=False),
        # 24, not 16: "deadline_exceeded" is 17 characters.
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("scope", sa.String(255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trace", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("recorder_errors", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'deadline_exceeded', 'failed')",
            name="ck_sandbox_runs_status",
        ),
        sa.CheckConstraint(
            "(status = 'running') = (ended_at IS NULL)",
            name="ck_sandbox_runs_open_iff_no_end",
        ),
        sa.CheckConstraint("deadline_at > started_at", name="ck_sandbox_runs_deadline_after_start"),
        sa.CheckConstraint("recorder_errors >= 0", name="ck_sandbox_runs_recorder_errors_nonneg"),
    )
    # One run at a time per agent. Two concurrent traces racing to become one proposal is
    # a correctness problem, not a capacity one.
    op.create_index(
        "uq_sandbox_runs_one_running_per_agent",
        "sandbox_runs",
        ["agent_id"],
        unique=True,
        postgresql_where=sa.text("status = 'running'"),
    )
    op.create_index("ix_sandbox_runs_agent_started", "sandbox_runs", ["agent_id", "started_at"])

    # 3. sessions: consented subset ------------------------------------------
    # NULL = every data class the pinned policy declares = today's behaviour.
    op.add_column(
        "sessions",
        sa.Column("consented_data_classes", postgresql.ARRAY(sa.String(128)), nullable=True),
    )

    # 4. audit_decisions: guarantee level and the step-up link ----------------
    # Additive columns on an append-only table: the trigger rejects UPDATE/DELETE on
    # ROWS, not ALTER TABLE, so this is allowed and no existing row is rewritten.
    op.add_column("audit_decisions", sa.Column("guarantee_level", sa.String(16), nullable=True))
    op.add_column("audit_decisions", sa.Column("step_up_ref", sa.Uuid(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "fk_audit_decisions_step_up",
        "audit_decisions",
        "step_up_grants",
        ["step_up_ref"],
        ["id"],
    )
    op.create_index(
        "ix_audit_decisions_guarantee_level", "audit_decisions", ["guarantee_level", "seq"]
    )

    # 5. manifests: the proposed status and ratification provenance -----------
    op.drop_constraint("ck_manifests_status", "manifests", type_="check")
    op.create_check_constraint("ck_manifests_status", "manifests", _MANIFEST_STATUS_NEW)
    op.add_column(
        "manifests", sa.Column("proposed_from_run_id", sa.Uuid(as_uuid=True), nullable=True)
    )
    op.add_column("manifests", sa.Column("ratified_by", sa.String(255), nullable=True))
    op.add_column("manifests", sa.Column("ratified_at", sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key(
        "fk_manifests_proposed_from_run",
        "manifests",
        "sandbox_runs",
        ["proposed_from_run_id"],
        ["id"],
    )
    op.create_check_constraint(
        "ck_manifests_ratifier_iff_ratified",
        "manifests",
        "(ratified_by IS NULL) = (ratified_at IS NULL)",
    )
    op.create_check_constraint(
        "ck_manifests_proposal_pending_or_ratified",
        "manifests",
        "proposed_from_run_id IS NULL OR ratified_at IS NOT NULL OR status = 'proposed'",
    )
    op.create_index(
        "uq_manifests_proposed_from_run",
        "manifests",
        ["proposed_from_run_id"],
        unique=True,
        postgresql_where=sa.text("proposed_from_run_id IS NOT NULL"),
    )

    # 6. least-privilege grants ----------------------------------------------
    for statement in WRITER_GRANTS_SQL_0005:
        op.execute(statement)


def downgrade() -> None:
    op.drop_index("uq_manifests_proposed_from_run", table_name="manifests")
    op.drop_constraint("ck_manifests_proposal_pending_or_ratified", "manifests", type_="check")
    op.drop_constraint("ck_manifests_ratifier_iff_ratified", "manifests", type_="check")
    op.drop_constraint("fk_manifests_proposed_from_run", "manifests", type_="foreignkey")
    op.drop_column("manifests", "ratified_at")
    op.drop_column("manifests", "ratified_by")
    op.drop_column("manifests", "proposed_from_run_id")
    op.drop_constraint("ck_manifests_status", "manifests", type_="check")
    op.create_check_constraint("ck_manifests_status", "manifests", _MANIFEST_STATUS_OLD)

    op.drop_index("ix_audit_decisions_guarantee_level", table_name="audit_decisions")
    op.drop_constraint("fk_audit_decisions_step_up", "audit_decisions", type_="foreignkey")
    op.drop_column("audit_decisions", "step_up_ref")
    op.drop_column("audit_decisions", "guarantee_level")

    op.drop_column("sessions", "consented_data_classes")

    op.drop_index("ix_sandbox_runs_agent_started", table_name="sandbox_runs")
    op.drop_index("uq_sandbox_runs_one_running_per_agent", table_name="sandbox_runs")
    op.drop_table("sandbox_runs")

    op.execute("DROP TRIGGER IF EXISTS step_up_grants_no_update_delete ON step_up_grants")
    op.execute("DROP FUNCTION IF EXISTS step_up_grants_append_only()")
    op.drop_index("ix_step_up_grants_session_created", table_name="step_up_grants")
    op.drop_table("step_up_grants")
