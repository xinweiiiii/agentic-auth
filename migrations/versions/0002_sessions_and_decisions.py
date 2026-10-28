"""sessions & decisions — the runtime plane

Revision ID: 0002_sessions_and_decisions
Revises: 0001_manifest_and_dag
Create Date: 2026-09-06

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_sessions_and_decisions"
down_revision = "0001_manifest_and_dag"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scope", sa.String(255), nullable=False),
        sa.Column("user_sub", sa.String(255), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("hop_budget", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        # A session can only pin a policy version that exists.
        sa.ForeignKeyConstraint(
            ["scope", "policy_version"],
            ["compiled_policies.scope", "compiled_policies.version"],
            name="fk_sessions_compiled_policy",
        ),
        sa.CheckConstraint("hop_budget >= 1", name="ck_sessions_hop_budget_positive"),
        sa.CheckConstraint("expires_at > created_at", name="ck_sessions_expiry_after_creation"),
        sa.CheckConstraint("user_sub <> ''", name="ck_sessions_user_sub_nonempty"),
    )
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])

    op.create_table(
        "decisions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("session_id", sa.Uuid(), sa.ForeignKey("sessions.id"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("caller", sa.String(255), nullable=False),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("data_class", sa.String(128), nullable=False),
        sa.Column("hop", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(8), nullable=False),
        sa.Column("deny_reason", sa.String(32), nullable=True),
        sa.Column("recoverable", sa.Boolean(), nullable=False),
        sa.Column("enforced", sa.Boolean(), nullable=False),
        sa.Column("taint", sa.String(32), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("act_chain", postgresql.JSONB(), nullable=False),
        sa.CheckConstraint("outcome IN ('allow', 'deny')", name="ck_decisions_outcome"),
        # An allow can never carry a reason; a deny can never lack one.
        sa.CheckConstraint(
            "(outcome = 'deny') = (deny_reason IS NOT NULL)",
            name="ck_decisions_reason_iff_deny",
        ),
        sa.CheckConstraint("hop >= 1", name="ck_decisions_hop_positive"),
    )
    op.create_index("ix_decisions_session_ts", "decisions", ["session_id", "ts"])
    op.create_index("ix_decisions_outcome_enforced", "decisions", ["outcome", "enforced"])
    op.create_index("ix_decisions_ts", "decisions", ["ts"])


def downgrade() -> None:
    op.drop_table("decisions")
    op.drop_table("sessions")
