"""manifest, registration, reconciliation & the scope->capability DAG

Revision ID: 0001_manifest_and_dag
Revises:
Create Date: 2026-09-01

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_manifest_and_dag"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("principal_ref", sa.String(255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("name", name="uq_agents_name"),
    )
    op.create_index("ix_agents_name", "agents", ["name"])

    op.create_table(
        "manifests",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("agent_id", sa.Uuid(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("doc", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attested_by", sa.String(255), nullable=False),
        sa.Column("override_reason", sa.String(1024), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("agent_id", "version", name="uq_manifests_agent_version"),
        sa.CheckConstraint("version >= 1", name="ck_manifests_version_positive"),
        sa.CheckConstraint(
            "status IN ('reconciled', 'needs_review', 'rejected')", name="ck_manifests_status"
        ),
        sa.CheckConstraint(
            "status <> 'reconciled' OR override_reason IS NULL OR override_reason <> ''",
            name="ck_manifests_override_reason_nonempty",
        ),
        sa.CheckConstraint("attested_by <> ''", name="ck_manifests_attested_by_nonempty"),
    )
    op.create_index("ix_manifests_agent_id", "manifests", ["agent_id"])

    op.create_table(
        "compiled_policies",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scope", sa.String(255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("dag", postgresql.JSONB(), nullable=False),
        sa.Column("source_manifest_ids", postgresql.ARRAY(sa.Uuid()), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("scope", "version", name="uq_compiled_policies_scope_version"),
        sa.CheckConstraint("version >= 1", name="ck_compiled_policies_version_positive"),
    )
    op.create_index("ix_compiled_policies_scope", "compiled_policies", ["scope"])

    op.create_table(
        "reconciliation_reports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("manifest_id", sa.Uuid(), sa.ForeignKey("manifests.id"), nullable=False),
        sa.Column("diff", postgresql.JSONB(), nullable=False),
        sa.Column("discovery_ok", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("manifest_id", name="uq_reconciliation_reports_manifest_id"),
    )
    op.create_index(
        "ix_reconciliation_reports_manifest_id", "reconciliation_reports", ["manifest_id"]
    )


def downgrade() -> None:
    op.drop_table("reconciliation_reports")
    op.drop_table("compiled_policies")
    op.drop_table("manifests")
    op.drop_table("agents")
