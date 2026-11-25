"""MCP OAuth 2.1 baseline: verified consent, client mappings

Revision ID: 0008_mcp_oauth_baseline
Revises: 0007_imported_audit

Feature 011 (authzai 0.4.0).

- ``sessions`` gains ``principal_source`` (``asserted`` | ``verified`` | ``embedded-test``),
  ``client_id`` and ``subject_token_hash``. The default reads every existing session as
  ``asserted``, which is what all of them were.
- ``audit_decisions`` gains ``principal_source`` and ``client_id``, both nullable with no
  backfill: the append-only trigger refuses UPDATE, and NULL honestly means "written before
  0.4.0 recorded it".
- ``agent_clients`` maps an IdP client to a registered agent. Rows are never deleted: a
  removal sets ``removed_at``, so the table is its own change history. A partial unique
  index keeps one active mapping per ``(issuer, client_id)``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_mcp_oauth_baseline"
down_revision = "0007_imported_audit"
branch_labels = None
depends_on = None

# Mappings are written by the control plane at runtime, and soft-removed with an UPDATE.
WRITER_GRANTS_SQL_0008 = ("GRANT SELECT, INSERT, UPDATE ON agent_clients TO agentic_auth_writer",)


def upgrade() -> None:
    op.add_column(
        "sessions",
        sa.Column("principal_source", sa.String(16), nullable=False, server_default="asserted"),
    )
    op.add_column("sessions", sa.Column("client_id", sa.String(255), nullable=True))
    op.add_column("sessions", sa.Column("subject_token_hash", sa.String(64), nullable=True))
    op.create_check_constraint(
        "ck_sessions_principal_source",
        "sessions",
        "principal_source IN ('asserted', 'verified', 'embedded-test')",
    )

    op.add_column("audit_decisions", sa.Column("principal_source", sa.String(16), nullable=True))
    op.add_column("audit_decisions", sa.Column("client_id", sa.String(255), nullable=True))

    op.create_table(
        "agent_clients",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("agent_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("client_id", sa.String(255), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("removed_by", sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], name="fk_agent_clients_agent"),
        sa.CheckConstraint("client_id <> ''", name="ck_agent_clients_client_id_nonempty"),
        sa.CheckConstraint("issuer <> ''", name="ck_agent_clients_issuer_nonempty"),
        sa.CheckConstraint(
            "(removed_at IS NULL) = (removed_by IS NULL)",
            name="ck_agent_clients_removed_by_iff_removed",
        ),
    )
    op.create_index(
        "uq_agent_clients_active",
        "agent_clients",
        ["issuer", "client_id"],
        unique=True,
        postgresql_where=sa.text("removed_at IS NULL"),
        sqlite_where=sa.text("removed_at IS NULL"),
    )
    op.create_index("ix_agent_clients_agent_created", "agent_clients", ["agent_id", "created_at"])
    for statement in WRITER_GRANTS_SQL_0008:
        op.execute(statement)


def downgrade() -> None:
    op.drop_index("ix_agent_clients_agent_created", table_name="agent_clients")
    op.drop_index("uq_agent_clients_active", table_name="agent_clients")
    op.drop_table("agent_clients")
    op.drop_column("audit_decisions", "client_id")
    op.drop_column("audit_decisions", "principal_source")
    op.drop_constraint("ck_sessions_principal_source", "sessions", type_="check")
    op.drop_column("sessions", "subject_token_hash")
    op.drop_column("sessions", "client_id")
    op.drop_column("sessions", "principal_source")
