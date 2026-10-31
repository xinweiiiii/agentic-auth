"""imported_audit: decisions carried over from another deployment

Revision ID: 0007_imported_audit
Revises: 0006_audit_deployment

``agentic-auth audit import`` writes an embedded control plane's exported decisions here,
apart from this deployment's own ``audit_decisions`` (agentic_auth/models/imported_audit.py
says why). Append-only, with the same trigger shape as migrations 0003-0005. The runtime role
gets no grant: importing is an owner-run step.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_imported_audit"
down_revision = "0006_audit_deployment"
branch_labels = None
depends_on = None

# Frozen copy of the constant in agentic_auth/models/imported_audit.py.
# tests/unit/test_audit_ddl.py asserts they are identical.
IMPORTED_AUDIT_APPEND_ONLY_SQL = (
    """CREATE OR REPLACE FUNCTION imported_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'imported_audit is append-only' USING ERRCODE = '55000';
END;
$$""",
    """CREATE TRIGGER imported_audit_no_update_delete
BEFORE UPDATE OR DELETE ON imported_audit
FOR EACH ROW EXECUTE FUNCTION imported_audit_append_only()""",
)


def upgrade() -> None:
    op.create_table(
        "imported_audit",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("action_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("source_deployment", sa.String(16), nullable=False),
        sa.Column("source_package_version", sa.String(32), nullable=False),
        sa.Column("exported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "imported_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("row", sa.dialects.postgresql.JSONB(), nullable=False),
    )
    for statement in IMPORTED_AUDIT_APPEND_ONLY_SQL:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS imported_audit_no_update_delete ON imported_audit")
    op.execute("DROP FUNCTION IF EXISTS imported_audit_append_only()")
    op.drop_table("imported_audit")
