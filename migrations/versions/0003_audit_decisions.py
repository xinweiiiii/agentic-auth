"""audit_decisions — the append-only audit log

Revision ID: 0003_audit_decisions
Revises: 0002_sessions_and_decisions
Create Date: 2026-09-13

Renames ``decisions`` to ``audit_decisions`` so every Phase 2 row survives, extends it
additively, backfills only what can be derived without guessing, and **only then** installs
the append-only trigger — the backfill is the last mutation this table will ever accept.

``downgrade()`` drops the Phase 3 columns: materialized chains and parent linkage are
destroyed. The ``agentic_auth_writer`` role is left in place, since roles are cluster-wide.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_audit_decisions"
down_revision = "0002_sessions_and_decisions"
branch_labels = None
depends_on = None

# Frozen copies of the constants in app/models/audit_decision.py.
# tests/unit/test_audit_ddl.py asserts they are identical, so the migrated schema and the
# create_all() test schema enforce exactly the same rule.
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

_RENAMED_CHECKS = (
    ("ck_decisions_outcome", "ck_audit_decisions_outcome"),
    ("ck_decisions_reason_iff_deny", "ck_audit_decisions_reason_iff_deny"),
    ("ck_decisions_hop_positive", "ck_audit_decisions_hop_positive"),
)
_RENAMED_INDEXES = (
    ("ix_decisions_outcome_enforced", "ix_audit_decisions_outcome_enforced"),
    ("ix_decisions_ts", "ix_audit_decisions_ts"),
)
_NEW_CHECKS = (
    ("ck_audit_decisions_target_kind", "target_kind IN ('tool', 'agent')"),
    ("ck_audit_decisions_complete_has_chain", "NOT chain_complete OR chain IS NOT NULL"),
    ("ck_audit_decisions_break_iff_incomplete", "chain_complete = (chain_break IS NULL)"),
    ("ck_audit_decisions_root_has_no_parent", "hop > 1 OR parent_action_id IS NULL"),
)
_NEW_INDEXES = (
    ("ix_audit_decisions_session_seq", ["session_id", "seq"]),
    ("ix_audit_decisions_acting_agent_seq", ["acting_agent", "seq"]),
    ("ix_audit_decisions_outcome_seq", ["outcome", "seq"]),
    ("ix_audit_decisions_parent_action_id", ["parent_action_id"]),
)


def upgrade() -> None:
    # 1. rename, keeping every row
    op.rename_table("decisions", "audit_decisions")
    op.drop_index("ix_decisions_session_ts", table_name="audit_decisions")
    for old, new in _RENAMED_INDEXES:
        op.execute(f"ALTER INDEX IF EXISTS {old} RENAME TO {new}")
    for old, new in _RENAMED_CHECKS:
        op.execute(f"ALTER TABLE audit_decisions RENAME CONSTRAINT {old} TO {new}")

    # 2. additive columns, nullable until backfilled
    op.add_column("audit_decisions", sa.Column("seq", sa.BigInteger(), nullable=True))
    op.add_column("audit_decisions", sa.Column("acting_agent", sa.String(255), nullable=True))
    op.add_column("audit_decisions", sa.Column("target_kind", sa.String(8), nullable=True))
    op.add_column("audit_decisions", sa.Column("subject_jti", sa.String(64), nullable=True))
    op.add_column("audit_decisions", sa.Column("parent_action_id", sa.Uuid(), nullable=True))
    op.add_column("audit_decisions", sa.Column("chain", postgresql.JSONB(), nullable=True))
    op.add_column(
        "audit_decisions",
        sa.Column("chain_complete", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("audit_decisions", sa.Column("chain_break", sa.String(32), nullable=True))

    # 3. backfill — before the trigger exists. `acting_agent` stays NULL on purpose: a
    #    Phase 2 row never stored the verified token holder (`act_chain` holds only the
    #    PREVIOUS actors, and `caller` is request input also recorded on caller-mismatch
    #    denies), so any value here would be a guess.
    op.execute(
        """
        UPDATE audit_decisions AS d SET
            seq = o.rn,
            target_kind = CASE WHEN left(d.target, 8) = 'agent://' THEN 'agent' ELSE 'tool' END,
            chain_break = 'LEGACY_RECORD'
        FROM (SELECT id, row_number() OVER (ORDER BY ts, id) AS rn FROM audit_decisions) AS o
        WHERE d.id = o.id
        """
    )

    # 4. tighten: identity, NOT NULL, constraints, indexes
    op.execute("ALTER TABLE audit_decisions ALTER COLUMN seq SET NOT NULL")
    op.execute("ALTER TABLE audit_decisions ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY")
    op.execute(
        "SELECT setval(pg_get_serial_sequence('audit_decisions', 'seq'), "
        "COALESCE((SELECT max(seq) FROM audit_decisions), 0) + 1, false)"
    )
    op.alter_column("audit_decisions", "target_kind", nullable=False)
    op.create_unique_constraint("uq_audit_decisions_seq", "audit_decisions", ["seq"])
    op.create_foreign_key(
        "fk_audit_decisions_parent_action",
        "audit_decisions",
        "audit_decisions",
        ["parent_action_id"],
        ["id"],
    )
    for name, condition in _NEW_CHECKS:
        op.create_check_constraint(name, "audit_decisions", condition)
    for name, columns in _NEW_INDEXES:
        op.create_index(name, "audit_decisions", columns)

    # 5. append-only, for every role including the owner
    for statement in APPEND_ONLY_SQL:
        op.execute(statement)

    # 6. least-privilege runtime role
    op.execute(WRITER_ROLE_SQL)
    for statement in WRITER_GRANTS_SQL:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_decisions_no_update_delete ON audit_decisions")
    op.execute("DROP FUNCTION IF EXISTS audit_decisions_append_only()")
    op.execute(
        "REVOKE ALL ON agents, manifests, compiled_policies, reconciliation_reports, sessions, "
        "audit_decisions FROM agentic_auth_writer"
    )

    for name, _ in _NEW_INDEXES:
        op.drop_index(name, table_name="audit_decisions")
    for name, _ in _NEW_CHECKS:
        op.drop_constraint(name, "audit_decisions", type_="check")
    op.drop_constraint("fk_audit_decisions_parent_action", "audit_decisions", type_="foreignkey")
    op.drop_constraint("uq_audit_decisions_seq", "audit_decisions", type_="unique")
    for column in (
        "chain_break",
        "chain_complete",
        "chain",
        "parent_action_id",
        "subject_jti",
        "target_kind",
        "acting_agent",
        "seq",
    ):
        op.drop_column("audit_decisions", column)

    for old, new in _RENAMED_CHECKS:
        op.execute(f"ALTER TABLE audit_decisions RENAME CONSTRAINT {new} TO {old}")
    for old, new in _RENAMED_INDEXES:
        op.execute(f"ALTER INDEX IF EXISTS {new} RENAME TO {old}")
    op.create_index("ix_decisions_session_ts", "audit_decisions", ["session_id", "ts"])
    op.rename_table("audit_decisions", "decisions")
