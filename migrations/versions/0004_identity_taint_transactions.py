"""identity, taint and transaction tokens (Phase 4)

Revision ID: 0004_identity_taint_transactions
Revises: 0003_audit_decisions
Create Date: 2026-09-20

Additive throughout:

1. ``agents`` gains identity state (``status``, ``trust_anchor_version``, ``pending_identity``).
2. ``trust_anchors``: one live row per agent, versioned, never deleted.
3. ``transaction_tokens``: append-only, one row per recorded allow decision.
4. ``audit_decisions`` gains ``taint_source`` and ``privileged``.
5. Least-privilege grants for the runtime role.

``downgrade()`` drops the anchors and transaction fingerprints — every enrollment and every
call-bound authority ever minted. The ``agentic_auth_writer`` role is left in place.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004_identity_taint_transactions"
down_revision = "0003_audit_decisions"
branch_labels = None
depends_on = None

# Frozen copies of the constants in app/models/transaction_token.py.
# tests/unit/test_audit_ddl.py asserts they are identical.
TXN_APPEND_ONLY_SQL = (
    """CREATE OR REPLACE FUNCTION transaction_tokens_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'transaction_tokens is append-only' USING ERRCODE = '55000';
END;
$$""",
    """CREATE TRIGGER transaction_tokens_no_update_delete
BEFORE UPDATE OR DELETE ON transaction_tokens
FOR EACH ROW EXECUTE FUNCTION transaction_tokens_append_only()""",
)

WRITER_GRANTS_SQL_0004 = (
    "GRANT SELECT, INSERT, UPDATE ON trust_anchors TO agentic_auth_writer",
    "GRANT SELECT, INSERT ON transaction_tokens TO agentic_auth_writer",
)

_AGENT_CHECKS = (
    ("ck_agents_status", "status IN ('registered', 'enrolled', 'quarantined', 'revoked')"),
    (
        "ck_agents_anchor_iff_enrolled_or_revoked",
        "(status IN ('enrolled', 'revoked')) = (trust_anchor_version IS NOT NULL)",
    ),
    ("ck_agents_principal_iff_anchor", "trust_anchor_version IS NULL OR principal_ref IS NOT NULL"),
)


def upgrade() -> None:
    # 1. agents: identity state. Every existing agent is `registered`.
    op.add_column(
        "agents",
        sa.Column("status", sa.String(16), nullable=False, server_default="registered"),
    )
    op.add_column("agents", sa.Column("trust_anchor_version", sa.Integer(), nullable=True))
    op.add_column("agents", sa.Column("pending_identity", postgresql.JSONB(), nullable=True))
    for name, condition in _AGENT_CHECKS:
        op.create_check_constraint(name, "agents", condition)

    # 2. trust_anchors
    op.create_table(
        "trust_anchors",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("jwks", postgresql.JSONB(), nullable=False),
        sa.Column("key_thumbprints", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("principal_ref", sa.String(255), nullable=False),
        sa.Column("manifest_version", sa.Integer(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(1024), nullable=True),
        sa.UniqueConstraint("agent_id", "version", name="uq_trust_anchors_agent_version"),
        sa.CheckConstraint("version >= 1", name="ck_trust_anchors_version_positive"),
    )
    op.create_index("ix_trust_anchors_agent_id", "trust_anchors", ["agent_id"])
    op.create_index("ix_trust_anchors_revoked_at", "trust_anchors", ["revoked_at"])
    op.create_index(
        "uq_trust_anchors_one_current",
        "trust_anchors",
        ["agent_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    # 3. transaction_tokens, append-only
    op.create_table(
        "transaction_tokens",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column(
            "action_id",
            sa.Uuid(),
            sa.ForeignKey("audit_decisions.id", name="fk_transaction_tokens_action"),
            nullable=False,
            unique=True,
        ),
        sa.Column("session_id", sa.Uuid(), sa.ForeignKey("sessions.id"), nullable=False),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("params_hash", sa.String(64), nullable=False),
        sa.Column("binding", postgresql.JSONB(), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("expires_at > issued_at", name="ck_transaction_tokens_expiry_after_issue"),
    )
    op.create_index("ix_transaction_tokens_session_id", "transaction_tokens", ["session_id"])
    for statement in TXN_APPEND_ONLY_SQL:
        op.execute(statement)

    # 4. audit_decisions: additive
    op.add_column("audit_decisions", sa.Column("taint_source", sa.String(512), nullable=True))
    op.add_column(
        "audit_decisions",
        sa.Column("privileged", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    # 5. least-privilege runtime role
    for statement in WRITER_GRANTS_SQL_0004:
        op.execute(statement)


def downgrade() -> None:
    op.execute("REVOKE ALL ON trust_anchors, transaction_tokens FROM agentic_auth_writer")

    op.drop_column("audit_decisions", "privileged")
    op.drop_column("audit_decisions", "taint_source")

    op.execute("DROP TRIGGER IF EXISTS transaction_tokens_no_update_delete ON transaction_tokens")
    op.execute("DROP FUNCTION IF EXISTS transaction_tokens_append_only()")
    op.drop_index("ix_transaction_tokens_session_id", table_name="transaction_tokens")
    op.drop_table("transaction_tokens")

    op.drop_index("uq_trust_anchors_one_current", table_name="trust_anchors")
    op.drop_index("ix_trust_anchors_revoked_at", table_name="trust_anchors")
    op.drop_index("ix_trust_anchors_agent_id", table_name="trust_anchors")
    op.drop_table("trust_anchors")

    for name, _ in _AGENT_CHECKS:
        op.drop_constraint(name, "agents", type_="check")
    op.drop_column("agents", "pending_identity")
    op.drop_column("agents", "trust_anchor_version")
    op.drop_column("agents", "status")
