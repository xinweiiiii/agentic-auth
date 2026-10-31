"""audit_decisions.deployment

Revision ID: 0006_audit_deployment
Revises: 0005_stepup_coldstart_guarantee

Which deployment wrote each decision: ``server`` (the control plane) or ``embedded`` (an
in-process control plane, development and testing only — agentic_auth.embedded).

Additive and default-only. Nothing is backfilled: the append-only trigger refuses UPDATE on
this table, and the column default already reads every existing row as ``server``, which is
what wrote all of them.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_audit_deployment"
down_revision = "0005_stepup_coldstart_guarantee"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_decisions",
        sa.Column("deployment", sa.String(16), nullable=False, server_default="server"),
    )


def downgrade() -> None:
    op.drop_column("audit_decisions", "deployment")
