"""``transaction_tokens`` — one append-only row per call-bound authority.

Two facts this table makes true in the database, not in code:

- **One transaction token per recorded allow decision.** ``UNIQUE (action_id)``. A second
  mint for the same decision is an ``IntegrityError``, never a second token.
- **Nothing rewrites history.** The same trigger shape as ``audit_decisions``; the runtime
  role holds ``SELECT, INSERT`` only.

The token itself is never stored. ``params_hash`` is the fingerprint the audit read
models join on.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from agentic_auth.models import Base
from agentic_auth.models.types import PortableJSON, TZDateTime, install_append_only

# Duplicated, frozen, in migrations/versions/0004_identity_taint_transactions.py.
# tests/unit/test_audit_ddl.py fails if the two drift apart.
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
    # Revocation and enrollment update these two; nothing else is ever updated.
    "GRANT SELECT, INSERT, UPDATE ON trust_anchors TO agentic_auth_writer",
    "GRANT SELECT, INSERT ON transaction_tokens TO agentic_auth_writer",
)


class TransactionToken(Base):
    __tablename__ = "transaction_tokens"
    __table_args__ = (
        CheckConstraint("expires_at > issued_at", name="ck_transaction_tokens_expiry_after_issue"),
    )

    # The token's jti (= txn). The single-use handle at the resource.
    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    action_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("audit_decisions.id", name="fk_transaction_tokens_action"),
        nullable=False,
        unique=True,
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("sessions.id"), nullable=False, index=True
    )
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    # base64url SHA-256 of the canonical binding document (docs/canonicalization.md).
    params_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # The RFC 6901 pointers applied, or NULL for the whole body.
    binding: Mapped[list[str] | None] = mapped_column(PortableJSON, nullable=True)
    issued_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False)


install_append_only(TransactionToken.__table__, TXN_APPEND_ONLY_SQL)
