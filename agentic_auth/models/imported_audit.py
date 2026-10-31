"""Audit history carried over from another deployment — kept apart from this one's own log.

An embedded control plane (``agentic_auth.embedded``) can export its decisions
(``EmbeddedControlPlane.export``). ``agentic-auth audit import`` lands them here, never in
``audit_decisions``: those decisions were made by a different deployment, under a different
signing key, and a development-only one at that. Mixing them into this control plane's own log
would let a chain query here present someone else's record as this deployment's.

Each row is the exported decision verbatim (``row``), with where it came from. Append-only, the
same way the decision log is. The runtime role is granted nothing on it: imports are an
owner-run maintenance step, like ``agentic-auth audit export``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import String, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from agentic_auth.models import Base, UUIDPrimaryKey
from agentic_auth.models.types import PortableJSON, TZDateTime, install_append_only

# The SQL below is duplicated, frozen, in migrations/versions/0007_imported_audit.py.
# tests/unit/test_audit_ddl.py fails if the two drift apart.
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


class ImportedAudit(UUIDPrimaryKey, Base):
    __tablename__ = "imported_audit"

    # The decision's own action id in the deployment that made it. Unique, so importing the
    # same bundle twice adds nothing the second time.
    action_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, unique=True)
    source_deployment: Mapped[str] = mapped_column(String(16), nullable=False)
    source_package_version: Mapped[str] = mapped_column(String(32), nullable=False)
    exported_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False)
    imported_at: Mapped[datetime] = mapped_column(
        TZDateTime, server_default=func.now(), nullable=False
    )
    row: Mapped[dict[str, Any]] = mapped_column(PortableJSON, nullable=False)


install_append_only(ImportedAudit.__table__, IMPORTED_AUDIT_APPEND_ONLY_SQL)
