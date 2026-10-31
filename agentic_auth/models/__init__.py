"""SQLAlchemy ORM base and shared column mixins."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Uuid, event, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from agentic_auth.models.types import TZDateTime


class Base(DeclarativeBase):
    pass


class UUIDPrimaryKey:
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


class TimestampCreated:
    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, server_default=func.now(), nullable=False
    )


@event.listens_for(Base, "before_insert", propagate=True)
def _sqlite_timestamps(_mapper: Any, connection: Any, target: Any) -> None:
    """SQLite's CURRENT_TIMESTAMP has whole-second precision; PostgreSQL's now() has
    microseconds. The embedded store compares creation times against the moment it was
    opened (agentic_auth/runtime.py: superseded_before), and a second of slack there would
    let a session from before a restart through. So on SQLite only, every server-defaulted
    timestamp is filled in here, at full precision, in UTC."""
    if connection.dialect.name != "sqlite":
        return
    now = datetime.now(UTC)
    for column in _mapper.columns:
        default = getattr(column.server_default, "arg", None)
        if getattr(default, "name", None) == "now" and getattr(target, column.key, None) is None:
            setattr(target, column.key, now)


from agentic_auth.models.agent import Agent  # noqa: E402,F401
from agentic_auth.models.audit_decision import AuditDecision  # noqa: E402,F401
from agentic_auth.models.compiled_policy import CompiledPolicy  # noqa: E402,F401
from agentic_auth.models.manifest import Manifest  # noqa: E402,F401
from agentic_auth.models.reconciliation_report import ReconciliationReport  # noqa: E402,F401
from agentic_auth.models.sandbox_run import SandboxRun  # noqa: E402,F401
from agentic_auth.models.session import Session  # noqa: E402,F401
from agentic_auth.models.step_up_grant import StepUpGrant  # noqa: E402,F401
from agentic_auth.models.transaction_token import TransactionToken  # noqa: E402,F401
from agentic_auth.models.trust_anchor import TrustAnchor  # noqa: E402,F401

__all__ = [
    "Base",
    "UUIDPrimaryKey",
    "TimestampCreated",
    "Agent",
    "Manifest",
    "CompiledPolicy",
    "ReconciliationReport",
    "Session",
    "AuditDecision",
    "TrustAnchor",
    "TransactionToken",
    "StepUpGrant",
    "SandboxRun",
]
