"""SQLAlchemy ORM base and shared column mixins."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Uuid, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class UUIDPrimaryKey:
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


class TimestampCreated:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


from app.models.agent import Agent  # noqa: E402,F401
from app.models.audit_decision import AuditDecision  # noqa: E402,F401
from app.models.compiled_policy import CompiledPolicy  # noqa: E402,F401
from app.models.manifest import Manifest  # noqa: E402,F401
from app.models.reconciliation_report import ReconciliationReport  # noqa: E402,F401
from app.models.sandbox_run import SandboxRun  # noqa: E402,F401
from app.models.session import Session  # noqa: E402,F401
from app.models.step_up_grant import StepUpGrant  # noqa: E402,F401
from app.models.transaction_token import TransactionToken  # noqa: E402,F401
from app.models.trust_anchor import TrustAnchor  # noqa: E402,F401

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
