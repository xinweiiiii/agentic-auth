"""``reconciliation_reports`` — one actionable-diff report per manifest submission."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base, TimestampCreated, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.manifest import Manifest


class ReconciliationReport(UUIDPrimaryKey, TimestampCreated, Base):
    __tablename__ = "reconciliation_reports"

    manifest_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("manifests.id"), nullable=False, unique=True, index=True
    )
    diff: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    discovery_ok: Mapped[bool] = mapped_column(Boolean, nullable=False)

    manifest: Mapped[Manifest] = relationship(back_populates="reconciliation_report")
