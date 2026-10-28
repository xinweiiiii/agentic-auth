"""``compiled_policies`` — append-only, versioned scope→capability DAG artifacts."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import CheckConstraint, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.models import Base, TimestampCreated, UUIDPrimaryKey


class CompiledPolicy(UUIDPrimaryKey, TimestampCreated, Base):
    __tablename__ = "compiled_policies"
    __table_args__ = (
        UniqueConstraint("scope", "version", name="uq_compiled_policies_scope_version"),
        CheckConstraint("version >= 1", name="ck_compiled_policies_version_positive"),
    )

    scope: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    dag: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    source_manifest_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(Uuid(as_uuid=True)), nullable=False
    )
