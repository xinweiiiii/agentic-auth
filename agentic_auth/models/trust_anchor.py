"""``trust_anchors`` — one row per pinned (key set, manifest version, principal).

At most one row per agent is *live* (``revoked_at IS NULL``), enforced by a partial unique
index. Re-enrollment revokes the previous row and inserts ``version + 1`` in one
transaction; revocation sets ``revoked_at`` and never clears it. ``key_thumbprints`` is
what "a revoked key is never re-pinned" checks against — a ``kid`` is chosen by the agent
and proves nothing.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from agentic_auth.models import Base, TimestampCreated, UUIDPrimaryKey
from agentic_auth.models.types import PortableArray, PortableJSON, TZDateTime


class TrustAnchor(UUIDPrimaryKey, TimestampCreated, Base):
    __tablename__ = "trust_anchors"
    __table_args__ = (
        UniqueConstraint("agent_id", "version", name="uq_trust_anchors_agent_version"),
        CheckConstraint("version >= 1", name="ck_trust_anchors_version_positive"),
        Index("ix_trust_anchors_revoked_at", "revoked_at"),
        Index(
            "uq_trust_anchors_one_current",
            "agent_id",
            unique=True,
            postgresql_where="revoked_at IS NULL",
            sqlite_where=text("revoked_at IS NULL"),
        ),
    )

    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("agents.id"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    # {"keys": [...]}: OKP/Ed25519 public keys only, each with a kid.
    jwks: Mapped[dict[str, Any]] = mapped_column(PortableJSON, nullable=False)
    key_thumbprints: Mapped[list[str]] = mapped_column(PortableArray(Text), nullable=False)
    principal_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    manifest_version: Mapped[int] = mapped_column(Integer, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    # Operator note from POST /v1/agents/{id}/revoke.
    revoke_reason: Mapped[str | None] = mapped_column(String(1024), nullable=True)
