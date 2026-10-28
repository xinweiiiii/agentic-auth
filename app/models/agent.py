"""``agents`` — one row per registered agent.

Phase 4 adds identity state. ``status`` moves ``registered -> enrolled | quarantined``, and
``enrolled | quarantined -> revoked`` (terminal). A trust anchor version and a principal exist
together or not at all: identity is pinned as one fact, never half of one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base, TimestampCreated, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.manifest import Manifest

AGENT_STATUSES = ("registered", "enrolled", "quarantined", "revoked")


class Agent(UUIDPrimaryKey, TimestampCreated, Base):
    __tablename__ = "agents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('registered', 'enrolled', 'quarantined', 'revoked')",
            name="ck_agents_status",
        ),
        # An anchor version exists exactly when the agent is (or was) enrolled.
        CheckConstraint(
            "(status IN ('enrolled', 'revoked')) = (trust_anchor_version IS NOT NULL)",
            name="ck_agents_anchor_iff_enrolled_or_revoked",
        ),
        # A pinned anchor always names an accountable principal.
        CheckConstraint(
            "trust_anchor_version IS NULL OR principal_ref IS NOT NULL",
            name="ck_agents_principal_iff_anchor",
        ),
    )

    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    # Phase 1 registered agents stay here until they enroll.
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="registered", server_default="registered"
    )
    # "<idp issuer>#<sub>" once an accountable principal is bound (Phase 4).
    principal_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # The current trust anchor's version; NULL unless enrolled or revoked.
    trust_anchor_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The identity document a quarantined agent presented, kept for operator inspection.
    # Public keys only; cleared on enrollment.
    pending_identity: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    manifests: Mapped[list[Manifest]] = relationship(
        back_populates="agent", order_by="Manifest.version"
    )
