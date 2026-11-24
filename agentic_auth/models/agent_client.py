"""``agent_clients`` — which registered agent an IdP client acts as (feature 011, M4).

An MCP client registered at the customer's IdP is *identified* by the ``azp`` of its tokens,
not authorized. This table is how an admin says "that client is this agent", and therefore
"its sessions run under this agent's scope". A client with no row here has no authority.

Never deleted. Removal sets ``removed_at`` and ``removed_by``, so the table is its own change
history (spec FR-012), and re-mapping a removed client creates a new row rather than
reactivating the old one. A partial unique index keeps one *active* mapping per
``(issuer, client_id)``; it is the final guard behind the service's conflict check.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from agentic_auth.models import Base, TimestampCreated, UUIDPrimaryKey
from agentic_auth.models.types import TZDateTime


class AgentClient(UUIDPrimaryKey, TimestampCreated, Base):
    __tablename__ = "agent_clients"
    __table_args__ = (
        CheckConstraint("client_id <> ''", name="ck_agent_clients_client_id_nonempty"),
        CheckConstraint("issuer <> ''", name="ck_agent_clients_issuer_nonempty"),
        CheckConstraint(
            "(removed_at IS NULL) = (removed_by IS NULL)",
            name="ck_agent_clients_removed_by_iff_removed",
        ),
        Index(
            "uq_agent_clients_active",
            "issuer",
            "client_id",
            unique=True,
            postgresql_where=text("removed_at IS NULL"),
            sqlite_where=text("removed_at IS NULL"),
        ),
        Index("ix_agent_clients_agent_created", "agent_id", "created_at"),
    )

    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("agents.id", name="fk_agent_clients_agent"), nullable=False
    )
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    # The credential role that made the change. Only admins can, so today always "admin".
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)
    removed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    removed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    @property
    def active(self) -> bool:
        return self.removed_at is None
