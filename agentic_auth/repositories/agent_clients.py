"""Persistence for ``agent_clients``. Rows are created and soft-removed, never deleted."""

from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.models import AgentClient


async def create(
    db: AsyncSession, *, agent_id: uuid.UUID, issuer: str, client_id: str, created_by: str
) -> AgentClient:
    row = AgentClient(agent_id=agent_id, issuer=issuer, client_id=client_id, created_by=created_by)
    db.add(row)
    await db.flush()
    return row


async def get_active(db: AsyncSession, issuer: str, client_id: str) -> AgentClient | None:
    stmt = select(AgentClient).where(
        AgentClient.issuer == issuer,
        AgentClient.client_id == client_id,
        AgentClient.removed_at.is_(None),
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def for_agent(db: AsyncSession, agent_id: uuid.UUID, client_id: str) -> list[AgentClient]:
    """Every mapping of ``client_id`` to this agent, active or removed, newest first."""
    stmt = (
        select(AgentClient)
        .where(AgentClient.agent_id == agent_id, AgentClient.client_id == client_id)
        .order_by(AgentClient.created_at.desc(), AgentClient.id.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def remove(db: AsyncSession, row: AgentClient, *, removed_by: str) -> AgentClient:
    row.removed_at = datetime.now(UTC)
    row.removed_by = removed_by
    await db.flush()
    return row


def _cursor(row: AgentClient) -> str:
    # Base64url, so the timestamp's "+" survives a query string.
    raw = f"{row.created_at.isoformat()}|{row.id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode(cursor: str) -> tuple[datetime, uuid.UUID]:
    from agentic_auth.errors import QueryValidationError

    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        created_raw, _, id_raw = raw.partition("|")
        return datetime.fromisoformat(created_raw), uuid.UUID(id_raw)
    except ValueError as exc:
        raise QueryValidationError(
            "cursor is not one this endpoint issued",
            [{"loc": ["query", "cursor"], "msg": "invalid cursor"}],
        ) from exc


async def list_page(
    db: AsyncSession,
    agent_id: uuid.UUID,
    limit: int,
    cursor: str | None,
    *,
    include_removed: bool,
) -> tuple[list[AgentClient], str | None]:
    """Newest first, keyset-paginated on ``(created_at, id)``."""
    stmt = select(AgentClient).where(AgentClient.agent_id == agent_id)
    if not include_removed:
        stmt = stmt.where(AgentClient.removed_at.is_(None))
    if cursor:
        created, row_id = _decode(cursor)
        stmt = stmt.where(
            or_(
                AgentClient.created_at < created,
                and_(AgentClient.created_at == created, AgentClient.id < row_id),
            )
        )
    stmt = stmt.order_by(AgentClient.created_at.desc(), AgentClient.id.desc()).limit(limit + 1)
    rows = list((await db.execute(stmt)).scalars())
    next_cursor = _cursor(rows[limit - 1]) if len(rows) > limit else None
    return rows[:limit], next_cursor
