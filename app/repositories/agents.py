"""Persistence for ``agents`` (+ latest-manifest projections)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Agent, Manifest


async def get_by_name(session: AsyncSession, name: str) -> Agent | None:
    return (await session.execute(select(Agent).where(Agent.name == name))).scalar_one_or_none()


async def get_by_id(session: AsyncSession, agent_id: uuid.UUID) -> Agent | None:
    return await session.get(Agent, agent_id)


async def create(session: AsyncSession, name: str) -> Agent:
    """Idempotent create-by-name: returns the existing row if present."""
    existing = await get_by_name(session, name)
    if existing is not None:
        return existing
    agent = Agent(name=name)
    session.add(agent)
    await session.flush()
    return agent


async def list_page(
    session: AsyncSession, limit: int, cursor: str | None, *, status: str | None = None
) -> tuple[list[Agent], str | None]:
    stmt = select(Agent).order_by(Agent.name).limit(limit + 1)
    if cursor:
        stmt = stmt.where(Agent.name > cursor)
    if status is not None:
        stmt = stmt.where(Agent.status == status)
    rows = list((await session.execute(stmt)).scalars().all())
    next_cursor = rows[limit - 1].name if len(rows) > limit else None
    return rows[:limit], next_cursor


async def latest_manifest(session: AsyncSession, agent_id: uuid.UUID) -> Manifest | None:
    stmt = (
        select(Manifest)
        .where(Manifest.agent_id == agent_id)
        .order_by(Manifest.version.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def latest_versions(
    session: AsyncSession, agent_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[int, str]]:
    if not agent_ids:
        return {}
    sub = (
        select(
            Manifest.agent_id,
            func.max(Manifest.version).label("v"),
        )
        .where(Manifest.agent_id.in_(agent_ids))
        .group_by(Manifest.agent_id)
        .subquery()
    )
    stmt = select(Manifest.agent_id, Manifest.version, Manifest.status).join(
        sub, (Manifest.agent_id == sub.c.agent_id) & (Manifest.version == sub.c.v)
    )
    return {row.agent_id: (row.version, row.status) for row in (await session.execute(stmt)).all()}


async def set_status(
    session: AsyncSession,
    agent: Agent,
    *,
    status: str,
    principal_ref: str | None = None,
    trust_anchor_version: int | None = None,
    pending_identity: dict[str, Any] | None = None,
) -> Agent:
    """The one place agent identity state changes (Phase 4). Callers commit."""
    agent.status = status
    agent.principal_ref = principal_ref
    agent.trust_anchor_version = trust_anchor_version
    agent.pending_identity = pending_identity
    await session.flush()
    return agent


async def revoked_names(session: AsyncSession) -> set[str]:
    rows = (await session.execute(select(Agent.name).where(Agent.status == "revoked"))).scalars()
    return set(rows)
