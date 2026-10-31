"""Persistence for ``trust_anchors``.

The only update this module performs is setting ``revoked_at`` — once. There is no delete.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.models import TrustAnchor


async def current(session: AsyncSession, agent_id: uuid.UUID) -> TrustAnchor | None:
    """The live anchor, or — when the agent is revoked — the most recently revoked one, so
    identity material stays readable after revocation. ``None`` when never enrolled."""
    live = (
        await session.execute(
            select(TrustAnchor).where(
                TrustAnchor.agent_id == agent_id, TrustAnchor.revoked_at.is_(None)
            )
        )
    ).scalar_one_or_none()
    if live is not None:
        return live
    return (
        await session.execute(
            select(TrustAnchor)
            .where(TrustAnchor.agent_id == agent_id)
            .order_by(TrustAnchor.version.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def next_version(session: AsyncSession, agent_id: uuid.UUID) -> int:
    highest = (
        await session.execute(
            select(func.max(TrustAnchor.version)).where(TrustAnchor.agent_id == agent_id)
        )
    ).scalar_one()
    return (highest or 0) + 1


async def append(
    session: AsyncSession,
    *,
    agent_id: uuid.UUID,
    version: int,
    jwks: dict[str, Any],
    key_thumbprints: list[str],
    principal_ref: str,
    manifest_version: int,
) -> TrustAnchor:
    row = TrustAnchor(
        agent_id=agent_id,
        version=version,
        jwks=jwks,
        key_thumbprints=key_thumbprints,
        principal_ref=principal_ref,
        manifest_version=manifest_version,
    )
    session.add(row)
    await session.flush()
    return row


async def revoke_current(
    session: AsyncSession, agent_id: uuid.UUID, *, at: datetime, reason: str | None
) -> TrustAnchor | None:
    """Set ``revoked_at`` on the live anchor. Returns the row, or ``None`` if none was live."""
    live = (
        await session.execute(
            select(TrustAnchor).where(
                TrustAnchor.agent_id == agent_id, TrustAnchor.revoked_at.is_(None)
            )
        )
    ).scalar_one_or_none()
    if live is None:
        return None
    await session.execute(
        update(TrustAnchor)
        .where(TrustAnchor.id == live.id)
        .values(revoked_at=at, revoke_reason=reason)
    )
    live.revoked_at = at
    live.revoke_reason = reason
    return live


async def revoked_thumbprints(session: AsyncSession, agent_id: uuid.UUID) -> set[str]:
    rows = (
        await session.execute(
            select(TrustAnchor.key_thumbprints).where(
                TrustAnchor.agent_id == agent_id, TrustAnchor.revoked_at.is_not(None)
            )
        )
    ).scalars()
    out: set[str] = set()
    for thumbprints in rows:
        out.update(thumbprints)
    return out


def encode_cursor(revoked_at: datetime, agent_id: uuid.UUID) -> str:
    raw = f"{revoked_at.isoformat()}|{agent_id}".encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    padded = cursor + "=" * (-len(cursor) % 4)
    raw = base64.urlsafe_b64decode(padded).decode()
    ts, agent = raw.split("|", 1)
    return datetime.fromisoformat(ts), uuid.UUID(agent)


async def list_revocations(
    session: AsyncSession,
    *,
    since: datetime | None,
    limit: int,
    cursor: str | None,
) -> tuple[list[TrustAnchor], str | None]:
    """Revoked anchors, oldest first, keyset on ``(revoked_at, agent_id)``."""
    stmt = (
        select(TrustAnchor)
        .where(TrustAnchor.revoked_at.is_not(None))
        .order_by(TrustAnchor.revoked_at, TrustAnchor.agent_id)
        .limit(limit + 1)
    )
    if since is not None:
        stmt = stmt.where(TrustAnchor.revoked_at >= since)
    if cursor:
        after_ts, after_agent = decode_cursor(cursor)
        stmt = stmt.where(
            (TrustAnchor.revoked_at > after_ts)
            | ((TrustAnchor.revoked_at == after_ts) & (TrustAnchor.agent_id > after_agent))
        )
    rows = list((await session.execute(stmt)).scalars().all())
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        assert last.revoked_at is not None
        next_cursor = encode_cursor(last.revoked_at, last.agent_id)
    return rows[:limit], next_cursor
