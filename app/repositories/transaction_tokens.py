"""Append-only persistence for ``transaction_tokens``.

Append and read only. ``UNIQUE (action_id)`` turns a second mint for one decision into an
``IntegrityError`` at ``flush()``; the service maps that to ``409``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import TransactionToken


async def append(
    db: AsyncSession,
    *,
    jti: str,
    action_id: uuid.UUID,
    session_id: uuid.UUID,
    target: str,
    params_hash: str,
    binding: list[str] | None,
    issued_at: datetime,
    expires_at: datetime,
) -> TransactionToken:
    row = TransactionToken(
        jti=jti,
        action_id=action_id,
        session_id=session_id,
        target=target,
        params_hash=params_hash,
        binding=binding,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    db.add(row)
    await db.flush()
    return row


async def get_by_action(db: AsyncSession, action_id: uuid.UUID) -> TransactionToken | None:
    return (
        await db.execute(select(TransactionToken).where(TransactionToken.action_id == action_id))
    ).scalar_one_or_none()


async def get_by_actions(
    db: AsyncSession, action_ids: list[uuid.UUID]
) -> dict[uuid.UUID, TransactionToken]:
    """The fingerprints for a page of decisions, in one query."""
    if not action_ids:
        return {}
    rows = (
        await db.execute(select(TransactionToken).where(TransactionToken.action_id.in_(action_ids)))
    ).scalars()
    return {row.action_id: row for row in rows}
