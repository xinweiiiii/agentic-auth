"""Persistence for step-up grants. Append-only: there is no update and no delete."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession as DbSession

from agentic_auth.models import StepUpGrant


async def append(
    db: DbSession,
    *,
    session_id: uuid.UUID,
    blocked_action_id: uuid.UUID,
    data_class: str,
    target: str,
    challenge_hash: str,
    approved_by: str | None,
    approved_at: datetime | None,
    declined_at: datetime | None,
) -> StepUpGrant:
    row = StepUpGrant(
        session_id=session_id,
        blocked_action_id=blocked_action_id,
        data_class=data_class,
        target=target,
        challenge_hash=challenge_hash,
        approved_by=approved_by,
        approved_at=approved_at,
        declined_at=declined_at,
    )
    db.add(row)
    await db.flush()
    return row


async def by_challenge(db: DbSession, challenge_hash: str) -> StepUpGrant | None:
    """The durable twin of the Redis ``GETDEL``.

    Even if the cache were lost and a challenge replayed, ``UNIQUE (challenge_hash)``
    refuses the second insert — so this lookup is how the caller turns that into a clean
    ``409`` instead of an integrity error.
    """
    return (
        await db.execute(select(StepUpGrant).where(StepUpGrant.challenge_hash == challenge_hash))
    ).scalar_one_or_none()


async def approved_classes(db: DbSession, session_id: uuid.UUID) -> set[str]:
    """Every data class a human has approved for this session.

    This is what rebuilds ``stepup:{session_id}`` after a Redis flush. Declines are
    excluded by the ``approved_at IS NOT NULL`` filter, so a refused challenge can never
    come back as a grant.
    """
    rows = await db.execute(
        select(StepUpGrant.data_class).where(
            StepUpGrant.session_id == session_id,
            StepUpGrant.approved_at.is_not(None),
        )
    )
    return set(rows.scalars().all())


async def for_session(db: DbSession, session_id: uuid.UUID) -> list[StepUpGrant]:
    rows = await db.execute(
        select(StepUpGrant)
        .where(StepUpGrant.session_id == session_id)
        .order_by(StepUpGrant.created_at)
    )
    return list(rows.scalars().all())


__all__ = ["append", "approved_classes", "by_challenge", "for_session"]
