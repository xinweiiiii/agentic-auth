"""Persistence for ``sessions``.

Create and read only — a session is immutable after insert, so there is deliberately no
update path here for a future edit to reach for.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession as DbSession

from agentic_auth.models import Session


async def create(
    db: DbSession,
    *,
    scope: str,
    user_sub: str,
    policy_version: int,
    hop_budget: int,
    expires_at: datetime,
    consented_data_classes: list[str] | None = None,
) -> Session:
    row = Session(
        scope=scope,
        user_sub=user_sub,
        policy_version=policy_version,
        hop_budget=hop_budget,
        expires_at=expires_at,
        consented_data_classes=consented_data_classes,
    )
    db.add(row)
    await db.flush()
    return row


async def get(db: DbSession, session_id: uuid.UUID) -> Session | None:
    return await db.get(Session, session_id)
