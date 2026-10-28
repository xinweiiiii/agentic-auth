"""Revocation: cut an agent off, and everything built on it (contracts/identity.md §7).

One transaction flips the live anchor's ``revoked_at`` and the agent's status; then the
anchor cache entry is deleted and the name is added to the ``revoked_agents`` set that
``decide()`` consults on every hop. The set is a cache of ``agents.status = 'revoked'``,
rebuilt at startup, so a flushed Redis can only make the control plane slower, never more
permissive: a miss falls back to the database.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.errors import NotEnrolled, NotFoundError
from app.repositories import agents as agents_repo
from app.repositories import trust_anchors as anchors_repo
from app.schemas.identity import RevocationItem, RevocationListRead, RevocationPage, RevokeOutcome
from app.services.anchors import AnchorCache
from app.services.metrics import get_metrics

logger = logging.getLogger(__name__)

REVOKED_SET = "revoked_agents"
REVOKED_READY = "revoked_agents:ready"


class RevocationService:
    def __init__(self, anchors: AnchorCache) -> None:
        self._anchors = anchors

    async def revoke(
        self, db: AsyncSession, redis: Redis | None, agent_id: uuid.UUID, reason: str | None
    ) -> RevokeOutcome:
        agent = await agents_repo.get_by_id(db, agent_id)
        if agent is None:
            raise NotFoundError(f"agent {agent_id} not found")
        current = await anchors_repo.current(db, agent.id)
        if current is None:
            raise NotEnrolled(f"agent {agent.name} has no trust anchor")

        if agent.status == "revoked" and current.revoked_at is not None:
            # Idempotent: the same body, no second write, no second count.
            return RevokeOutcome(
                status="revoked",
                trust_anchor_version=current.version,
                revoked_at=current.revoked_at,
            )

        now = datetime.now(UTC)
        live = await anchors_repo.revoke_current(db, agent.id, at=now, reason=reason)
        version = live.version if live is not None else current.version
        await agents_repo.set_status(
            db,
            agent,
            status="revoked",
            principal_ref=agent.principal_ref,
            trust_anchor_version=version,
            pending_identity=None,
        )
        await db.commit()

        await self._anchors.invalidate(agent.name)
        await self._add_revoked(redis, agent.name)
        get_metrics().revocations.inc()
        return RevokeOutcome(status="revoked", trust_anchor_version=version, revoked_at=now)

    # -- the revoked set -----------------------------------------------------------------

    async def revoked_set(self, db: AsyncSession, redis: Redis | None) -> frozenset[str]:
        """Every revoked agent name. Redis first; the database when Redis has no view."""
        if redis is not None:
            try:
                # One round trip for both: this runs on every authorize and every exchange.
                pipe = redis.pipeline(transaction=False)
                pipe.get(REVOKED_READY)
                pipe.smembers(REVOKED_SET)
                ready, members = await pipe.execute()
                if ready:
                    return frozenset(m.decode() if isinstance(m, bytes) else m for m in members)
            except Exception:
                logger.warning("revoked set unavailable in redis; reading the database")
        names = await agents_repo.revoked_names(db)
        await self._rebuild_into(redis, names)
        return frozenset(names)

    async def rebuild(self, db: AsyncSession, redis: Redis | None) -> None:
        await self._rebuild_into(redis, await agents_repo.revoked_names(db))

    async def _rebuild_into(self, redis: Redis | None, names: set[str]) -> None:
        if redis is None:
            return
        with contextlib.suppress(Exception):
            pipe = redis.pipeline(transaction=True)
            pipe.delete(REVOKED_SET)
            if names:
                pipe.sadd(REVOKED_SET, *names)
            pipe.set(REVOKED_READY, "1")
            await pipe.execute()

    async def _add_revoked(self, redis: Redis | None, name: str) -> None:
        if redis is None:
            return
        with contextlib.suppress(Exception):
            await redis.sadd(REVOKED_SET, name)

    # -- the list -----------------------------------------------------------------------------

    async def list(
        self,
        db: AsyncSession,
        *,
        since: datetime | None,
        limit: int,
        cursor: str | None,
    ) -> RevocationListRead:
        rows, next_cursor = await anchors_repo.list_revocations(
            db, since=since, limit=limit, cursor=cursor
        )
        names: dict[uuid.UUID, str] = {}
        for row in rows:
            if row.agent_id not in names:
                agent = await agents_repo.get_by_id(db, row.agent_id)
                names[row.agent_id] = agent.name if agent is not None else str(row.agent_id)
        return RevocationListRead(
            as_of=datetime.now(UTC),
            items=[
                RevocationItem(
                    agent=names[row.agent_id],
                    trust_anchor_version=row.version,
                    revoked_at=row.revoked_at,
                )
                for row in rows
            ],
            page=RevocationPage(next_cursor=next_cursor, limit=limit),
        )


__all__ = ["REVOKED_SET", "RevocationService"]
