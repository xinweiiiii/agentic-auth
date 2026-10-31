"""Consent, policy-version pinning, and session reads.

A session is created once and never updated. Everything a decision needs is either in the
request, in the presented token, or in this immutable row — which is what lets the PDP
stay stateless and lets a session read be a pure cache-friendly lookup.
"""

from __future__ import annotations

import contextlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth import runtime
from agentic_auth.config import get_settings
from agentic_auth.errors import (
    NotFoundError,
    QueryValidationError,
    SessionExpired,
    SessionSuperseded,
)
from agentic_auth.repositories import sessions as sessions_repo
from agentic_auth.schemas.consent import ConsentCreate, ConsentRead
from agentic_auth.services import policy_loader
from agentic_auth.services.policy_loader import PolicyIndex
from agentic_auth.services.tokens.profile import TokenProfile


def _key(session_id: str) -> str:
    return f"session:{session_id}"


@dataclass(frozen=True)
class PinnedSession:
    id: uuid.UUID
    scope: str
    user_sub: str
    policy_version: int
    hop_budget: int
    created_at: datetime
    expires_at: datetime
    # Phase 5. The subset of the pinned policy's data classes this consent covers, or
    # None for "everything the policy declares" — which is exactly Phase 2-4 semantics.
    # Nothing reads it until the PDP split lands.
    consented_data_classes: list[str] | None = None

    def as_cache(self) -> str:
        return json.dumps(
            {
                "id": str(self.id),
                "scope": self.scope,
                "user_sub": self.user_sub,
                "policy_version": self.policy_version,
                "hop_budget": self.hop_budget,
                "created_at": self.created_at.isoformat(),
                "expires_at": self.expires_at.isoformat(),
                "consented_data_classes": self.consented_data_classes,
            }
        )

    @classmethod
    def from_cache(cls, raw: str | bytes) -> PinnedSession:
        d = json.loads(raw)
        return cls(
            id=uuid.UUID(d["id"]),
            scope=d["scope"],
            user_sub=d["user_sub"],
            policy_version=d["policy_version"],
            hop_budget=d["hop_budget"],
            created_at=datetime.fromisoformat(d["created_at"]),
            expires_at=datetime.fromisoformat(d["expires_at"]),
            # `.get`, not `[...]`: an entry cached before this field existed must still
            # load, and its absence means exactly what None means.
            consented_data_classes=d.get("consented_data_classes"),
        )

    @classmethod
    def from_row(cls, row: Any) -> PinnedSession:
        return cls(
            id=row.id,
            scope=row.scope,
            user_sub=row.user_sub,
            policy_version=row.policy_version,
            hop_budget=row.hop_budget,
            created_at=row.created_at,
            expires_at=row.expires_at,
            consented_data_classes=row.consented_data_classes,
        )


class SessionService:
    def __init__(self, tokens: TokenProfile, *, ttl_seconds: int | None = None) -> None:
        self._tokens = tokens
        self._ttl = ttl_seconds or get_settings().session_ttl_seconds

    async def consent(
        self, db: AsyncSession, redis: Redis | None, body: ConsentCreate
    ) -> ConsentRead:
        """Record consent and pin the policy version in effect at this moment.

        Loading the policy here is not just a lookup — it is the gate that refuses a scope
        whose compiled policy predates runtime enforcement, rather than pinning something
        the PDP could not later decide against.
        """
        version = await policy_loader.latest_version(db, body.scope)
        if version is None:
            raise NotFoundError(f"no compiled policy for scope {body.scope!r}")

        # Raises PolicyRecompileRequired for a v1 policy. Deliberately before the insert.
        index = await policy_loader.load(db, redis, body.scope, version)

        consented = self._validate_data_classes(index, body.data_classes)

        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=body.ttl_seconds or self._ttl)
        row = await sessions_repo.create(
            db,
            scope=body.scope,
            user_sub=body.user_sub,
            policy_version=version,
            # Copied at consent, so a later publish cannot widen a running session.
            hop_budget=index.hop_budget,
            expires_at=expires_at,
            consented_data_classes=consented,
        )
        session = PinnedSession.from_row(row)
        root_grant = self._tokens.mint_root_grant(
            sub=body.user_sub,
            scope=body.scope,
            session_id=str(row.id),
            policy_version=version,
        )
        await self._cache(redis, session)
        return ConsentRead(
            session_id=str(row.id),
            root_grant=root_grant,
            policy_version=version,
            scope=body.scope,
            user_sub=body.user_sub,
            hop_budget=index.hop_budget,
            expires_at=expires_at,
            data_classes=consented,
        )

    @staticmethod
    def _validate_data_classes(index: PolicyIndex, requested: list[str] | None) -> list[str] | None:
        """Check a consented subset against the pinned policy, before the insert.

        Validating here rather than at first use means a typo surfaces to the integrator
        as a 422 on the consent call, instead of as a refusal three hops into a chain
        where it reads like a policy bug.

        Rejected outright when the feature is off, so a caller cannot believe it pinned a
        narrower consent than it did — silently ignoring the field would be the same
        class of error the guarantee level exists to prevent.
        """
        if requested is None:
            return None
        if not get_settings().consent_granularity_enabled:
            raise QueryValidationError(
                "data_classes requires consent granularity, which is disabled on this "
                "deployment (AGENTIC_AUTH_CONSENT_GRANULARITY_ENABLED)",
                [{"loc": ["body", "data_classes"], "msg": "feature disabled"}],
            )

        declared = {cls for classes in index.data_classes_by_agent.values() for cls in classes}
        unknown = sorted(set(requested) - declared)
        if unknown:
            raise QueryValidationError(
                f"data classes {unknown} are not declared by any agent in scope "
                f"{index.scope!r} at policy version {index.version}",
                [{"loc": ["body", "data_classes"], "msg": f"not declared: {unknown}"}],
            )
        # Deduplicated and ordered so the stored array, the cache and the read model
        # cannot disagree about a set that was written twice.
        return sorted(set(requested))

    async def get(self, db: AsyncSession, redis: Redis | None, session_id: str) -> PinnedSession:
        """Read-through by id. Raises ``SessionExpired`` past ``expires_at``.

        Expiry is checked against this record, not against the token's ``exp``, so a
        still-valid token inside a dead session is refused.
        """
        try:
            sid = uuid.UUID(session_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise NotFoundError(f"unknown session {session_id!r}") from exc

        session: PinnedSession | None = None
        if redis is not None:
            with contextlib.suppress(Exception):
                cached = await redis.get(_key(session_id))
                if cached is not None:
                    session = PinnedSession.from_cache(cached)

        if session is None:
            row = await sessions_repo.get(db, sid)
            if row is None:
                raise NotFoundError(f"unknown session {session_id!r}")
            session = PinnedSession.from_row(row)
            await self._cache(redis, session)

        if session.expires_at <= datetime.now(UTC):
            raise SessionExpired(
                f"session {session_id} expired at {session.expires_at.isoformat()}"
            )
        current = runtime.override()
        if (
            current is not None
            and current.superseded_before is not None
            and session.created_at < current.superseded_before
        ):
            raise SessionSuperseded(
                f"session {session_id} predates this embedded store's last open; consent again"
            )
        return session

    async def _cache(self, redis: Redis | None, session: PinnedSession) -> None:
        if redis is None:
            return
        ttl = int((session.expires_at - datetime.now(UTC)).total_seconds())
        if ttl <= 0:
            return
        with contextlib.suppress(Exception):
            await redis.set(_key(str(session.id)), session.as_cache(), ex=ttl)
