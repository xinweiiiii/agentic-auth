"""The current trust anchor per agent, cached in Redis and invalidated on every change.

``anchor:{agent_name}`` holds the serialized :class:`AgentIdentityRead`; no TTL, because an
anchor only changes through enrollment and revocation, and both delete the key after
commit. A cache miss reads the database. Redis being down is a slower read, never a wrong
one.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.models import Agent, TrustAnchor
from agentic_auth.repositories import agents as agents_repo
from agentic_auth.repositories import trust_anchors as anchors_repo
from agentic_auth.schemas.identity import AgentIdentityRead


def anchor_key(agent_name: str) -> str:
    return f"anchor:{agent_name}"


def thumbprint(jwk: dict[str, Any]) -> str:
    """SHA-256 of the raw public key bytes, base64url — the identity of the KEY itself."""
    raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()


def identity_read(
    agent: Agent, anchor: TrustAnchor | None, *, as_of: datetime
) -> AgentIdentityRead:
    show = anchor is not None and agent.status in ("enrolled", "revoked")
    return AgentIdentityRead(
        agent=agent.name,
        status=agent.status,
        trust_anchor_version=agent.trust_anchor_version,
        jwks=anchor.jwks if show and anchor is not None else None,
        principal_ref=agent.principal_ref if show else None,
        manifest_version=anchor.manifest_version if show and anchor is not None else None,
        revoked=agent.status == "revoked",
        revoked_at=anchor.revoked_at if anchor is not None else None,
        as_of=as_of,
    )


class AnchorCache:
    def __init__(self, redis: Redis | None) -> None:
        self._redis = redis

    async def current(self, db: AsyncSession, agent_name: str) -> AgentIdentityRead | None:
        """The agent's identity material, or ``None`` for an unknown agent."""
        if self._redis is not None:
            with contextlib.suppress(Exception):
                cached = await self._redis.get(anchor_key(agent_name))
                if cached is not None:
                    return AgentIdentityRead.model_validate_json(cached)
        agent = await agents_repo.get_by_name(db, agent_name)
        if agent is None:
            return None
        anchor = await anchors_repo.current(db, agent.id)
        read = identity_read(agent, anchor, as_of=datetime.now(UTC))
        if self._redis is not None:
            with contextlib.suppress(Exception):
                await self._redis.set(anchor_key(agent_name), read.model_dump_json())
        return read

    async def invalidate(self, agent_name: str) -> None:
        if self._redis is None:
            return
        with contextlib.suppress(Exception):
            await self._redis.delete(anchor_key(agent_name))


__all__ = ["AnchorCache", "anchor_key", "identity_read", "thumbprint"]
