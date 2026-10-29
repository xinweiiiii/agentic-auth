"""Identity material and revocation — what offline verifiers bootstrap from, and how an
operator cuts an agent off."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import AdminDep, IdentityReaderDep, SessionDep
from app.api.service_deps import AnchorCacheDep, RedisDep, RevocationServiceDep
from app.errors import NotFoundError, QueryValidationError
from app.repositories import agents as agents_repo
from app.repositories import trust_anchors as anchors_repo
from app.schemas.common import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from app.schemas.identity import (
    AgentIdentityRead,
    RevocationListRead,
    RevokeOutcome,
    RevokeRequest,
)
from app.services.anchors import identity_read

router = APIRouter(prefix="/v1", tags=["identity"])


@router.get(
    "/agents/{agent_id}/identity",
    response_model=AgentIdentityRead,
    dependencies=[IdentityReaderDep],
)
async def get_identity(
    agent_id: uuid.UUID, db: SessionDep, anchors: AnchorCacheDep
) -> AgentIdentityRead:
    agent = await agents_repo.get_by_id(db, agent_id)
    if agent is None:
        raise NotFoundError(f"agent {agent_id} not found")
    anchor = await anchors_repo.current(db, agent.id)
    return identity_read(agent, anchor, as_of=datetime.now(UTC))


@router.get(
    "/identity/agents/{agent_name}",
    response_model=AgentIdentityRead,
    dependencies=[IdentityReaderDep],
)
async def get_identity_by_name(
    agent_name: str, db: SessionDep, anchors: AnchorCacheDep
) -> AgentIdentityRead:
    """The same material as ``/agents/{id}/identity``, addressed by the agent's name.

    A resource server knows the agents it expects by name and holds only an identity-reader
    token, which cannot list agents (that listing is admin-only) — so it bootstraps through
    this route instead.
    """
    read = await anchors.current(db, agent_name)
    if read is None:
        raise NotFoundError(f"agent {agent_name!r} not found")
    return read


@router.post("/agents/{agent_id}/revoke", response_model=RevokeOutcome, dependencies=[AdminDep])
async def revoke_agent(
    agent_id: uuid.UUID,
    db: SessionDep,
    redis: RedisDep,
    service: RevocationServiceDep,
    body: RevokeRequest | None = None,
) -> RevokeOutcome:
    """Idempotent. Cuts off the anchor and every hop that would extend this agent's
    authority — checked at the next authorize and exchange, and by offline verifiers within
    their freshness window."""
    return await service.revoke(db, redis, agent_id, body.reason if body else None)


@router.get(
    "/identity/revocations", response_model=RevocationListRead, dependencies=[IdentityReaderDep]
)
async def list_revocations(
    db: SessionDep,
    service: RevocationServiceDep,
    since: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT)] = DEFAULT_PAGE_LIMIT,
    cursor: Annotated[str | None, Query()] = None,
) -> RevocationListRead:
    if since is not None and since.tzinfo is None:
        raise QueryValidationError(
            "since must include a timezone", [{"loc": ["since"], "msg": "must include a timezone"}]
        )
    try:
        return await service.list(db, since=since, limit=limit, cursor=cursor)
    except (ValueError, TypeError) as exc:
        raise QueryValidationError(
            "invalid cursor", [{"loc": ["cursor"], "msg": str(exc)}]
        ) from exc
