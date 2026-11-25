"""Which registered agent an IdP client acts as (feature 011, M4, research R6).

An MCP client registered at the customer's IdP is *identified* by its tokens' ``azp``; it is
not *authorized* by that (PRD FR-15). An admin maps it to a registered agent here, and from
then on its sessions run in that agent's scope (a scope is rooted at one agent, research F3).
A client nobody mapped gets nothing, and is never turned into an agent automatically: anyone
registered at the IdP could otherwise create objects in this registry.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.config import get_settings
from agentic_auth.errors import ClientAlreadyMapped, NotFoundError
from agentic_auth.models import Agent, AgentClient
from agentic_auth.repositories import agent_clients as repo
from agentic_auth.repositories import agents as agents_repo


@dataclass(frozen=True)
class Mapped:
    agent: Agent
    mapping: AgentClient


class ClientMappingService:
    async def _agent(self, db: AsyncSession, agent_id: uuid.UUID) -> Agent:
        agent = await agents_repo.get_by_id(db, agent_id)
        if agent is None:
            raise NotFoundError(f"agent {agent_id} not found")
        return agent

    async def create(
        self, db: AsyncSession, agent_id: uuid.UUID, client_id: str, *, created_by: str
    ) -> AgentClient:
        await self._agent(db, agent_id)
        issuer = get_settings().principal_idp_issuer
        existing = await repo.get_active(db, issuer, client_id)
        if existing is not None:
            raise ClientAlreadyMapped(
                f"client {client_id!r} already acts as an agent; remove that mapping first",
                {"agent_id": str(existing.agent_id)},
            )
        try:
            # The partial unique index is the final guard against a concurrent create.
            async with db.begin_nested():
                row = await repo.create(
                    db, agent_id=agent_id, issuer=issuer, client_id=client_id, created_by=created_by
                )
        except IntegrityError as exc:
            raise ClientAlreadyMapped(
                f"client {client_id!r} already acts as an agent; remove that mapping first"
            ) from exc
        return row

    async def list(
        self,
        db: AsyncSession,
        agent_id: uuid.UUID,
        limit: int,
        cursor: str | None,
        *,
        include_removed: bool,
    ) -> tuple[list[AgentClient], str | None]:
        await self._agent(db, agent_id)
        return await repo.list_page(db, agent_id, limit, cursor, include_removed=include_removed)

    async def remove(
        self, db: AsyncSession, agent_id: uuid.UUID, client_id: str, *, removed_by: str
    ) -> None:
        """Soft-remove. Idempotent: removing an already removed mapping succeeds. Live
        sessions are not ended; they expire, and revoking the agent is the immediate stop."""
        await self._agent(db, agent_id)
        rows = await repo.for_agent(db, agent_id, client_id)
        if not rows:
            raise NotFoundError(f"client {client_id!r} was never mapped to agent {agent_id}")
        for row in rows:
            if row.removed_at is None:
                await repo.remove(db, row, removed_by=removed_by)

    async def resolve(self, db: AsyncSession, client_id: str) -> Mapped | None:
        issuer = get_settings().principal_idp_issuer
        mapping = await repo.get_active(db, issuer, client_id)
        if mapping is None:
            return None
        agent = await agents_repo.get_by_id(db, mapping.agent_id)
        return Mapped(agent, mapping) if agent is not None else None
