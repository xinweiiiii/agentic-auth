"""``/v1/agents/{agent_id}/clients`` — which IdP clients act as this agent (feature 011, M4).

Admin-only, and 404 unless ``client_mapping_enabled``: a deployment that has not opted in
should not discover the endpoints.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Response, status

from agentic_auth.api.deps import AdminDep, PaginationDep, SessionDep
from agentic_auth.config import get_settings
from agentic_auth.errors import NotFoundError
from agentic_auth.schemas.agent_client import AgentClientCreate, AgentClientRead
from agentic_auth.schemas.common import Page, PageInfo
from agentic_auth.services.client_mapping import ClientMappingService

router = APIRouter(prefix="/v1/agents", tags=["client-mapping"], dependencies=[AdminDep])

ADMIN_IDENTITY = "admin"


def _require_enabled() -> None:
    if not get_settings().client_mapping_enabled:
        raise NotFoundError("client mapping is not enabled on this deployment")


@router.post(
    "/{agent_id}/clients", response_model=AgentClientRead, status_code=status.HTTP_201_CREATED
)
async def map_client(
    agent_id: uuid.UUID, body: AgentClientCreate, db: SessionDep
) -> AgentClientRead:
    _require_enabled()
    row = await ClientMappingService().create(
        db, agent_id, body.client_id, created_by=ADMIN_IDENTITY
    )
    return AgentClientRead.model_validate(row)


@router.get("/{agent_id}/clients", response_model=Page[AgentClientRead])
async def list_clients(
    agent_id: uuid.UUID,
    db: SessionDep,
    pagination: PaginationDep,
    include_removed: Annotated[bool, Query()] = False,
) -> Page[AgentClientRead]:
    _require_enabled()
    rows, next_cursor = await ClientMappingService().list(
        db, agent_id, pagination.limit, pagination.cursor, include_removed=include_removed
    )
    return Page(
        data=[AgentClientRead.model_validate(r) for r in rows],
        page=PageInfo(next_cursor=next_cursor, limit=pagination.limit),
    )


@router.delete("/{agent_id}/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unmap_client(agent_id: uuid.UUID, client_id: str, db: SessionDep) -> Response:
    _require_enabled()
    await ClientMappingService().remove(db, agent_id, client_id, removed_by=ADMIN_IDENTITY)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
