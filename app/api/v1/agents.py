"""``/v1/agents`` — registration, listing, reconciliation reports."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Response

from app.api.deps import AdminDep, PaginationDep, SessionDep
from app.api.responses import render_outcome
from app.api.service_deps import ManifestServiceDep, RedisDep
from app.errors import NotFoundError
from app.repositories import agents as agents_repo
from app.repositories import reconciliation_reports as reports_repo
from app.schemas.agent import AgentCreate, AgentListItem, AgentStatus
from app.schemas.common import Page, PageInfo
from app.schemas.reconciliation import ReconciliationReport

router = APIRouter(prefix="/v1", tags=["agents"], dependencies=[AdminDep])

ADMIN_IDENTITY = "admin"


@router.post("/agents")
async def register_agent(
    body: AgentCreate,
    session: SessionDep,
    service: ManifestServiceDep,
    redis: RedisDep,
) -> Response:
    outcome = await service.register_agent(
        session,
        redis,
        name=body.name,
        manifest=body.manifest,
        attested_by=ADMIN_IDENTITY,
        override=body.override,
    )
    return render_outcome(
        outcome,
        created_key={
            "agent_id": str(outcome.agent_id),
            "manifest_version": outcome.version,
            "status": outcome.status,
        },
    )


@router.get("/agents", response_model=Page[AgentListItem])
async def list_agents(
    session: SessionDep,
    pagination: PaginationDep,
    status: Annotated[AgentStatus | None, Query()] = None,
) -> Page[AgentListItem]:
    rows, next_cursor = await agents_repo.list_page(
        session, pagination.limit, pagination.cursor, status=status
    )
    latest = await agents_repo.latest_versions(session, [a.id for a in rows])
    items = [
        AgentListItem(
            id=a.id,
            name=a.name,
            status=a.status,
            trust_anchor_version=a.trust_anchor_version,
            latest_manifest_version=latest.get(a.id, (None, None))[0],
            latest_status=latest.get(a.id, (None, None))[1],
        )
        for a in rows
    ]
    return Page(data=items, page=PageInfo(next_cursor=next_cursor, limit=pagination.limit))


@router.get("/agents/{agent_id}/reconciliation", response_model=ReconciliationReport)
async def get_reconciliation(agent_id: uuid.UUID, session: SessionDep) -> ReconciliationReport:
    agent = await agents_repo.get_by_id(session, agent_id)
    if agent is None:
        raise NotFoundError(f"agent {agent_id} not found")
    found = await reports_repo.get_latest_for_agent(session, agent_id)
    if found is None:
        raise NotFoundError(f"agent {agent_id} has no manifest submission yet")
    report, manifest = found
    return ReconciliationReport(
        manifest_version=manifest.version,
        status=manifest.status,
        discovery_ok=report.discovery_ok,
        diff=report.diff,
    )
