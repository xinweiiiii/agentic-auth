"""``/v1/agents/{id}/sandbox`` and the proposal endpoints (FR-032..FR-042).

Admin-only throughout, and 404 unless ``sandbox_enabled``: a deployment that has not
adopted cold start should not advertise routes that run agents.

Nothing here can affect a decision. A proposal is a ``manifests`` row with status
``proposed``, which the compiler never selects — so no policy is compiled for it, no
session can pin it, and no decision can resolve against it. That is asserted directly in
``tests/unit/test_proposed_is_inert.py`` rather than left to emerge (research.md R12).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.api.deps import AdminDep, SessionDep
from agentic_auth.api.service_deps import SandboxServiceDep
from agentic_auth.config import get_settings
from agentic_auth.errors import NotFoundError
from agentic_auth.models import Agent, SandboxRun
from agentic_auth.repositories import agents as agents_repo
from agentic_auth.repositories import sandbox_runs as runs_repo
from agentic_auth.schemas.sandbox import (
    ObservedRead,
    ProposedManifestRead,
    RatifyRequest,
    SandboxRunListItem,
    SandboxRunPage,
    SandboxRunRead,
    SandboxStart,
)

router = APIRouter(prefix="/v1/agents", tags=["cold-start"], dependencies=[AdminDep])


def _require_enabled() -> None:
    if not get_settings().sandbox_enabled:
        raise NotFoundError("sandboxed observation is not enabled on this deployment")


async def _agent(db: AsyncSession, agent_id: uuid.UUID) -> Agent:
    agent = await agents_repo.get_by_id(db, agent_id)
    if agent is None:
        raise NotFoundError(f"unknown agent {agent_id}")
    return agent


def _read(run: SandboxRun) -> SandboxRunRead:
    observed = None
    proposal = (run.trace or {}).get("x-proposal") if isinstance(run.trace, dict) else None
    if proposal:
        observed = ObservedRead(**proposal.get("observed", {}))
    return SandboxRunRead(
        id=run.id,
        agent_id=run.agent_id,
        status=run.status,
        scope=run.scope,
        started_at=run.started_at,
        deadline_at=run.deadline_at,
        ended_at=run.ended_at,
        recorder_errors=run.recorder_errors,
        observed=observed,
    )


@router.post(
    "/{agent_id}/sandbox", response_model=SandboxRunRead, status_code=status.HTTP_201_CREATED
)
async def start_run(
    agent_id: uuid.UUID,
    body: SandboxStart,
    db: SessionDep,
    sandbox: SandboxServiceDep,
) -> SandboxRunRead:
    """Begin observing. Every call the agent attempts is allowed and recorded, and every
    tool it can reach is a mock with nothing real behind it (FR-032)."""
    _require_enabled()
    await _agent(db, agent_id)
    run = await sandbox.start(
        db, agent_id=agent_id, scope=body.scope, deadline_seconds=body.deadline_seconds
    )
    return _read(run)


@router.get("/{agent_id}/sandbox", response_model=SandboxRunPage)
async def list_runs(
    agent_id: uuid.UUID,
    db: SessionDep,
    limit: int = Query(default=50, ge=1, le=200),
) -> SandboxRunPage:
    _require_enabled()
    await _agent(db, agent_id)
    rows = await runs_repo.list_for_agent(db, agent_id, limit=limit)
    return SandboxRunPage(
        data=[SandboxRunListItem.model_validate(r) for r in rows],
        next_cursor=rows[-1].started_at.isoformat() if len(rows) == limit else None,
    )


@router.get("/{agent_id}/sandbox/{run_id}", response_model=SandboxRunRead)
async def read_run(
    agent_id: uuid.UUID,
    run_id: uuid.UUID,
    db: SessionDep,
    sandbox: SandboxServiceDep,
) -> SandboxRunRead:
    _require_enabled()
    run = await runs_repo.get(db, run_id)
    if run is None or run.agent_id != agent_id:
        raise NotFoundError(f"unknown run {run_id}")
    # The deadline is applied on read rather than by a sweeper: a run only matters when
    # someone asks, and a second place to get the deadline wrong is a second bug.
    return _read(await sandbox.expire_if_due(db, run))


@router.get("/{agent_id}/proposed-manifest", response_model=ProposedManifestRead)
async def read_proposal(
    agent_id: uuid.UUID,
    db: SessionDep,
    sandbox: SandboxServiceDep,
    run_id: uuid.UUID | None = None,
) -> ProposedManifestRead:
    """The manifest proposed from a run — inert until ratified."""
    _require_enabled()
    agent = await _agent(db, agent_id)

    run = (
        await runs_repo.get(db, run_id)
        if run_id is not None
        else await runs_repo.latest_completed(db, agent_id)
    )
    if run is None or run.agent_id != agent_id:
        raise NotFoundError("no completed sandbox run for this agent")

    row = await sandbox.propose(db, run, agent_name=agent.name)
    return ProposedManifestRead(
        manifest_id=row.id,
        agent_id=agent_id,
        run_id=run.id,
        status="proposed",
        doc=row.doc,
        covers_no_behaviour=bool(
            (row.doc.get("x-proposal") or {}).get("covers_no_behaviour", False)
        ),
    )


@router.post("/{agent_id}/proposed-manifest/ratify", status_code=status.HTTP_201_CREATED)
async def ratify_proposal(
    agent_id: uuid.UUID,
    body: RatifyRequest,
    db: SessionDep,
    sandbox: SandboxServiceDep,
) -> dict:
    """The human act that makes a proposal real (FR-037).

    For an agent with no prior manifest this pins version 1, immutable from here
    (FR-038). Reconciliation then runs against it exactly as it would for a hand-written
    manifest, so a ratified manifest that fails reconciliation does not enrol the agent
    (FR-042).
    """
    _require_enabled()
    await _agent(db, agent_id)
    row = await sandbox.ratify(
        db,
        run_id=body.run_id,
        agent_id=agent_id,
        approved_by="admin",
        document=body.doc,
    )
    return {
        "manifest_id": str(row.id),
        "agent_id": str(agent_id),
        "version": row.version,
        "status": row.status,
        "ratified_by": row.ratified_by,
        "ratified_at": row.ratified_at.isoformat() if row.ratified_at else None,
    }
