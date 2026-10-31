"""Persistence for sandbox observation runs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession as DbSession

from agentic_auth.models import SandboxRun
from agentic_auth.models.sandbox_run import STATUS_RUNNING


async def start(
    db: DbSession,
    *,
    agent_id: uuid.UUID,
    scope: str,
    started_at: datetime,
    deadline_at: datetime,
) -> SandboxRun:
    """Open a run. The partial unique index refuses a second concurrent one for the same
    agent — two traces racing to become one proposal is a correctness problem, not a
    capacity one, so the caller turns the IntegrityError into a 409."""
    row = SandboxRun(
        agent_id=agent_id,
        scope=scope,
        status=STATUS_RUNNING,
        started_at=started_at,
        deadline_at=deadline_at,
    )
    db.add(row)
    await db.flush()
    return row


async def finish(
    db: DbSession,
    run: SandboxRun,
    *,
    status: str,
    ended_at: datetime,
    trace: dict[str, Any] | None,
    recorder_errors: int = 0,
) -> SandboxRun:
    run.status = status
    run.ended_at = ended_at
    # `trace=None` means "no NEW trace", not "discard what was observed". A run stopped
    # by its deadline must keep what it saw — FR-033 says the proposal covers what was
    # observed up to that point, and nulling it here would make that impossible.
    if trace is not None:
        run.trace = trace
        run.recorder_errors = recorder_errors
    await db.flush()
    return run


async def get(db: DbSession, run_id: uuid.UUID) -> SandboxRun | None:
    return (
        await db.execute(select(SandboxRun).where(SandboxRun.id == run_id))
    ).scalar_one_or_none()


async def running_for(db: DbSession, agent_id: uuid.UUID) -> SandboxRun | None:
    return (
        await db.execute(
            select(SandboxRun).where(
                SandboxRun.agent_id == agent_id, SandboxRun.status == STATUS_RUNNING
            )
        )
    ).scalar_one_or_none()


async def latest_completed(db: DbSession, agent_id: uuid.UUID) -> SandboxRun | None:
    from agentic_auth.models.sandbox_run import STATUS_COMPLETED, STATUS_DEADLINE_EXCEEDED

    return (
        await db.execute(
            select(SandboxRun)
            .where(
                SandboxRun.agent_id == agent_id,
                SandboxRun.status.in_([STATUS_COMPLETED, STATUS_DEADLINE_EXCEEDED]),
            )
            .order_by(SandboxRun.started_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def list_for_agent(
    db: DbSession, agent_id: uuid.UUID, *, limit: int = 50, before: datetime | None = None
) -> list[SandboxRun]:
    """Keyset on ``(started_at, id)``, newest first."""
    stmt = select(SandboxRun).where(SandboxRun.agent_id == agent_id)
    if before is not None:
        stmt = stmt.where(SandboxRun.started_at < before)
    stmt = stmt.order_by(SandboxRun.started_at.desc(), SandboxRun.id.desc()).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


__all__ = ["finish", "get", "latest_completed", "list_for_agent", "running_for", "start"]
