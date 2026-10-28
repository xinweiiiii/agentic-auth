"""Persistence for ``reconciliation_reports`` (one per manifest submission)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Manifest, ReconciliationReport


async def create(
    session: AsyncSession,
    *,
    manifest_id: uuid.UUID,
    diff: list[dict[str, Any]],
    discovery_ok: bool,
) -> ReconciliationReport:
    report = ReconciliationReport(manifest_id=manifest_id, diff=diff, discovery_ok=discovery_ok)
    session.add(report)
    await session.flush()
    return report


async def get_latest_for_agent(
    session: AsyncSession, agent_id: uuid.UUID
) -> tuple[ReconciliationReport, Manifest] | None:
    stmt = (
        select(ReconciliationReport, Manifest)
        .join(Manifest, ReconciliationReport.manifest_id == Manifest.id)
        .where(Manifest.agent_id == agent_id)
        .order_by(Manifest.version.desc())
        .limit(1)
    )
    row = (await session.execute(stmt)).first()
    if row is None:
        return None
    return row[0], row[1]
