"""Append-only persistence for ``manifests``.

Version numbers are server-assigned, monotonic per agent, and gap-free. The repository
exposes no update or delete.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.models import Manifest
from agentic_auth.models.manifest import STATUS_PROPOSED


async def _next_version(session: AsyncSession, agent_id: uuid.UUID) -> int:
    current = (
        await session.execute(
            select(func.max(Manifest.version)).where(Manifest.agent_id == agent_id)
        )
    ).scalar_one()
    return (current or 0) + 1


async def append_version(
    session: AsyncSession,
    *,
    agent_id: uuid.UUID,
    doc: dict[str, Any],
    status: str,
    attested_by: str,
    override_reason: str | None,
    max_retries: int = 5,
) -> Manifest:
    """Insert the next version for an agent, retrying on a lost race for the number."""
    if not attested_by or not attested_by.strip():
        raise ValueError("attested_by must not be empty")

    for _ in range(max_retries):
        version = await _next_version(session, agent_id)
        manifest = Manifest(
            agent_id=agent_id,
            version=version,
            doc=doc,
            status=status,
            attested_by=attested_by,
            override_reason=override_reason,
        )
        try:
            async with session.begin_nested():
                session.add(manifest)
                await session.flush()
            return manifest
        except IntegrityError:
            # Lost the race for this version number; recompute and retry.
            continue
    raise RuntimeError("could not assign a manifest version after retries")


async def get_version(session: AsyncSession, agent_id: uuid.UUID, version: int) -> Manifest | None:
    return (
        await session.execute(
            select(Manifest).where(Manifest.agent_id == agent_id, Manifest.version == version)
        )
    ).scalar_one_or_none()


async def get_latest(session: AsyncSession, agent_id: uuid.UUID) -> Manifest | None:
    return (
        await session.execute(
            select(Manifest)
            .where(Manifest.agent_id == agent_id)
            .order_by(Manifest.version.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def list_versions(session: AsyncSession, agent_id: uuid.UUID) -> list[Manifest]:
    return list(
        (
            await session.execute(
                select(Manifest).where(Manifest.agent_id == agent_id).order_by(Manifest.version)
            )
        )
        .scalars()
        .all()
    )


async def latest_resolvable(session: AsyncSession, agent_id: uuid.UUID) -> Manifest | None:
    """The newest manifest that may take part in a decision — never a proposal.

    ``get_latest`` deliberately still returns a ``proposed`` row, because the proposal
    endpoints need to read it. Anything on a decision path calls this instead.
    """
    return (
        await session.execute(
            select(Manifest)
            .where(Manifest.agent_id == agent_id, Manifest.status != STATUS_PROPOSED)
            .order_by(Manifest.version.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def proposed_for(session: AsyncSession, agent_id: uuid.UUID) -> Manifest | None:
    """The agent's outstanding proposal, if any. At most one is ever open, because a
    ratification flips the row out of ``proposed`` and only one run may be in flight."""
    return (
        await session.execute(
            select(Manifest)
            .where(Manifest.agent_id == agent_id, Manifest.status == STATUS_PROPOSED)
            .order_by(Manifest.version.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def proposed_from_run(session: AsyncSession, run_id: uuid.UUID) -> Manifest | None:
    return (
        await session.execute(select(Manifest).where(Manifest.proposed_from_run_id == run_id))
    ).scalar_one_or_none()


async def all_reconciled(session: AsyncSession) -> list[Manifest]:
    """Latest reconciled manifest for every agent (input to DAG compilation).

    **This is where a proposal stops.** The filter below already excludes
    ``status = 'proposed'``, so an observation-derived manifest never reaches the
    compiler, no ``compiled_policies`` row exists for it, and therefore
    ``SessionService.consent()`` raises before its insert and no session can pin it.
    Inertness is a property of this one predicate, so ``tests/unit/test_proposed_is_inert.py``
    asserts it explicitly rather than trusting that it stays true by accident.
    """
    sub = (
        select(Manifest.agent_id, func.max(Manifest.version).label("v"))
        .where(Manifest.status == "reconciled")
        .group_by(Manifest.agent_id)
        .subquery()
    )
    stmt = select(Manifest).join(
        sub, (Manifest.agent_id == sub.c.agent_id) & (Manifest.version == sub.c.v)
    )
    return list((await session.execute(stmt)).scalars().all())
