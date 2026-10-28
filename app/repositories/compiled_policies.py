"""Append-only persistence for ``compiled_policies`` (versioned per scope)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CompiledPolicy


async def append_version(
    session: AsyncSession,
    *,
    scope: str,
    dag: dict[str, Any],
    source_manifest_ids: list[uuid.UUID],
    max_retries: int = 5,
) -> CompiledPolicy:
    for _ in range(max_retries):
        current = (
            await session.execute(
                select(func.max(CompiledPolicy.version)).where(CompiledPolicy.scope == scope)
            )
        ).scalar_one()
        version = (current or 0) + 1
        row = CompiledPolicy(
            scope=scope,
            version=version,
            dag={**dag, "version": version},
            source_manifest_ids=source_manifest_ids,
        )
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
            return row
        except IntegrityError:
            continue
    raise RuntimeError("could not assign a compiled-policy version after retries")


async def get_version(session: AsyncSession, scope: str, version: int) -> CompiledPolicy | None:
    return (
        await session.execute(
            select(CompiledPolicy).where(
                CompiledPolicy.scope == scope, CompiledPolicy.version == version
            )
        )
    ).scalar_one_or_none()


async def get_latest(session: AsyncSession, scope: str) -> CompiledPolicy | None:
    return (
        await session.execute(
            select(CompiledPolicy)
            .where(CompiledPolicy.scope == scope)
            .order_by(CompiledPolicy.version.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def latest_version_number(session: AsyncSession, scope: str) -> int | None:
    return (
        await session.execute(
            select(func.max(CompiledPolicy.version)).where(CompiledPolicy.scope == scope)
        )
    ).scalar_one()
