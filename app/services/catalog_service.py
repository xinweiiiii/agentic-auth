"""Scope catalog reads, backed by the immutable Redis DAG cache.

Cache key: ``dag:{scope}:{version}`` — immutable, no TTL. On a miss the catalog is read
from Postgres and written back.
"""

from __future__ import annotations

import contextlib
import json

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.errors import NotFoundError
from app.repositories import compiled_policies as policies_repo
from app.schemas.dag import ScopeCatalog


def _key(scope: str, version: int) -> str:
    return f"dag:{scope}:{version}"


def _catalog_from_dag(scope: str, version: int, dag: dict) -> ScopeCatalog:
    return ScopeCatalog(
        scope=scope,
        version=version,
        tools=dag.get("tools", []),
        data_classes=dag.get("data_classes", {"reads": [], "writes": []}),
        downstream_agents=dag.get("downstream_agents", []),
        hop_budget=dag["hop_budget"],
    )


async def get_catalog(
    session: AsyncSession, redis: Redis, scope: str, version: int | None
) -> ScopeCatalog:
    if version is None:
        version = await policies_repo.latest_version_number(session, scope)
        if version is None:
            raise NotFoundError(f"no compiled DAG for scope {scope!r}")

    cached = await redis.get(_key(scope, version))
    if cached is not None:
        return _catalog_from_dag(scope, version, json.loads(cached))

    row = await policies_repo.get_version(session, scope, version)
    if row is None:
        raise NotFoundError(f"no compiled DAG for scope {scope!r} version {version}")

    await redis.set(_key(scope, version), json.dumps(row.dag))
    return _catalog_from_dag(scope, version, row.dag)


async def warm(redis: Redis, scope: str, version: int, dag: dict) -> None:
    """Best-effort write-through after a compile."""
    with contextlib.suppress(Exception):
        await redis.set(_key(scope, version), json.dumps(dag))
