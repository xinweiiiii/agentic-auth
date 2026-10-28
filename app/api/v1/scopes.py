"""``/v1/scopes/{scope}/catalog`` — what a scope expands to."""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.api.deps import AdminDep, SessionDep
from app.api.service_deps import RedisDep
from app.schemas.dag import ScopeCatalog
from app.services import catalog_service

router = APIRouter(prefix="/v1", tags=["scopes"], dependencies=[AdminDep])


@router.get("/scopes/{scope}/catalog", response_model=ScopeCatalog)
async def get_scope_catalog(
    scope: str,
    session: SessionDep,
    redis: RedisDep,
    version: int | None = Query(default=None, ge=1),
) -> ScopeCatalog:
    return await catalog_service.get_catalog(session, redis, scope, version)
