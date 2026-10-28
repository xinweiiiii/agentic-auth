"""``/v1/manifests`` — submit a new version, immutable version-pinned reads."""

from __future__ import annotations

from fastapi import APIRouter, Query, Response

from app.api.deps import AdminDep, SessionDep
from app.api.responses import render_outcome
from app.api.service_deps import ManifestServiceDep, RedisDep
from app.api.v1.agents import ADMIN_IDENTITY
from app.errors import NotFoundError
from app.repositories import agents as agents_repo
from app.repositories import manifests as manifests_repo
from app.schemas.manifest_api import ManifestCreate, ManifestRead

router = APIRouter(prefix="/v1", tags=["manifests"], dependencies=[AdminDep])


@router.post("/manifests")
async def submit_manifest(
    body: ManifestCreate,
    session: SessionDep,
    service: ManifestServiceDep,
    redis: RedisDep,
) -> Response:
    outcome = await service.submit_manifest(
        session,
        redis,
        agent_name=body.agent,
        manifest=body.manifest,
        attested_by=ADMIN_IDENTITY,
        override=body.override,
    )
    return render_outcome(
        outcome,
        created_key={
            "agent": outcome.agent_name,
            "version": outcome.version,
            "status": outcome.status,
        },
    )


@router.get("/manifests/{scope}", response_model=ManifestRead)
async def read_manifest(
    scope: str,
    session: SessionDep,
    version: int | None = Query(default=None, ge=1),
) -> ManifestRead:
    agent = await agents_repo.get_by_name(session, scope)
    if agent is None:
        raise NotFoundError(f"no manifest for scope {scope!r}")

    if version is None:
        row = await manifests_repo.get_latest(session, agent.id)
    else:
        row = await manifests_repo.get_version(session, agent.id, version)
    if row is None:
        raise NotFoundError(f"no manifest for scope {scope!r} version {version}")

    return ManifestRead(
        agent=scope,
        version=row.version,
        status=row.status,
        attested_by=row.attested_by,
        doc=row.doc,
        created_at=row.created_at,
    )
