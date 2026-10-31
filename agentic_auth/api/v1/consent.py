"""``POST /v1/consent`` — the human act that roots a session's authority."""

from __future__ import annotations

from fastapi import APIRouter, status

from agentic_auth.api.deps import AdminDep, SessionDep
from agentic_auth.api.service_deps import RedisDep, SessionServiceDep
from agentic_auth.schemas.consent import ConsentCreate, ConsentRead

router = APIRouter(prefix="/v1", tags=["consent"], dependencies=[AdminDep])


@router.post("/consent", response_model=ConsentRead, status_code=status.HTTP_201_CREATED)
async def create_consent(
    body: ConsentCreate,
    db: SessionDep,
    redis: RedisDep,
    sessions: SessionServiceDep,
) -> ConsentRead:
    return await sessions.consent(db, redis, body)
