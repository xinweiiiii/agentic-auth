"""``POST /v1/consent`` — the human act that roots a session's authority."""

from __future__ import annotations

from fastapi import APIRouter, status

from agentic_auth.api.deps import ConsenterDep, SessionDep
from agentic_auth.api.service_deps import RedisDep, SessionServiceDep
from agentic_auth.schemas.consent import ConsentCreate, ConsentRead

# The consent token or admin (feature 011): what a connector proxy holds is enough to start a
# session for a user it validated, and nothing else.
router = APIRouter(prefix="/v1", tags=["consent"], dependencies=[ConsenterDep])


@router.post("/consent", response_model=ConsentRead, status_code=status.HTTP_201_CREATED)
async def create_consent(
    body: ConsentCreate,
    db: SessionDep,
    redis: RedisDep,
    sessions: SessionServiceDep,
) -> ConsentRead:
    return await sessions.consent(db, redis, body)
