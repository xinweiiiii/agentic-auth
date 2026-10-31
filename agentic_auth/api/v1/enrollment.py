"""``/v1/agents/{id}/enroll`` and ``/enroll/complete`` — challenge, then signed response.

A ``200`` from ``complete`` never means "authorized". It means a trust anchor now exists
(enrolled) or does not (quarantined). Authorization is the hop token, minted elsewhere.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from agentic_auth.api.deps import EnrollerDep, SessionDep
from agentic_auth.api.service_deps import EnrollmentServiceDep, RedisDep
from agentic_auth.schemas.identity import (
    EnrollBegin,
    EnrollChallenge,
    EnrollComplete,
    EnrollOutcome,
)

router = APIRouter(prefix="/v1", tags=["enrollment"], dependencies=[EnrollerDep])


@router.post(
    "/agents/{agent_id}/enroll",
    response_model=EnrollChallenge,
    status_code=status.HTTP_201_CREATED,
)
async def begin_enrollment(
    agent_id: uuid.UUID,
    body: EnrollBegin,
    db: SessionDep,
    redis: RedisDep,
    service: EnrollmentServiceDep,
) -> EnrollChallenge:
    return await service.begin(db, redis, agent_id, body)


@router.post("/agents/{agent_id}/enroll/complete", response_model=EnrollOutcome)
async def complete_enrollment(
    agent_id: uuid.UUID,
    body: EnrollComplete,
    db: SessionDep,
    redis: RedisDep,
    service: EnrollmentServiceDep,
) -> EnrollOutcome:
    return await service.complete(db, redis, agent_id, body)
