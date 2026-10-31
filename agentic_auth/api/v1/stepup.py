"""``/v1/consent/step-up`` — a recoverable refusal becomes a question (FR-022..FR-031).

Two routes, with deliberately different authentication:

- **Raising** a challenge takes the session's own grant or an admin bearer. Asking is
  harmless; it grants nothing.
- **Answering** one takes the consenting human's credential. An agent that could approve
  its own widening would turn ``SCOPE_NOT_CONSENTED`` into a formality, and the whole
  threat model assumes the agent may be under an attacker's influence (research.md R6).

Both answer 404 unless ``step_up_enabled``, so a deployment that has not adopted step-up
does not advertise an endpoint it will refuse everything from.
"""

from __future__ import annotations

from fastapi import APIRouter, status

from agentic_auth.api.deps import AdminDep, ConsentingHumanDep, SessionDep
from agentic_auth.api.service_deps import RedisDep, SessionServiceDep, StepUpServiceDep
from agentic_auth.config import get_settings
from agentic_auth.errors import NotFoundError
from agentic_auth.schemas.authorize import StepUpChallenge
from agentic_auth.schemas.stepup import StepUpComplete, StepUpGrantRead, StepUpRequest
from agentic_auth.services import policy_loader

router = APIRouter(prefix="/v1/consent", tags=["step-up"])


def _require_enabled() -> None:
    if not get_settings().step_up_enabled:
        raise NotFoundError("step-up consent is not enabled on this deployment")


@router.post(
    "/step-up",
    response_model=StepUpChallenge,
    status_code=status.HTTP_201_CREATED,
    dependencies=[AdminDep],
)
async def raise_challenge(
    body: StepUpRequest,
    db: SessionDep,
    redis: RedisDep,
    sessions: SessionServiceDep,
    stepup: StepUpServiceDep,
) -> StepUpChallenge:
    """Ask the human whether to widen this session by the data class that was refused.

    The session's pinned policy is loaded here so the ceiling can be checked before a
    human is ever asked: a widening that could not be granted should fail now, not after
    someone approves it.
    """
    _require_enabled()
    session = await sessions.get(db, redis, str(body.session_id))
    policy = await policy_loader.load(db, redis, session.scope, session.policy_version)
    return await stepup.challenge(
        db,
        redis,
        session_id=body.session_id,
        blocked_action_id=body.blocked_action_id,
        policy=policy,
    )


@router.post("/step-up/complete", response_model=StepUpGrantRead)
async def complete_challenge(
    body: StepUpComplete,
    approver: ConsentingHumanDep,
    db: SessionDep,
    redis: RedisDep,
    sessions: SessionServiceDep,
    stepup: StepUpServiceDep,
) -> StepUpGrantRead:
    """Record the human's answer. On an approval the chain may resume from the blocked
    hop; on a decline the original refusal stands."""
    _require_enabled()
    settings = get_settings()
    return await stepup.complete(
        db,
        redis,
        challenge_id=body.challenge_id,
        approved=body.approved,
        approved_by=approver,
        session_ttl_seconds=settings.session_ttl_seconds,
    )
