"""``POST /v1/token/exchange`` — RFC 8693, form-encoded.

Errors follow RFC 6749 §5.2 rather than this project's envelope, because an OAuth client
already knows how to read ``{"error": "invalid_grant"}`` and this endpoint is the one
place we speak someone else's protocol.

From Phase 3 an exchange must name the recorded allow it is spending (``action_id``). The
service refuses to mint unless that row is committed and matches this exact hop, which is
what makes audit-before-dispatch a database property rather than an ordering convention.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse

from app import observability
from app.api.deps import SessionDep
from app.api.service_deps import AuditServiceDep, RedisDep, TokenExchangeServiceDep
from app.errors import DomainError
from app.observability import surface
from app.schemas.authorize import DenyReason, Taint
from app.schemas.token import GRANT_TYPE, JWT_TOKEN_TYPE, TokenExchangeRequest
from app.services.metrics import get_metrics
from app.services.tokens.exchange import ExchangeDenied, ExchangeRefused
from app.services.tokens.replay import ReplayGuardUnavailable, TokenAlreadyExchanged

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["token"])

ACTION_ID_REQUIRED = (
    "action_id is required: pass the action_id from the allow decision for this hop"
)
ACTION_ID_INVALID = "action_id is not a valid UUID"


def exchange_form(
    grant_type: Annotated[str, Form()],
    subject_token: Annotated[str, Form()],
    subject_token_type: Annotated[str, Form()],
    resource: Annotated[str, Form()],
    scope: Annotated[str, Form()],
    actor_token: Annotated[str | None, Form()] = None,
    actor_token_type: Annotated[str | None, Form()] = None,
    audience: Annotated[str | None, Form()] = None,
    taint: Annotated[str | None, Form()] = None,
    # Optional in the signature only so that its absence is an RFC 6749 `invalid_request`
    # with the fix spelled out, rather than FastAPI's generic 422.
    action_id: Annotated[str | None, Form()] = None,
) -> tuple[TokenExchangeRequest, Taint | None, uuid.UUID]:
    if grant_type != GRANT_TYPE:
        raise ExchangeRefused("unsupported_grant_type", f"unsupported grant_type {grant_type!r}")
    if subject_token_type != JWT_TOKEN_TYPE:
        raise ExchangeRefused(
            "invalid_request", f"unsupported subject_token_type {subject_token_type!r}"
        )
    if not action_id:
        raise ExchangeRefused("invalid_request", ACTION_ID_REQUIRED)
    try:
        recorded_action = uuid.UUID(action_id)
    except ValueError as exc:
        raise ExchangeRefused("invalid_request", ACTION_ID_INVALID) from exc

    return (
        TokenExchangeRequest(
            grant_type=GRANT_TYPE,
            subject_token=subject_token,
            subject_token_type=JWT_TOKEN_TYPE,
            resource=resource,
            scope=scope,
            actor_token=actor_token,
            actor_token_type=JWT_TOKEN_TYPE if actor_token_type else None,
            audience=audience,
        ),
        Taint(taint) if taint else None,
        recorded_action,
    )


def _oauth_error(
    status: int, error: str, description: str, *, reason: DenyReason | None = None
) -> JSONResponse:
    """RFC 6749 §5.2, plus the machine reason when policy is what refused.

    ``error`` stays the OAuth code an OAuth client branches on. ``reason`` is an additive
    member (§5.2 permits them) carrying the same deny vocabulary the decision endpoint
    returns, because an enforcement point needs to tell AGENT_NOT_ENROLLED from
    OUT_OF_SCOPE — and only this response knows which it was: ``AGENT_NOT_ENROLLED`` is
    established by the proof-of-possession check, which lives here and not in the PDP.
    """
    body: dict[str, str] = {"error": error, "error_description": description}
    if reason is not None:
        body["reason"] = reason.value
    return JSONResponse(status_code=status, content=body)


@router.post("/token/exchange")
async def exchange_token(
    request: Request,
    parsed: Annotated[tuple[TokenExchangeRequest, Taint | None, uuid.UUID], Depends(exchange_form)],
    db: SessionDep,
    redis: RedisDep,
    service: TokenExchangeServiceDep,
    audit: AuditServiceDep,
) -> JSONResponse:
    body, taint, action_id = parsed
    span = _ExchangeSpan(request.headers, action_id)
    try:
        response, _decision, _subject = await service.exchange(
            db, redis, body, taint=taint, action_id=action_id
        )
    except ExchangeDenied as denied:
        # The recorded allow no longer holds under a fresh decision. Record the refusal,
        # then say no. A denied hop yields no token, whether or not the record lands.
        await audit.record(
            db,
            session_id=denied.session_id,
            caller=denied.caller,
            target=denied.target,
            data_class=denied.data_class,
            decision=denied.decision,
            enforced=True,
            taint=denied.decision.taint.value if denied.decision.taint else None,
            taint_source=denied.taint_source,
            privileged=denied.decision.privileged,
            policy_version=denied.policy_version,
            token=denied.token,
        )
        if denied.decision.reason is not None:
            get_metrics().denials.labels(reason=denied.decision.reason.value).inc()
        span.emit("denied", session_id=str(denied.session_id), hop=denied.decision.hop)
        return _oauth_error(403, "invalid_target", str(denied), reason=denied.decision.reason)
    except TokenAlreadyExchanged as exc:
        span.emit("already_exchanged")
        return _oauth_error(400, "invalid_grant", str(exc))
    except ReplayGuardUnavailable as exc:
        # The stack trace is deliberately NOT recorded: once a sink is attached the SDK exports
        # `exception.stacktrace` verbatim, and a traceback through token verification can carry
        # a token fragment.
        logger.error(
            "replay guard unavailable; refusing to issue",
            extra={
                "authz.component": surface.COMPONENT_CONTROL_PLANE,
                "error.type": type(exc).__name__,
            },
        )
        span.emit("replay_guard_unavailable")
        return _oauth_error(503, "invalid_grant", "single-use guard unavailable; refusing to issue")
    except DomainError:
        span.emit("refused")
        raise
    # ExchangeRefused is rendered by the app-wide OAuth handler (app/api/errors.py),
    # because the grant grammar is validated in a dependency that runs before this body.

    span.emit("ok")
    return JSONResponse(status_code=200, content=response.model_dump())


class _ExchangeSpan:
    """Emits exactly one ``authz.exchange`` span, whichever way the handler leaves.

    A small class rather than a ``with`` block because the handler has six exits and the
    attributes are only known at each one. ``emit`` is idempotent, so a path that records and
    then re-raises cannot double-count.
    """

    __slots__ = ("_action_id", "_done", "_headers")

    def __init__(self, headers: Mapping[str, str], action_id: uuid.UUID) -> None:
        self._headers = headers
        self._action_id = action_id
        self._done = False

    def emit(self, result: str, *, session_id: str | None = None, hop: int | None = None) -> None:
        if self._done:
            return
        self._done = True
        config = observability.config()
        if not config.enabled:
            return
        parent = observability.extract_parent(
            self._headers, session_id=session_id, key=config.key, metrics=get_metrics()
        )
        attributes = observability.exchange_attributes(
            config,
            action_id=str(self._action_id),
            session_id=session_id,
            hop=hop,
            result=result,
        )
        with observability.tracer().start_as_current_span(
            surface.SPAN_EXCHANGE,
            context=parent,
            attributes=attributes,
            record_exception=False,
        ):
            pass
