"""``POST /v1/token/transaction`` — call-bound authority for one privileged tool call.

Bearer: the hop token minted for the tool call (``aud`` = target). The recorded decision is
read from the token's signed ``action_id`` claim, never from the body.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from agentic_auth import observability
from agentic_auth.api.deps import PresentedTokenDep, SessionDep
from agentic_auth.api.service_deps import RedisDep, TransactionServiceDep
from agentic_auth.config import get_settings
from agentic_auth.errors import NotFoundError, TransactionValidationError
from agentic_auth.observability import surface
from agentic_auth.schemas.transaction import TransactionMinted, TransactionMintRequest
from agentic_auth.services.metrics import get_metrics

router = APIRouter(prefix="/v1", tags=["token"])


@router.post("/token/transaction", response_model=TransactionMinted)
async def mint_transaction_token(
    request: Request,
    body: TransactionMintRequest,
    db: SessionDep,
    redis: RedisDep,
    service: TransactionServiceDep,
    token: PresentedTokenDep,
) -> TransactionMinted:
    settings = get_settings()
    if not settings.transaction_tokens_enabled:
        raise NotFoundError("transaction tokens are disabled")
    declared = request.headers.get("content-length")
    if (
        declared is not None
        and declared.isdigit()
        and int(declared) > settings.max_privileged_body_bytes
    ):
        _emit_mint_span(request, token, "too_large")
        raise TransactionValidationError(
            "params exceed the binding size cap",
            [{"loc": ["params"], "msg": f"> {settings.max_privileged_body_bytes} bytes"}],
        )
    try:
        minted = await service.mint(db, redis, token, body.params)
    except Exception as exc:
        _emit_mint_span(request, token, "refused", error_type=type(exc).__name__)
        raise
    _emit_mint_span(request, token, "minted")
    return minted


def _emit_mint_span(
    request: Request,
    token: object,
    result: str,
    *,
    error_type: str | None = None,
) -> None:
    """``authz.transaction.mint``.

    Records *that* a binding was computed and nothing about what was bound: no ``params``, no
    ``params_hash``, no binding, no part of the request body.
    ``agentic_auth/observability/surface.py``
    refuses those keys by substring, so this is enforced rather than merely intended.
    """
    config = observability.config()
    if not config.enabled:
        return
    session_id = getattr(token, "session_id", None)
    attributes = observability.mint_attributes(
        config,
        action_id=str(getattr(token, "action_id", "") or "") or None,
        session_id=str(session_id) if session_id else None,
        result=result,
        acting_agent=getattr(token, "holder", None),
    )
    if error_type is not None:
        attributes[surface.ATTR_ERROR_TYPE] = error_type
    parent = observability.extract_parent(
        request.headers,
        session_id=str(session_id) if session_id else None,
        key=config.key,
        metrics=get_metrics(),
    )
    with observability.tracer().start_as_current_span(
        surface.SPAN_MINT,
        context=parent,
        attributes=attributes,
        record_exception=False,
    ):
        pass
