"""Exception handlers that render the standard error envelope."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.errors import DomainError
from app.services.tokens.exchange import ExchangeRefused


def _envelope(code: str, message: str, details: dict | None = None) -> dict:
    body: dict = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return body


async def _domain_handler(_: Request, exc: DomainError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=_envelope(exc.code, exc.message, exc.details),
    )


async def _validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    fields = [{"loc": [str(p) for p in err["loc"]], "msg": err["msg"]} for err in exc.errors()]
    return JSONResponse(
        status_code=422,
        content=_envelope("validation_error", "request validation failed", {"fields": fields}),
    )


async def _oauth_handler(_: Request, exc: ExchangeRefused) -> JSONResponse:
    """RFC 6749 §5.2 error body — the token endpoint speaks OAuth, not our envelope.

    Registered app-wide rather than caught in the route because the grant grammar is
    validated in a dependency, which runs before the handler body.
    """
    status = 403 if exc.oauth_error == "invalid_target" else 400
    return JSONResponse(
        status_code=status,
        content={"error": exc.oauth_error, "error_description": exc.description},
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(DomainError, _domain_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, _validation_handler)  # type: ignore[arg-type]
    app.add_exception_handler(ExchangeRefused, _oauth_handler)  # type: ignore[arg-type]
