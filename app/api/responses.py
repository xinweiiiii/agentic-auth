"""Shared helpers for rendering process outcomes to HTTP responses."""

from __future__ import annotations

from fastapi.responses import JSONResponse

from app.services.manifest_service import ProcessOutcome


def _envelope(code: str, message: str, details: dict | None = None) -> dict:
    body: dict = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return body


def render_outcome(outcome: ProcessOutcome, *, created_key: dict) -> JSONResponse:
    """``created_key`` is the 201 body (already JSON-serializable)."""
    if outcome.http_status == 201:
        return JSONResponse(status_code=201, content=created_key)
    if outcome.http_status == 422:
        return JSONResponse(
            status_code=422,
            content=_envelope(
                "reconciliation_rejected",
                "manifest declares capabilities that exceed or conflict with what is discoverable",
                {"diff": outcome.diff},
            ),
        )
    # 409
    return JSONResponse(
        status_code=409,
        content=_envelope(
            "needs_review",
            "capability discovery was unavailable; resubmit with an override reason to proceed",
            {"diff": outcome.diff},
        ),
    )
