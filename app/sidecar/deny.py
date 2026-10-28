"""The structured refusal the agent receives.

``reason`` and ``recoverable`` are the machine contract — an agent may branch on them.
``message`` is for humans and may change between versions.
"""

from __future__ import annotations

from typing import Any

from starlette.responses import JSONResponse

from app.schemas.authorize import INFRASTRUCTURE_REASONS, DenyReason, is_recoverable

# Policy said no (403) vs. we could not ask or could not record (503). Collapsing the two
# would make "you may not" indistinguishable from "we do not know", and only one of those
# is worth retrying. The set lives in app.schemas.authorize so observe mode, this renderer,
# and the SDK can never classify a reason differently.
__all__ = ["INFRASTRUCTURE_REASONS"]

UPSTREAM_NOT_MAPPED = "UPSTREAM_NOT_MAPPED"
TARGET_NOT_RESOLVED = "TARGET_NOT_RESOLVED"
# Phase 4, local to the sidecar: a privileged call whose body could not be bound.
BODY_TOO_LARGE_TO_BIND = "BODY_TOO_LARGE_TO_BIND"
PARAMS_NOT_AN_OBJECT = "PARAMS_NOT_AN_OBJECT"
# Phase 4, infrastructure: the mint could not be reached or answered unusably (503).
TRANSACTION_SERVICE_UNAVAILABLE = "TRANSACTION_SERVICE_UNAVAILABLE"


def deny_body(
    reason: str,
    message: str,
    *,
    recoverable: bool = False,
    target: str | None = None,
    hop: int | None = None,
    session_id: str | None = None,
    policy_version: int | None = None,
) -> dict[str, Any]:
    details: dict[str, Any] = {"reason": reason, "recoverable": recoverable}
    for key, value in (
        ("target", target),
        ("hop", hop),
        ("session_id", session_id),
        ("policy_version", policy_version),
    ):
        if value is not None:
            details[key] = value
    return {"error": {"code": "policy_denied", "message": message, "details": details}}


def policy_denied(
    reason: DenyReason | str,
    message: str,
    **details: Any,
) -> JSONResponse:
    reason_value = reason.value if isinstance(reason, DenyReason) else reason
    status = 503 if reason in INFRASTRUCTURE_REASONS else 403
    recoverable = is_recoverable(reason) if isinstance(reason, DenyReason) else False
    return JSONResponse(
        status_code=status,
        content=deny_body(reason_value, message, recoverable=recoverable, **details),
    )


def not_mapped(path: str) -> JSONResponse:
    """Blocked, not forwarded. An unmapped upstream is a hole in the policy, not a pass."""
    return JSONResponse(
        status_code=403,
        content=deny_body(
            UPSTREAM_NOT_MAPPED,
            f"no upstream mapped for {path!r}; the sidecar forwards only what it is configured to",
        ),
    )


def target_unresolved(path: str) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content=deny_body(
            TARGET_NOT_RESOLVED,
            f"no target/data_class configured for {path!r} and none supplied by the caller; "
            "refusing rather than guessing a data class",
        ),
    )


def unauthorized(message: str) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"error": {"code": "unauthorized", "message": message}},
    )


def unbindable(reason: str, message: str, *, target: str) -> JSONResponse:
    """A privileged call the sidecar cannot bind. Blocked, never forwarded unbound."""
    return JSONResponse(
        status_code=403, content=deny_body(reason, message, recoverable=False, target=target)
    )


def transaction_unavailable(message: str, *, target: str) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content=deny_body(
            TRANSACTION_SERVICE_UNAVAILABLE, message, recoverable=False, target=target
        ),
    )
