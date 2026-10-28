"""Domain exceptions raised by the service layer."""

from __future__ import annotations

from typing import Any


class DomainError(Exception):
    """Base for errors that map to a specific HTTP response."""

    status_code: int = 400
    code: str = "domain_error"

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class NotFoundError(DomainError):
    status_code = 404
    code = "not_found"


class QueryValidationError(DomainError):
    """A query string that cannot be honoured. Rendered exactly like request validation —
    ``422 validation_error`` with ``details.fields[].loc`` naming the parameter — so a
    client never has to tell the two apart."""

    status_code = 422
    code = "validation_error"

    def __init__(self, message: str, fields: list[dict[str, Any]]) -> None:
        super().__init__(message, {"fields": fields})


class UnauthorizedError(DomainError):
    status_code = 401
    code = "unauthorized"


class ReconciliationRejected(DomainError):
    status_code = 422
    code = "reconciliation_rejected"


class NeedsReviewWithoutOverride(DomainError):
    status_code = 409
    code = "needs_review"


class DagCycleError(DomainError):
    status_code = 422
    code = "dag_cycle"


class ManifestValidationError(DomainError):
    status_code = 422
    code = "validation_error"


class SessionExpired(DomainError):
    status_code = 401
    code = "session_expired"


class PolicyRecompileRequired(DomainError):
    """The scope's compiled policy predates the runtime plane's DAG schema.

    Never guessed past: an unenforceable policy must not silently become an allow.
    Resubmitting the manifest compiles a new version (append-only; nothing mutates).
    """

    status_code = 409
    code = "policy_recompile_required"


class PolicyDenied(DomainError):
    """A hop was refused by policy. ``details`` carries reason, recoverability,
    target and hop so the caller can act rather than guess."""

    status_code = 403
    code = "policy_denied"


class PolicyUnavailable(DomainError):
    """A decision could not be made. Always a deny — never a fallthrough."""

    status_code = 503
    code = "pdp_unavailable"


class TokenServiceUnavailable(DomainError):
    """Narrowed authority could not be issued after an allow. The presented token is
    never forwarded as a fallback."""

    status_code = 503
    code = "token_service_unavailable"


# -- Phase 4 -------------------------------------------------------------------------


class TransactionAlreadyMinted(DomainError):
    """One transaction token per recorded decision; this decision already has one."""

    status_code = 409
    code = "transaction_already_minted"


class TransactionValidationError(QueryValidationError):
    """A mint request that cannot be honoured: non-privileged target, oversized or
    non-canonicalizable params. Rendered as ``422 validation_error``."""


class KeyRevoked(DomainError):
    """A presented key belongs to a revoked trust anchor, or the agent is revoked."""

    status_code = 409
    code = "key_revoked"


class NotEnrolled(DomainError):
    """The agent has no trust anchor to act on."""

    status_code = 409
    code = "not_enrolled"


class IdpUnavailable(DomainError):
    """The principal identity provider could not be reached. Retryable; status unchanged."""

    status_code = 503
    code = "idp_unavailable"
