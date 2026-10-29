"""``admit()`` — the one place identity and authorization are combined, as a conjunction.

    grant  AND  (identity, when required)  AND  (transaction, when privileged)

There is no path here that admits on identity alone, and no path that admits a privileged
call without its transaction token. Each refusal names exactly the step that failed, so a
resource can answer precisely without leaking anything else (docs/verifier-library.md).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.verify.anchors import AnchorStore, JwksSource
from app.verify.grants import VerificationFailed, VerifiedGrant, verify_grant
from app.verify.identity import VerifiedIdentity, verify_identity
from app.verify.replay import ReplayStore
from app.verify.transaction import REJECTION_CAUSE, VerifiedTransaction, verify_transaction

# `mutmut run` leaves 1 equivalent mutant here: the default `leeway_seconds` 60 -> 61. It moves
# a clock-skew boundary by one second, which cannot be observed deterministically without an
# injectable clock (PyJWT reads the wall clock). Every other mutant is killed, including that
# `issuer` and `leeway_seconds` actually reach the grant, identity and transaction checks
# (tests/unit/test_verify_admit.py: custom issuer, per-step leeway).

AUTHORIZATION = "authorization"
AGENT_IDENTITY = "agent-identity"
TXN_TOKEN = "txn-token"


@dataclass(frozen=True)
class Admission:
    ok: bool
    reason: str | None = None
    detail: str | None = None
    grant: VerifiedGrant | None = None
    identity: VerifiedIdentity | None = None
    transaction: VerifiedTransaction | None = None

    @property
    def details(self) -> dict[str, Any]:
        return {"reason": self.reason, "detail": self.detail}


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def _bearer(headers: Mapping[str, str]) -> str | None:
    raw = _header(headers, AUTHORIZATION)
    if not raw or not raw.startswith("Bearer "):
        return None
    return raw.removeprefix("Bearer ").strip() or None


def admit(
    headers: Mapping[str, str],
    *,
    target: str,
    params: Mapping[str, Any] | None,
    privileged: bool,
    issuer_jwks: JwksSource,
    anchors: AnchorStore,
    replay: ReplayStore,
    identity_required: bool,
    freshness_seconds: int,
    issuer: str = "agentic-auth",
    leeway_seconds: int = 60,
    metrics: Any = None,
) -> Admission:
    """Decide admission from the request headers alone. No I/O beyond the replay claim."""
    jwks = issuer_jwks.jwks()
    try:
        if jwks is None:
            raise VerificationFailed("GRANT_INVALID", "issuer keys were never bootstrapped")

        # 1. the grant: what this call is allowed to be
        grant = verify_grant(
            _bearer(headers),
            issuer_jwks=jwks,
            audience=target,
            issuer=issuer,
            leeway_seconds=leeway_seconds,
        )

        # 2. the identity: who is presenting it (never sufficient on its own)
        identity: VerifiedIdentity | None = None
        if identity_required:
            identity = verify_identity(
                _header(headers, AGENT_IDENTITY),
                anchors=anchors,
                target=target,
                grant=grant,
                freshness_seconds=freshness_seconds,
                leeway_seconds=leeway_seconds,
            )

        # 3. the transaction: this exact call, once
        transaction: VerifiedTransaction | None = None
        if privileged:
            if params is None:
                raise VerificationFailed("TXN_PARAMS_MISMATCH", "privileged call has no params")
            transaction = verify_transaction(
                _header(headers, TXN_TOKEN),
                target=target,
                params=params,
                grant=grant,
                issuer_jwks=jwks,
                replay=replay,
                issuer=issuer,
                leeway_seconds=leeway_seconds,
            )
    except VerificationFailed as failed:
        if metrics is not None:
            metrics.admissions.labels(result=failed.reason).inc()
            cause = REJECTION_CAUSE.get(failed.reason)
            if cause is not None:
                metrics.transaction_rejections.labels(cause=cause).inc()
        return Admission(ok=False, reason=failed.reason, detail=failed.detail)

    if metrics is not None:
        metrics.admissions.labels(result="admitted").inc()
    return Admission(ok=True, grant=grant, identity=identity, transaction=transaction)


__all__ = ["Admission", "admit"]
