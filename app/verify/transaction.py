"""Verifying a transaction token at a resource.

Seven steps, every one mandatory, in the contract's order. Steps 1–5 read the token; step 6
recomputes the binding hash from the params the resource actually parsed; step 7 claims the
``jti`` in the replay store — last, so a token that fails any earlier step is never marked
used, and a store that cannot answer refuses.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import jwt

from app.verify.canonical import CanonicalizationError, binding_hash
from app.verify.grants import (
    ALGORITHM,
    DEFAULT_LEEWAY,
    VerificationFailed,
    VerifiedGrant,
    key_from_jwks,
)
from app.verify.replay import ReplayStore, ReplayStoreUnavailable, txn_key

TRANSACTION_TYP = "txn+jwt"

# reason -> metrics cause label
REJECTION_CAUSE = {
    "TXN_TARGET_MISMATCH": "target_mismatch",
    "TXN_PARAMS_MISMATCH": "params_mismatch",
    "TXN_GRANT_MISMATCH": "params_mismatch",
    "TXN_REPLAY": "replay",
    "TXN_EXPIRED": "expired",
    "TXN_INVALID": "malformed",
    "TXN_UNSUPPORTED_BINDING": "malformed",
    "TXN_MISSING": "malformed",
    "REPLAY_STORE_UNAVAILABLE": "store_unavailable",
}


@dataclass(frozen=True)
class VerifiedTransaction:
    raw: str
    jti: str
    aud: str
    session_id: str
    action_id: str
    hop: int
    params_hash: str
    binding: list[str] | None
    expires_at: datetime


def verify_transaction(
    token: str | None,
    *,
    target: str,
    params: Mapping[str, Any],
    grant: VerifiedGrant,
    issuer_jwks: Mapping[str, Any],
    replay: ReplayStore,
    issuer: str = "agentic-auth",
    leeway_seconds: int = DEFAULT_LEEWAY,
) -> VerifiedTransaction:
    # 1. header
    if not token:
        raise VerificationFailed("TXN_MISSING", "no Txn-Token")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise VerificationFailed("TXN_INVALID", f"malformed header: {exc}") from exc
    if header.get("typ") != TRANSACTION_TYP:
        raise VerificationFailed(
            "TXN_INVALID", f"typ {header.get('typ')!r} is not {TRANSACTION_TYP}"
        )
    if header.get("alg") != ALGORITHM:
        raise VerificationFailed("TXN_INVALID", f"unexpected alg {header.get('alg')!r}")
    key = key_from_jwks(issuer_jwks, header.get("kid"))
    if key is None:
        raise VerificationFailed("TXN_INVALID", f"unknown issuer kid {header.get('kid')!r}")

    # 2. signature, iss, exp, required claims; 3. aud == target
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[ALGORITHM],
            issuer=issuer,
            audience=target,
            leeway=leeway_seconds,
            options={"require": ["exp", "iat", "jti", "sub", "aud", "iss"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise VerificationFailed("TXN_EXPIRED", str(exc)) from exc
    except jwt.InvalidAudienceError as exc:
        raise VerificationFailed("TXN_TARGET_MISMATCH", str(exc)) from exc
    except jwt.PyJWTError as exc:
        raise VerificationFailed("TXN_INVALID", str(exc)) from exc
    for claim in ("txn", "session_id", "action_id", "hop", "azd"):
        if claim not in claims:
            raise VerificationFailed("TXN_INVALID", f"missing claim {claim!r}")
    if claims["txn"] != claims["jti"]:
        raise VerificationFailed("TXN_INVALID", "txn must equal jti")

    # 4. agrees with the grant it is layered on
    if (
        str(claims["session_id"]) != grant.session_id
        or str(claims["action_id"]) != (grant.action_id or "")
        or int(claims["hop"]) != grant.hop
        or claims["sub"] != grant.sub
    ):
        raise VerificationFailed("TXN_GRANT_MISMATCH", "transaction token is for another grant")

    # 5. binding algorithm
    azd = claims["azd"]
    if not isinstance(azd, Mapping) or not isinstance(azd.get("params_hash"), str):
        raise VerificationFailed("TXN_INVALID", "azd is malformed")
    if azd.get("hash_alg") != "sha-256" or azd.get("canon") != "rfc8785":
        raise VerificationFailed("TXN_UNSUPPORTED_BINDING", "unsupported hash_alg or canon")
    if azd.get("target") != target:
        raise VerificationFailed("TXN_TARGET_MISMATCH", "azd.target disagrees with the call")
    binding = azd.get("binding")
    if binding is not None and not (
        isinstance(binding, list) and all(isinstance(b, str) for b in binding)
    ):
        raise VerificationFailed("TXN_INVALID", "azd.binding is malformed")

    # 6. recompute the binding hash from the params THIS resource parsed
    try:
        recomputed = binding_hash(target, params, binding)
    except CanonicalizationError as exc:
        raise VerificationFailed(
            "TXN_PARAMS_MISMATCH", f"params not canonicalizable: {exc}"
        ) from exc
    if recomputed != azd["params_hash"]:
        raise VerificationFailed("TXN_PARAMS_MISMATCH", "binding parameters differ")

    # 7. single use — last, and fail closed
    expires_at = datetime.fromtimestamp(claims["exp"], tz=UTC)
    ttl = int((expires_at - datetime.now(UTC)).total_seconds()) + leeway_seconds + 1
    try:
        first = replay.claim(txn_key(claims["jti"]), ttl)
    except ReplayStoreUnavailable as exc:
        raise VerificationFailed("REPLAY_STORE_UNAVAILABLE", str(exc)) from exc
    if not first:
        raise VerificationFailed("TXN_REPLAY", "transaction token already used")

    return VerifiedTransaction(
        raw=token,
        jti=claims["jti"],
        aud=target,
        session_id=str(claims["session_id"]),
        action_id=str(claims["action_id"]),
        hop=int(claims["hop"]),
        params_hash=azd["params_hash"],
        binding=list(binding) if binding is not None else None,
        expires_at=expires_at,
    )


__all__ = ["REJECTION_CAUSE", "TRANSACTION_TYP", "VerifiedTransaction", "verify_transaction"]
