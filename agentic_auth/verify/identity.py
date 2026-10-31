"""Verifying the ``Agent-Identity`` assertion at a resource.

The assertion is a JWT the agent signed with a key in its CURRENT pinned trust anchor. It
proves who is calling and is bound to the exact grant string through ``grant_hash``, so an
assertion minted for one call cannot be paired with another grant. It authorizes nothing:
``admit()`` still requires the grant.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import jwt

from agentic_auth.verify.anchors import AnchorStore
from agentic_auth.verify.grants import (
    AGENT_PREFIX,
    ALGORITHM,
    DEFAULT_LEEWAY,
    VerificationFailed,
    VerifiedGrant,
    key_from_jwks,
    sha256_b64url,
)

MAX_LIFETIME = 60


@dataclass(frozen=True)
class VerifiedIdentity:
    raw: str
    agent: str
    trust_anchor_version: int | None
    jti: str
    expires_at: datetime


def verify_identity(
    assertion: str | None,
    *,
    anchors: AnchorStore,
    target: str,
    grant: VerifiedGrant,
    freshness_seconds: int,
    leeway_seconds: int = DEFAULT_LEEWAY,
    now: datetime | None = None,
) -> VerifiedIdentity:
    if not assertion:
        raise VerificationFailed("IDENTITY_MISSING", "no Agent-Identity header")

    as_of = anchors.as_of()
    current = now or datetime.now(UTC)
    if as_of is None:
        raise VerificationFailed("IDENTITY_STALE", "anchor view was never bootstrapped")
    if (current - as_of).total_seconds() > freshness_seconds:
        raise VerificationFailed(
            "IDENTITY_STALE", f"anchor view is older than {freshness_seconds}s"
        )

    holder = grant.holder_agent
    if holder is None:
        raise VerificationFailed("GRANT_INVALID", "grant names no acting agent")
    anchor = anchors.current(holder)
    if anchor is None or anchor.status in ("registered", "quarantined"):
        raise VerificationFailed("IDENTITY_UNKNOWN_AGENT", f"no trust anchor for {holder!r}")
    if anchor.revoked:
        raise VerificationFailed("IDENTITY_REVOKED", f"{holder!r} is revoked")
    if anchor.jwks is None:
        raise VerificationFailed("IDENTITY_UNKNOWN_AGENT", f"no keys pinned for {holder!r}")

    try:
        header = jwt.get_unverified_header(assertion)
    except jwt.PyJWTError as exc:
        raise VerificationFailed("IDENTITY_INVALID", f"malformed header: {exc}") from exc
    if header.get("alg") != ALGORITHM:
        raise VerificationFailed("IDENTITY_INVALID", f"unexpected alg {header.get('alg')!r}")
    key = key_from_jwks(anchor.jwks, header.get("kid"))
    if key is None:
        raise VerificationFailed(
            "IDENTITY_INVALID", f"kid {header.get('kid')!r} is not in the pinned anchor"
        )
    try:
        claims = jwt.decode(
            assertion,
            key,
            algorithms=[ALGORITHM],
            audience=target,
            leeway=leeway_seconds,
            options={"require": ["exp", "iat", "jti", "sub", "aud", "grant_hash"]},
        )
    except jwt.PyJWTError as exc:
        raise VerificationFailed("IDENTITY_INVALID", str(exc)) from exc

    if claims.get("sub") != f"{AGENT_PREFIX}{holder}" or claims.get("iss") != claims.get("sub"):
        raise VerificationFailed("IDENTITY_INVALID", "assertion is for another agent")
    if int(claims["exp"]) - int(claims["iat"]) > MAX_LIFETIME:
        raise VerificationFailed("IDENTITY_INVALID", "assertion lifetime exceeds 60s")
    if claims["grant_hash"] != sha256_b64url(grant.raw):
        raise VerificationFailed("IDENTITY_INVALID", "assertion is bound to a different grant")

    return VerifiedIdentity(
        raw=assertion,
        agent=holder,
        trust_anchor_version=anchor.trust_anchor_version,
        jti=claims["jti"],
        expires_at=datetime.fromtimestamp(claims["exp"], tz=UTC),
    )


__all__ = ["MAX_LIFETIME", "VerifiedIdentity", "verify_identity"]
