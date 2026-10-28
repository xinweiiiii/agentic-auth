"""Verifying a hop token at a resource, against the control plane's JWKS.

The verification order is the one in ``contracts/hop-token.md``, re-implemented here so a
resource server needs only ``pyjwt[crypto]`` and a JWKS dict — never the control plane's
own modules. Every step is mandatory; any failure is a :class:`VerificationFailed` naming
its cause.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import jwt

ALGORITHM = "EdDSA"
AGENT_PREFIX = "agent://"
DEFAULT_LEEWAY = 60


class VerificationFailed(Exception):
    """A resource-side check failed. ``reason`` is one of the contract's reason codes."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def key_from_jwks(jwks: Mapping[str, Any], kid: str | None) -> Any:
    """The public key named by ``kid`` in a JWKS dict, or ``None``."""
    for entry in jwks.get("keys", []):
        if entry.get("kid") == kid:
            if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
                return None
            return jwt.PyJWK(dict(entry), algorithm=ALGORITHM).key
    return None


def sha256_b64url(text: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()).rstrip(b"=").decode()


def _act_chain(act: Any, sub: str) -> tuple[list[str], int]:
    """``([human, delegate..., current actor], depth)``; raises on a malformed chain."""
    actors: list[str] = []
    node = act
    depth = 0
    while node is not None:
        if not isinstance(node, dict) or not isinstance(node.get("sub"), str) or not node["sub"]:
            raise VerificationFailed("GRANT_INVALID", "malformed act chain")
        if set(node) - {"sub", "act"}:
            raise VerificationFailed("GRANT_INVALID", "unexpected keys in act link")
        actors.append(node["sub"])
        node = node.get("act")
        depth += 1
        if depth > 32:
            raise VerificationFailed("GRANT_INVALID", "act chain too deep")
    return [sub, *reversed(actors)], depth


@dataclass(frozen=True)
class VerifiedGrant:
    raw: str
    sub: str
    aud: str
    scope: str
    session_id: str
    action_id: str | None
    hop: int
    jti: str
    act: dict[str, Any] | None
    act_chain: list[str]
    taint: str | None
    expires_at: datetime

    @property
    def holder_agent(self) -> str | None:
        """The agent acting on this grant: the outermost ``act.sub``. ``None`` for a root
        grant, which is never valid at a resource."""
        if self.act is None:
            return None
        return str(self.act["sub"]).removeprefix(AGENT_PREFIX)


def verify_grant(
    token: str | None,
    *,
    issuer_jwks: Mapping[str, Any],
    audience: str,
    issuer: str = "agentic-auth",
    leeway_seconds: int = DEFAULT_LEEWAY,
) -> VerifiedGrant:
    if not token:
        raise VerificationFailed("GRANT_MISSING", "no bearer token")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise VerificationFailed("GRANT_INVALID", f"malformed header: {exc}") from exc
    if header.get("alg") != ALGORITHM:
        raise VerificationFailed("GRANT_INVALID", f"unexpected alg {header.get('alg')!r}")
    if header.get("typ") not in (None, "JWT"):
        raise VerificationFailed("GRANT_INVALID", f"unexpected typ {header.get('typ')!r}")
    key = key_from_jwks(issuer_jwks, header.get("kid"))
    if key is None:
        raise VerificationFailed("GRANT_INVALID", f"unknown issuer kid {header.get('kid')!r}")
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[ALGORITHM],
            issuer=issuer,
            audience=audience,
            leeway=leeway_seconds,
            options={"require": ["exp", "iat", "jti", "sub", "aud", "iss"]},
        )
    except jwt.InvalidAudienceError as exc:
        raise VerificationFailed("GRANT_TARGET_MISMATCH", str(exc)) from exc
    except jwt.ExpiredSignatureError as exc:
        raise VerificationFailed("GRANT_EXPIRED", str(exc)) from exc
    except jwt.PyJWTError as exc:
        raise VerificationFailed("GRANT_INVALID", str(exc)) from exc

    for claim in ("scope", "session_id", "policy_version", "hop"):
        if claim not in claims:
            raise VerificationFailed("GRANT_INVALID", f"missing claim {claim!r}")
    act = claims.get("act")
    chain, depth = _act_chain(act, claims["sub"])
    if claims["hop"] != depth + 1:
        raise VerificationFailed("GRANT_INVALID", "hop disagrees with act depth")
    if act is None:
        # The root grant names a scope, not a resource; it is never presentable here.
        raise VerificationFailed("GRANT_INVALID", "a root grant is not valid at a resource")
    taint = claims.get("taint")
    if taint is not None and taint not in ("trusted_internal", "untrusted_external"):
        raise VerificationFailed("GRANT_INVALID", f"unknown taint {taint!r}")
    action_id = claims.get("action_id")
    return VerifiedGrant(
        raw=token,
        sub=claims["sub"],
        aud=claims["aud"] if isinstance(claims["aud"], str) else claims["aud"][0],
        scope=claims["scope"],
        session_id=str(claims["session_id"]),
        action_id=str(action_id) if action_id is not None else None,
        hop=int(claims["hop"]),
        jti=claims["jti"],
        act=act,
        act_chain=chain,
        taint=taint,
        expires_at=datetime.fromtimestamp(claims["exp"], tz=UTC),
    )


__all__ = ["VerificationFailed", "VerifiedGrant", "key_from_jwks", "sha256_b64url", "verify_grant"]
