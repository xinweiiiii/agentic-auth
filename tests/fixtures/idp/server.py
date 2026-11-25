"""A fake OIDC identity provider for principal binding and MCP client logins.

Serves its JWKS and mints ID tokens for a human principal that name an agent through the
binding claim. ``down`` makes every request fail the way an unreachable provider does, so
enrollment can prove that *unreachable* is a retryable 503 and never a quarantine.

Feature 011 adds what an MCP client's login produces: RFC 8414 and OIDC discovery
documents, access tokens carrying ``azp`` and ``scope``, key rotation, and tokens signed
with an algorithm of the test's choosing (``none`` and ``HS256`` included) so the
validator's refusals can be exercised with real tokens rather than hand-built strings.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

ISSUER = "http://idp.test"
AUDIENCE = "agentic-auth"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass
class FakeIdp:
    key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    kid: str = "idp-k1"
    down: bool = False
    issuer: str = ISSUER
    audience: str = AUDIENCE
    binding_claim: str = "agent"
    # Keys published alongside the current one, so a rotation can keep old tokens valid.
    previous: list[tuple[str, Ed25519PrivateKey]] = field(default_factory=list)
    # Discovery can fail on its own, separately from the JWKS.
    discovery_down: bool = False
    jwks_fetches: int = 0

    def jwks(self) -> dict[str, Any]:
        return {"keys": [_okp_jwk(kid, key) for kid, key in [(self.kid, self.key), *self.previous]]}

    def rotate(self, *, keep_previous: bool = True) -> str:
        """Start signing with a new key. Returns its ``kid``."""
        if keep_previous:
            self.previous.append((self.kid, self.key))
        self.key = Ed25519PrivateKey.generate()
        self.kid = f"idp-k{len(self.previous) + 2}-{uuid4().hex[:6]}"
        return self.kid

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["account.read", "kb.internal", "kb.public"],
        }

    def mint_access_token(
        self,
        *,
        sub: str = "alice",
        aud: str | list[str] | None = None,
        azp: str | None = "desktop-client",
        scope: str | None = None,
        expires_in: int = 300,
        not_before: int | None = None,
        issuer: str | None = None,
        kid: str | None = None,
        alg: str = "EdDSA",
        drop: tuple[str, ...] = (),
        extra: dict[str, Any] | None = None,
    ) -> str:
        """An access token as the IdP would issue it to an MCP client after login.

        ``alg`` other than EdDSA signs with something this IdP never publishes: ``none``
        (unsigned) or ``HS256`` keyed with the public key bytes, the classic confusion
        attack. ``drop`` removes claims after they are built.
        """
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": issuer or self.issuer,
            "sub": sub,
            "aud": aud if aud is not None else self.audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
            "jti": uuid4().hex,
        }
        if not_before is not None:
            claims["nbf"] = int((now + timedelta(seconds=not_before)).timestamp())
        if azp is not None:
            claims["azp"] = azp
        if scope is not None:
            claims["scope"] = scope
        claims.update(extra or {})
        for name in drop:
            claims.pop(name, None)
        headers = {"kid": kid or self.kid}
        if alg == "none":
            return jwt.encode(claims, None, algorithm="none", headers=headers)
        if alg.startswith("HS"):
            public = self.key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            return _hmac_jwt(claims, public, alg, headers)
        return jwt.encode(claims, self._pem(), algorithm="EdDSA", headers=headers)

    def _pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def mint_id_token(
        self,
        *,
        sub: str = "alice",
        agent: str | None,
        aud: str | None = None,
        expires_in: int = 300,
        kid: str | None = None,
    ) -> str:
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": sub,
            "aud": aud or self.audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        }
        if agent is not None:
            claims[self.binding_claim] = agent
        return jwt.encode(claims, self._pem(), algorithm="EdDSA", headers={"kid": kid or self.kid})

    def principal_ref(self, sub: str = "alice") -> str:
        return f"{self.issuer}#{sub}"


def _okp_jwk(kid: str, key: Ed25519PrivateKey) -> dict[str, Any]:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw),
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
    }


def _hmac_jwt(claims: dict[str, Any], secret: bytes, alg: str, headers: dict[str, str]) -> str:
    """Sign with HMAC by hand: PyJWT refuses an asymmetric-looking secret, which is the
    very protection a confused verifier would lack."""
    import hashlib
    import hmac
    import json

    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    head = _b64url(json.dumps({"alg": alg, "typ": "JWT", **headers}).encode())
    body = _b64url(json.dumps(claims).encode())
    sig = hmac.new(secret, f"{head}.{body}".encode(), digest).digest()
    return f"{head}.{body}.{_b64url(sig)}"


def build_idp(idp: FakeIdp | None = None) -> tuple[Starlette, FakeIdp]:
    state = idp or FakeIdp()

    async def jwks(_: Request) -> JSONResponse:
        state.jwks_fetches += 1
        if state.down:
            return JSONResponse({"error": "unavailable"}, status_code=503)
        return JSONResponse(state.jwks())

    async def discovery(_: Request) -> JSONResponse:
        if state.down or state.discovery_down:
            return JSONResponse({"error": "unavailable"}, status_code=503)
        return JSONResponse(state.discovery())

    return (
        Starlette(
            routes=[
                Route("/.well-known/jwks.json", jwks),
                Route("/.well-known/oauth-authorization-server", discovery),
                Route("/.well-known/openid-configuration", discovery),
            ]
        ),
        state,
    )
