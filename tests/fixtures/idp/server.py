"""A fake OIDC identity provider for principal binding.

Serves its JWKS and mints ID tokens for a human principal that name an agent through the
binding claim. ``down`` makes every request fail the way an unreachable provider does, so
enrollment can prove that *unreachable* is a retryable 503 and never a quarantine.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

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

    def jwks(self) -> dict[str, Any]:
        raw = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": _b64url(raw),
                    "kid": self.kid,
                    "alg": "EdDSA",
                    "use": "sig",
                }
            ]
        }

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
        pem = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": kid or self.kid})

    def principal_ref(self, sub: str = "alice") -> str:
        return f"{self.issuer}#{sub}"


def build_idp(idp: FakeIdp | None = None) -> tuple[Starlette, FakeIdp]:
    state = idp or FakeIdp()

    async def jwks(_: Request) -> JSONResponse:
        if state.down:
            return JSONResponse({"error": "unavailable"}, status_code=503)
        return JSONResponse(state.jwks())

    return Starlette(routes=[Route("/.well-known/jwks.json", jwks)]), state
