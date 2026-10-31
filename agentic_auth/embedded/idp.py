"""A stand-in for the human identity provider enrollment binds an agent to.

Enrollment requires an accountable principal: an ID token from the organisation's IdP naming
the agent. An embedded instance has no IdP, so it carries this one. Anything it binds is a
*test* principal, and says so: the enrollment's principal assertion carries
``principal_source: embedded-test``, so an exported record can never pass for a real binding.
"""

from __future__ import annotations

import base64
import uuid
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

HOST = "idp.embedded.invalid"
ISSUER = f"https://{HOST}"
AUDIENCE = "agentic-auth"
BINDING_CLAIM = "agent"
PRINCIPAL_SOURCE = "embedded-test"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass
class TestIdp:
    __test__ = False  # not a pytest class, whatever its name

    key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    kid: str = "embedded-idp-1"

    def jwks(self) -> dict[str, Any]:
        raw = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {
            "keys": [
                {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw), "kid": self.kid}
                | {"alg": "EdDSA", "use": "sig"}
            ]
        }

    def mint(self, *, agent: str, sub: str, expires_in: int = 300) -> str:
        """An ID token for ``sub`` naming ``agent`` in the binding claim."""
        now = datetime.now(UTC)
        claims = {
            "iss": ISSUER,
            "sub": sub,
            "aud": AUDIENCE,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
            "jti": str(uuid.uuid4()),
            BINDING_CLAIM: f"agent://{agent}",
            "principal_source": PRINCIPAL_SOURCE,
        }
        pem = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": self.kid})

    def app(self) -> Starlette:
        async def jwks(_: Request) -> JSONResponse:
            return JSONResponse(self.jwks())

        return Starlette(routes=[Route("/.well-known/jwks.json", jwks)])
