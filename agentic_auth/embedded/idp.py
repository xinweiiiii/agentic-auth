"""A stand-in for the human identity provider enrollment binds an agent to.

Enrollment requires an accountable principal: an ID token from the organisation's IdP naming
the agent. An embedded instance has no IdP, so it carries this one. Anything it binds is a
*test* principal, and says so: the enrollment's principal assertion carries
``principal_source: embedded-test``, so an exported record can never pass for a real binding.

0.4.0 (feature 011): it also mints the access tokens an MCP client's login would produce, with
``azp`` and ``scope``, and serves a discovery document, so verified consent, client mapping
and a connector proxy in front of an embedded instance work with no infrastructure. Sessions
it roots are recorded as ``embedded-test``.
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
#: The client id an embedded login reports in ``azp`` unless a test names another.
DEFAULT_CLIENT_ID = "embedded-client"


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

    def mint(self, *, sub: str, agent: str | None = None, expires_in: int = 300) -> str:
        """An ID token for ``sub``. With ``agent``, it names that agent in the binding claim
        (enrollment); without, it is the person's own credential (approving a step-up)."""
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "sub": sub,
            "aud": AUDIENCE,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
            "jti": str(uuid.uuid4()),
            "principal_source": PRINCIPAL_SOURCE,
        }
        if agent is not None:
            claims[BINDING_CLAIM] = f"agent://{agent}"
        pem = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": self.kid})

    def mint_access_token(
        self,
        *,
        sub: str,
        audience: str | list[str] = AUDIENCE,
        client_id: str | None = DEFAULT_CLIENT_ID,
        scope: str | None = None,
        expires_in: int = 300,
    ) -> str:
        """An access token as an MCP client receives it after the user signs in."""
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "sub": sub,
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
            "jti": str(uuid.uuid4()),
            "principal_source": PRINCIPAL_SOURCE,
        }
        if client_id is not None:
            claims["azp"] = client_id
        if scope is not None:
            claims["scope"] = scope
        return jwt.encode(claims, self._pem(), algorithm="EdDSA", headers={"kid": self.kid})

    def _pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def discovery(self) -> dict[str, Any]:
        """RFC 8414 metadata. No authorization endpoint: nothing logs in here."""
        return {
            "issuer": ISSUER,
            "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
            "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"],
        }

    def app(self) -> Starlette:
        async def jwks(_: Request) -> JSONResponse:
            return JSONResponse(self.jwks())

        async def discovery(_: Request) -> JSONResponse:
            return JSONResponse(self.discovery())

        return Starlette(
            routes=[
                Route("/.well-known/jwks.json", jwks),
                Route("/.well-known/oauth-authorization-server", discovery),
                Route("/.well-known/openid-configuration", discovery),
            ]
        )
