"""Agent identity fixtures: Ed25519 keypairs, identity documents, and the small signed
tokens the identity contract defines.

Everything here signs with a key the TEST holds. ``bad=True`` variants sign with a key
that is NOT in the document, which is the forgery every verifier must refuse.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ISSUER = "agentic-auth"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass(frozen=True)
class AgentKeypair:
    name: str
    private_key: Ed25519PrivateKey
    kid: str

    @property
    def sub(self) -> str:
        return f"agent://{self.name}"

    def public_raw(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def jwk(self) -> dict[str, Any]:
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(self.public_raw()),
            "kid": self.kid,
            "alg": "EdDSA",
            "use": "sig",
        }

    def thumbprint(self) -> str:
        return _b64url(hashlib.sha256(self.public_raw()).digest())

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def sign(self, claims: dict[str, Any], *, kid: str | None = None) -> str:
        return jwt.encode(
            claims, self.private_pem(), algorithm="EdDSA", headers={"kid": kid or self.kid}
        )


def agent_keypair(name: str, *, kid: str | None = None) -> AgentKeypair:
    return AgentKeypair(
        name=name, private_key=Ed25519PrivateKey.generate(), kid=kid or f"{name}-k1"
    )


def thumbprint(jwk: dict[str, Any]) -> str:
    raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    return _b64url(hashlib.sha256(raw).digest())


def identity_document(
    key: AgentKeypair,
    *,
    principal_assertion: str | None = None,
    extra_keys: tuple[AgentKeypair, ...] = (),
    claims: dict[str, Any] | None = None,
    sub: str | None = None,
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "sub": sub or key.sub,
        "jwks": {"keys": [key.jwk(), *(k.jwk() for k in extra_keys)]},
        "claims": claims or {"runtime": "test"},
    }
    if principal_assertion is not None:
        doc["principal_assertion"] = principal_assertion
    return doc


def _window(seconds: int) -> tuple[int, int]:
    now = datetime.now(UTC)
    return int(now.timestamp()), int((now + timedelta(seconds=seconds)).timestamp())


def sign_challenge(
    key: AgentKeypair,
    nonce: str,
    *,
    aud: str = ISSUER,
    bad: bool = False,
    sub: str | None = None,
    lifetime: int = 60,
) -> str:
    iat, exp = _window(lifetime)
    signer = agent_keypair(key.name, kid=key.kid) if bad else key  # wrong key, same kid
    return signer.sign(
        {
            "iss": key.sub,
            "sub": sub or key.sub,
            "aud": aud,
            "nonce": nonce,
            "iat": iat,
            "exp": exp,
        }
    )


def st_hash(subject_token: str) -> str:
    return _b64url(hashlib.sha256(subject_token.encode()).digest())


def actor_token(
    key: AgentKeypair,
    subject_token: str,
    *,
    aud: str = ISSUER,
    bad_hash: bool = False,
    bad: bool = False,
    sub: str | None = None,
    lifetime: int = 60,
) -> str:
    iat, exp = _window(lifetime)
    signer = agent_keypair(key.name, kid=key.kid) if bad else key
    return signer.sign(
        {
            "iss": key.sub,
            "sub": sub or key.sub,
            "aud": aud,
            "iat": iat,
            "exp": exp,
            "jti": str(uuid.uuid4()),
            "st_hash": st_hash("not-the-token" if bad_hash else subject_token),
        }
    )


def identity_assertion(
    key: AgentKeypair,
    grant: str,
    audience: str,
    *,
    bad: bool = False,
    bad_hash: bool = False,
    sub: str | None = None,
    lifetime: int = 60,
) -> str:
    iat, exp = _window(lifetime)
    signer = agent_keypair(key.name, kid=key.kid) if bad else key
    return signer.sign(
        {
            "iss": key.sub,
            "sub": sub or key.sub,
            "aud": audience,
            "iat": iat,
            "exp": exp,
            "jti": str(uuid.uuid4()),
            "grant_hash": st_hash("not-the-grant" if bad_hash else grant),
        }
    )
