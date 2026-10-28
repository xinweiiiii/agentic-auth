"""Issuer keypair and JWK Set.

Ed25519: ~64-byte signatures that verify in tens of microseconds, which matters because
verification happens on every hop inside the 15 ms per-hop budget.

``kid`` is present from day one so that key rotation — Phase 4's problem — never becomes
a breaking change.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.config import get_settings

logger = logging.getLogger(__name__)

ALGORITHM = "EdDSA"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _raw_public_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _thumbprint(public_key: Ed25519PublicKey) -> str:
    """A stable kid derived from the key itself, so it survives a restart."""
    return _b64url(hashlib.sha256(_raw_public_bytes(public_key)).digest())[:16]


@dataclass(frozen=True)
class IssuerKey:
    private_key: Ed25519PrivateKey
    kid: str

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def public_jwk(self) -> dict[str, Any]:
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(_raw_public_bytes(self.public_key)),
            "kid": self.kid,
            "alg": ALGORITHM,
            "use": "sig",
        }

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def load_or_generate(pem: str = "", kid: str = "") -> IssuerKey:
    """Load an Ed25519 private key from PEM, or generate an ephemeral one.

    An ephemeral key is a development convenience: it is logged as ephemeral, and every
    token it signed stops verifying when the process restarts. That is loud by design —
    a silently rotating issuer key is far worse than a noisy one.
    """
    if pem.strip():
        loaded = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError(f"issuer key must be Ed25519, got {type(loaded).__name__}")
        private_key = loaded
    else:
        private_key = Ed25519PrivateKey.generate()
        logger.warning(
            "no AGENTIC_AUTH_ISSUER_PRIVATE_KEY configured — generated an EPHEMERAL "
            "issuer key. Tokens will not verify after a restart. Development only."
        )
    return IssuerKey(private_key=private_key, kid=kid or _thumbprint(private_key.public_key()))


@lru_cache
def get_issuer_key() -> IssuerKey:
    settings = get_settings()
    return load_or_generate(settings.issuer_private_key, settings.issuer_kid)


def jwks() -> dict[str, Any]:
    return {"keys": [get_issuer_key().public_jwk()]}
