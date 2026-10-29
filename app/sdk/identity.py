"""An agent's identity key and the small tokens it signs.

``AgentKey`` holds an Ed25519 private key. It signs exactly three things: the enrollment
challenge, the exchange ``actor_token``, and the resource-side ``Agent-Identity`` assertion.
It never authorizes anything — identity and authorization stay separate artifacts.

The private key never appears in ``repr``, logs, or any document this module produces.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ALGORITHM = "EdDSA"
ISSUER = "agentic-auth"
AGENT_PREFIX = "agent://"
TOKEN_LIFETIME_SECONDS = 60
CHALLENGE_LIFETIME_SECONDS = 120


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sha256_b64url(text: str) -> str:
    return _b64url(hashlib.sha256(text.encode()).digest())


def thumbprint_of_jwk(jwk: dict[str, Any]) -> str:
    """SHA-256 of the raw 32-byte public key, base64url. The identity of a KEY, chosen by
    nobody — unlike ``kid``, which the agent picks."""
    raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    return _b64url(hashlib.sha256(raw).digest())


class AgentKey:
    def __init__(self, private_key: Ed25519PrivateKey, *, kid: str | None = None) -> None:
        self._private = private_key
        self._kid = kid or self.thumbprint()[:16]

    # -- construction -----------------------------------------------------------

    @classmethod
    def generate(cls, *, kid: str | None = None) -> AgentKey:
        return cls(Ed25519PrivateKey.generate(), kid=kid)

    @classmethod
    def load(cls, source: str | Path, *, kid: str | None = None) -> AgentKey:
        """From a PKCS8 PEM path or PEM text.

        A PEM carries no ``kid``. Leave ``kid`` unset at ``generate()`` and ``load()`` and the
        key names itself by a thumbprint prefix, so a key saved and reloaded keeps the ``kid``
        it enrolled with. Pass the same explicit ``kid`` to both calls otherwise.
        """
        text = source if isinstance(source, str) and "BEGIN" in source else Path(source).read_text()
        loaded = serialization.load_pem_private_key(text.encode(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError(f"agent key must be Ed25519, got {type(loaded).__name__}")
        return cls(loaded, kid=kid)

    def save(self, path: str | Path) -> None:
        Path(path).write_bytes(self._private_pem())
        Path(path).chmod(0o600)

    def _private_pem(self) -> bytes:
        return self._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    # -- public material ----------------------------------------------------------

    @property
    def kid(self) -> str:
        return self._kid

    def public_raw(self) -> bytes:
        return self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def thumbprint(self) -> str:
        return _b64url(hashlib.sha256(self.public_raw()).digest())

    def jwk(self) -> dict[str, Any]:
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(self.public_raw()),
            "kid": self._kid,
            "alg": ALGORITHM,
            "use": "sig",
        }

    def identity_document(
        self,
        agent: str,
        *,
        claims: dict[str, Any] | None = None,
        principal_assertion: str | None = None,
    ) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "sub": f"{AGENT_PREFIX}{agent}",
            "jwks": {"keys": [self.jwk()]},
            "claims": claims or {},
        }
        if principal_assertion is not None:
            doc["principal_assertion"] = principal_assertion
        return doc

    # -- signing ------------------------------------------------------------------

    def _sign(self, claims: dict[str, Any], *, lifetime: int) -> str:
        now = datetime.now(UTC)
        payload = {
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=lifetime)).timestamp()),
            "jti": str(uuid.uuid4()),
            **claims,
        }
        return jwt.encode(
            payload, self._private_pem(), algorithm=ALGORITHM, headers={"kid": self._kid}
        )

    def sign_challenge(self, agent: str, nonce: str, *, aud: str = ISSUER) -> str:
        sub = f"{AGENT_PREFIX}{agent}"
        return self._sign(
            {"iss": sub, "sub": sub, "aud": aud, "nonce": nonce},
            lifetime=CHALLENGE_LIFETIME_SECONDS,
        )

    def actor_token(self, agent: str, subject_token: str, *, aud: str = ISSUER) -> str:
        """RFC 8693 ``actor_token``: proof of possession bound to the exact subject token."""
        sub = f"{AGENT_PREFIX}{agent}"
        return self._sign(
            {"iss": sub, "sub": sub, "aud": aud, "st_hash": sha256_b64url(subject_token)},
            lifetime=TOKEN_LIFETIME_SECONDS,
        )

    def identity_assertion(self, agent: str, grant: str, audience: str) -> str:
        """The ``Agent-Identity`` header: who is calling, bound to the exact grant string."""
        sub = f"{AGENT_PREFIX}{agent}"
        return self._sign(
            {"iss": sub, "sub": sub, "aud": audience, "grant_hash": sha256_b64url(grant)},
            lifetime=TOKEN_LIFETIME_SECONDS,
        )

    def __repr__(self) -> str:
        return f"AgentKey(kid={self._kid!r})"


__all__ = ["AgentKey", "sha256_b64url", "thumbprint_of_jwk"]
