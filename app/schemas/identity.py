"""Identity plane request/response models.

Inbound models are ``extra="forbid"``. ``Jwk`` accepts OKP/Ed25519 public keys only and
rejects a private member outright: an identity document that leaks ``d`` is a bug on the
agent's side that the control plane refuses to store.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.agent import AgentStatus
from app.schemas.manifest import AgentUri


class Jwk(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    x: str = Field(description="base64url, 32 bytes")
    kid: str = Field(min_length=1, max_length=64)
    alg: Literal["EdDSA"] = "EdDSA"
    use: Literal["sig"] = "sig"

    @field_validator("x")
    @classmethod
    def _thirty_two_bytes(cls, value: str) -> str:
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, TypeError) as exc:
            raise ValueError("x must be base64url") from exc
        if len(raw) != 32:
            raise ValueError("x must decode to 32 bytes")
        return value


class Jwks(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keys: list[Jwk] = Field(min_length=1, max_length=8)

    @field_validator("keys")
    @classmethod
    def _unique_kids(cls, keys: list[Jwk]) -> list[Jwk]:
        kids = [k.kid for k in keys]
        if len(set(kids)) != len(kids):
            raise ValueError("kid values must be unique")
        return keys


class IdentityDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sub: AgentUri
    jwks: Jwks
    claims: dict[str, Any] = Field(default_factory=dict)
    principal_assertion: str | None = Field(default=None, max_length=8192)

    def public_document(self) -> dict[str, Any]:
        """What may be stored: never the assertion (a bearer credential for the IdP)."""
        return {"sub": self.sub, "jwks": self.jwks.model_dump(), "claims": self.claims}


class EnrollBegin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_doc: IdentityDocument


class EnrollChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: uuid.UUID
    nonce: str
    expires_at: datetime


class EnrollComplete(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: uuid.UUID
    signed_response: str = Field(max_length=8192)


QuarantineReason = Literal["PRINCIPAL_UNBINDABLE", "PRINCIPAL_IDP_NOT_CONFIGURED"]


class EnrollOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["enrolled", "quarantined"]
    trust_anchor_version: int | None = None
    principal_ref: str | None = None
    reason: QuarantineReason | None = None
    detail: str | None = None


class RevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=1024)


class RevokeOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["revoked"]
    trust_anchor_version: int
    revoked_at: datetime


class AgentIdentityRead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: str
    status: AgentStatus
    trust_anchor_version: int | None
    jwks: dict[str, Any] | None
    principal_ref: str | None
    manifest_version: int | None
    revoked: bool
    revoked_at: datetime | None
    as_of: datetime


class RevocationItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: str
    trust_anchor_version: int
    revoked_at: datetime


class RevocationPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    next_cursor: str | None
    limit: int


class RevocationListRead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    as_of: datetime
    items: list[RevocationItem]
    page: RevocationPage
