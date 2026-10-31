"""RFC 8693 token exchange: the request grammar and the issued response."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"


class TokenExchangeRequest(BaseModel):
    """Form-encoded per RFC 8693 §2.1.

    ``resource`` and ``scope`` are required here even though the RFC makes them optional:
    a hop token that does not name exactly one target and one data class would not be a
    narrowing, which is the only thing this endpoint exists to do.
    """

    model_config = ConfigDict(extra="forbid")

    grant_type: Literal["urn:ietf:params:oauth:grant-type:token-exchange"]
    subject_token: str
    subject_token_type: Literal["urn:ietf:params:oauth:token-type:jwt"]
    resource: str = Field(max_length=512)
    scope: str = Field(max_length=128)
    # Optional in Phase 2; required once agents carry proof-of-possession in Phase 4.
    actor_token: str | None = None
    actor_token_type: Literal["urn:ietf:params:oauth:token-type:jwt"] | None = None
    audience: str | None = None


class TokenExchangeResponse(BaseModel):
    """RFC 8693 §2.2."""

    model_config = ConfigDict(extra="forbid")

    access_token: str
    issued_token_type: Literal["urn:ietf:params:oauth:token-type:jwt"] = (
        "urn:ietf:params:oauth:token-type:jwt"
    )
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    scope: str


class OAuthError(BaseModel):
    """RFC 6749 §5.2 error body — what an OAuth client already knows how to read."""

    model_config = ConfigDict(extra="forbid")

    error: Literal["invalid_request", "invalid_grant", "invalid_target", "unsupported_grant_type"]
    error_description: str | None = None


class HopTokenClaims(BaseModel):
    """The claim set of an issued hop token."""

    model_config = ConfigDict(extra="allow")

    iss: str
    sub: str
    aud: str
    scope: str
    resource: str
    exp: int
    iat: int
    jti: str
    session_id: str
    policy_version: int
    hop: int
    act: dict[str, Any] | None = None
    # Phase 4: effective taint at mint; absent reads as trusted_internal.
    taint: Literal["trusted_internal", "untrusted_external"] | None = None


class AzdClaim(BaseModel):
    """The binding a transaction token carries (docs/canonicalization.md §4)."""

    model_config = ConfigDict(extra="forbid")

    target: str
    params_hash: str
    hash_alg: Literal["sha-256"] = "sha-256"
    canon: Literal["rfc8785"] = "rfc8785"
    binding: list[str] | None = None


class TransactionTokenClaims(BaseModel):
    """The claim set of a transaction token."""

    model_config = ConfigDict(extra="allow")

    iss: str
    iat: int
    exp: int
    jti: str
    txn: str
    sub: str
    aud: str
    session_id: str
    action_id: str
    hop: int
    act: dict[str, Any] | None = None
    taint: Literal["trusted_internal", "untrusted_external"] | None = None
    azd: AzdClaim


class ActorTokenClaims(BaseModel):
    """RFC 8693 ``actor_token`` as this project uses it: proof of possession of the enrolled
    key, bound to the exact subject token."""

    model_config = ConfigDict(extra="allow")

    iss: str
    sub: str
    aud: str
    iat: int
    exp: int
    jti: str
    st_hash: str
