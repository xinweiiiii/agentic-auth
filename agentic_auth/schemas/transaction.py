"""``POST /v1/token/transaction`` — request and response."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TransactionMintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    params: dict[str, Any] = Field(
        description="The call's parameters, a JSON object. Bound per docs/canonicalization.md."
    )


class TransactionMinted(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transaction_token: str
    expires_in: int
    params_hash: str = Field(description="base64url SHA-256 of the canonical binding document")
    binding: list[str] | None = Field(
        description="RFC 6901 pointers applied, or null for the whole body"
    )
    action_id: uuid.UUID
