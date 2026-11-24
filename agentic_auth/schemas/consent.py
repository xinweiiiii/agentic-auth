"""Consent: the human act that roots all downstream authority."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SerializerFunctionWrapHandler, model_serializer

from agentic_auth.schemas.common import PrincipalSource

MIN_SESSION_TTL = 60
MAX_SESSION_TTL = 86_400
# A bound on the consented subset. Generous — a real scope declares a handful — but a
# request is attacker-shaped input and an unbounded list is an unbounded array column.
MAX_CONSENTED_DATA_CLASSES = 256


class SubjectTokenType(StrEnum):
    """RFC 8693 token type URIs consent accepts as evidence of the human."""

    ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
    ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"


class ConsentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Required, except when client mapping (M4) is on and the token's client is mapped: the
    # scope is then the mapped agent's, and if given here it must equal it.
    scope: str | None = Field(default=None, max_length=255, min_length=1)
    # The consenting human. With verified consent off (the default) it is asserted by the
    # integrator and required. With it on it is optional, taken from ``subject_token``, and
    # if given must equal the verified ``iss#sub``. Required-ness depends on a setting, so
    # the service enforces it, not this schema.
    user_sub: str | None = Field(default=None, max_length=255, min_length=1)
    # 0.4.0 (feature 011, M2). The user's IdP token, as evidence of who consented. Verified
    # by the control plane itself, even when a proxy already verified it. Never stored:
    # only its SHA-256 lands on the session.
    subject_token: str | None = Field(default=None, min_length=1, max_length=16384, repr=False)
    subject_token_type: SubjectTokenType = SubjectTokenType.ACCESS_TOKEN
    ttl_seconds: int | None = Field(default=None, ge=MIN_SESSION_TTL, le=MAX_SESSION_TTL)
    # Phase 5. The subset of the pinned policy's data classes this consent covers.
    #
    # Omitted (the default) means "everything the policy declares", which is exactly
    # Phase 2-4 semantics — so every existing caller is unaffected. Supplying a subset is
    # what makes SCOPE_NOT_CONSENTED mean "the human did not approve this" rather than
    # "the manifest never declared it", and therefore what makes step-up able to grant
    # anything at all.
    #
    # Validated against the pinned policy at consent time, not at first use: a typo
    # should surface to the integrator immediately, not as a refusal three hops into a
    # chain. Rejected entirely unless `consent_granularity_enabled`.
    data_classes: list[str] | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_CONSENTED_DATA_CLASSES,
        description=(
            "Subset of the pinned policy's data classes to consent to. Omit for all of "
            "them. Every entry must be declared by some agent in the compiled scope."
        ),
    )


class ConsentRead(BaseModel):
    """What the integrator gets back. ``root_grant`` is the hop-1 token."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    root_grant: str
    policy_version: int
    scope: str
    user_sub: str
    hop_budget: int
    expires_at: datetime
    # Phase 5. What was actually pinned: null means every class the policy declares.
    data_classes: list[str] | None = None
    # 0.4.0. How the consenting human was established, and the IdP client (M4). Omitted from
    # the response, not sent as null, until they carry information: a 0.3.0 SDK builds its
    # Session from every key it receives, so a new key would break every deployed client
    # that has not opted into 0.4.0's features (spec FR-019).
    principal_source: PrincipalSource | None = None
    client_id: str | None = None

    @model_serializer(mode="wrap")
    def _omit_unset_0_4_0_fields(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        for name in ("principal_source", "client_id"):
            if data.get(name) is None:
                data.pop(name, None)
        return data


class SessionRead(BaseModel):
    """The session without any token material — for reads and diagnostics."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    scope: str
    user_sub: str
    policy_version: int
    hop_budget: int
    created_at: datetime
    expires_at: datetime
    data_classes: list[str] | None = None
