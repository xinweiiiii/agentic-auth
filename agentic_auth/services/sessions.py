"""Consent, policy-version pinning, and session reads.

A session is created once and never updated. Everything a decision needs is either in the
request, in the presented token, or in this immutable row — which is what lets the PDP
stay stateless and lets a session read be a pure cache-friendly lookup.

**Who consented** (feature 011, M2). With ``verified_consent_enabled`` the consenting human
comes from the user's IdP token, which this service verifies itself — even when a proxy has
already verified it, because a proxy's verdict is not evidence. The session records
``principal_source=verified`` and the token's SHA-256, never the token. With it off, the
integrator's asserted ``user_sub`` is used and recorded as ``asserted``, exactly as before.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth import runtime
from agentic_auth.config import get_settings
from agentic_auth.errors import (
    ClientNotAuthorized,
    DomainError,
    IdpUnavailable,
    NotFoundError,
    QueryValidationError,
    SessionExpired,
    SessionSuperseded,
    SubjectMismatch,
    SubjectTokenInvalid,
    SubjectTokenRequired,
)
from agentic_auth.oauth import validate as oauth_validate
from agentic_auth.repositories import sessions as sessions_repo
from agentic_auth.schemas.common import PrincipalSource
from agentic_auth.schemas.consent import ConsentCreate, ConsentRead
from agentic_auth.services import policy_loader
from agentic_auth.services.metrics import get_metrics
from agentic_auth.services.policy_loader import PolicyIndex
from agentic_auth.services.tokens.profile import TokenProfile

logger = logging.getLogger(__name__)


def _key(session_id: str) -> str:
    return f"session:{session_id}"


@dataclass(frozen=True)
class Principal:
    """Who consented, and how we know."""

    user_sub: str
    source: PrincipalSource
    client_id: str | None = None
    subject_token_hash: str | None = None


# One validator per (settings instance, IdP configuration), so the JWKS cache outlives a
# request. Keyed on the settings object as well, so an embedded control plane never shares
# keys with the process around it.
_validators: dict[tuple[object, ...], oauth_validate.TokenValidator] = {}


def reset_validators() -> None:
    """Forget cached IdP keys. Tests whose fake IdP mints fresh keys under the same URL."""
    _validators.clear()


def _consent_validator() -> oauth_validate.TokenValidator:
    from agentic_auth.services.principal import idp_http

    s = get_settings()
    key = (
        id(s),
        s.principal_idp_issuer,
        s.principal_idp_jwks_url,
        s.consent_audiences,
        s.principal_idp_algorithms,
    )
    validator = _validators.get(key)
    if validator is None:
        validator = oauth_validate.TokenValidator(
            issuer=s.principal_idp_issuer,
            audiences=s.consent_audiences,
            jwks=oauth_validate.JwksCache(s.principal_idp_jwks_url, idp_http),
            algorithms=s.principal_algorithms,
        )
        _validators[key] = validator
    return validator


@dataclass(frozen=True)
class PinnedSession:
    id: uuid.UUID
    scope: str
    user_sub: str
    policy_version: int
    hop_budget: int
    created_at: datetime
    expires_at: datetime
    # Phase 5. The subset of the pinned policy's data classes this consent covers, or
    # None for "everything the policy declares" — which is exactly Phase 2-4 semantics.
    # Nothing reads it until the PDP split lands.
    consented_data_classes: list[str] | None = None
    # 0.4.0. Copied onto every audit row this session produces.
    principal_source: str = PrincipalSource.ASSERTED.value
    client_id: str | None = None

    def as_cache(self) -> str:
        return json.dumps(
            {
                "id": str(self.id),
                "scope": self.scope,
                "user_sub": self.user_sub,
                "policy_version": self.policy_version,
                "hop_budget": self.hop_budget,
                "created_at": self.created_at.isoformat(),
                "expires_at": self.expires_at.isoformat(),
                "consented_data_classes": self.consented_data_classes,
                "principal_source": self.principal_source,
                "client_id": self.client_id,
            }
        )

    @classmethod
    def from_cache(cls, raw: str | bytes) -> PinnedSession:
        d = json.loads(raw)
        return cls(
            id=uuid.UUID(d["id"]),
            scope=d["scope"],
            user_sub=d["user_sub"],
            policy_version=d["policy_version"],
            hop_budget=d["hop_budget"],
            created_at=datetime.fromisoformat(d["created_at"]),
            expires_at=datetime.fromisoformat(d["expires_at"]),
            # `.get`, not `[...]`: an entry cached before this field existed must still
            # load, and its absence means exactly what None means.
            consented_data_classes=d.get("consented_data_classes"),
            principal_source=d.get("principal_source", PrincipalSource.ASSERTED.value),
            client_id=d.get("client_id"),
        )

    @classmethod
    def from_row(cls, row: Any) -> PinnedSession:
        return cls(
            id=row.id,
            scope=row.scope,
            user_sub=row.user_sub,
            policy_version=row.policy_version,
            hop_budget=row.hop_budget,
            created_at=row.created_at,
            expires_at=row.expires_at,
            consented_data_classes=row.consented_data_classes,
            principal_source=row.principal_source,
            client_id=row.client_id,
        )


class SessionService:
    def __init__(self, tokens: TokenProfile, *, ttl_seconds: int | None = None) -> None:
        self._tokens = tokens
        self._ttl = ttl_seconds or get_settings().session_ttl_seconds

    async def consent(
        self, db: AsyncSession, redis: Redis | None, body: ConsentCreate
    ) -> ConsentRead:
        """Record consent and pin the policy version in effect at this moment.

        Loading the policy here is not just a lookup — it is the gate that refuses a scope
        whose compiled policy predates runtime enforcement, rather than pinning something
        the PDP could not later decide against.

        Who consented is settled first, before any policy is read: a refusal there must not
        depend on, or reveal, what scopes exist.
        """
        try:
            principal = await self._principal(body)
            scope = await self._scope(db, body, principal)
        except DomainError as exc:
            _count_refusal(exc, body.subject_token)
            raise

        version = await policy_loader.latest_version(db, scope)
        if version is None:
            raise NotFoundError(f"no compiled policy for scope {scope!r}")

        # Raises PolicyRecompileRequired for a v1 policy. Deliberately before the insert.
        index = await policy_loader.load(db, redis, scope, version)

        consented = self._validate_data_classes(index, body.data_classes)

        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=body.ttl_seconds or self._ttl)
        row = await sessions_repo.create(
            db,
            scope=scope,
            user_sub=principal.user_sub,
            policy_version=version,
            # Copied at consent, so a later publish cannot widen a running session.
            hop_budget=index.hop_budget,
            expires_at=expires_at,
            consented_data_classes=consented,
            principal_source=principal.source.value,
            client_id=principal.client_id,
            subject_token_hash=principal.subject_token_hash,
        )
        session = PinnedSession.from_row(row)
        root_grant = self._tokens.mint_root_grant(
            sub=principal.user_sub,
            scope=scope,
            session_id=str(row.id),
            policy_version=version,
        )
        await self._cache(redis, session)
        return ConsentRead(
            session_id=str(row.id),
            root_grant=root_grant,
            policy_version=version,
            scope=scope,
            user_sub=principal.user_sub,
            hop_budget=index.hop_budget,
            expires_at=expires_at,
            data_classes=consented,
            # Asserted is what every 0.3.0 session was; saying so adds nothing and would
            # change the response shape for clients that never opted in.
            principal_source=(
                None if principal.source is PrincipalSource.ASSERTED else principal.source
            ),
            client_id=principal.client_id,
        )

    @staticmethod
    async def _scope(db: AsyncSession, body: ConsentCreate, principal: Principal) -> str:
        """The scope this session runs in.

        With client mapping on and a verified token, it is the scope of the agent the token's
        client maps to (research F3: a scope is rooted at one agent). An unmapped client, or
        one whose agent has no compiled scope yet, is identified but not authorized: refused,
        pointing at cold start. Otherwise the request names it, as before.
        """
        settings = get_settings()
        if not (
            settings.client_mapping_enabled and principal.source is not PrincipalSource.ASSERTED
        ):
            if body.scope is None:
                raise QueryValidationError(
                    "scope is required", [{"loc": ["body", "scope"], "msg": "Field required"}]
                )
            return body.scope

        from agentic_auth.services.client_mapping import ClientMappingService

        client_id = principal.client_id
        mapped = await ClientMappingService().resolve(db, client_id) if client_id else None
        details: dict[str, Any] = {
            "reason": "CLIENT_NOT_AUTHORIZED",
            "recoverable": False,
            "next": "cold_start",
            "client_id": client_id,
        }
        if mapped is None:
            raise ClientNotAuthorized(
                "this client is identified but not mapped to any agent: an admin maps it with "
                "POST /v1/agents/{agent_id}/clients, or ratifies a manifest through cold start",
                details,
            )
        scope = mapped.agent.name
        if await policy_loader.latest_version(db, scope) is None:
            if settings.sandbox_enabled:
                details["sandbox"] = f"/v1/agents/{mapped.agent.id}/sandbox"
            raise ClientNotAuthorized(
                f"this client acts as agent {scope!r}, which has no pinned manifest yet: it has "
                "no authority until a human ratifies one",
                details,
            )
        if body.scope is not None and body.scope != scope:
            raise QueryValidationError(
                f"scope must be {scope!r}, the scope of the agent this client acts as, or omitted",
                [{"loc": ["body", "scope"], "msg": "does not match the mapped agent"}],
            )
        return scope

    @staticmethod
    async def _principal(body: ConsentCreate) -> Principal:
        """Who is consenting, and how we know it. Raises a ``DomainError`` refusal."""
        settings = get_settings()
        if not settings.verified_consent_enabled:
            if body.subject_token is not None:
                # Refused, not ignored: silently dropping the evidence would let a caller
                # believe the session's root was verified when it was not.
                raise QueryValidationError(
                    "subject_token was sent but verified consent is not enabled on this "
                    "deployment (AGENTIC_AUTH_VERIFIED_CONSENT_ENABLED)",
                    [{"loc": ["body", "subject_token"], "msg": "feature disabled"}],
                )
            if body.user_sub is None:
                raise QueryValidationError(
                    "user_sub is required",
                    [{"loc": ["body", "user_sub"], "msg": "Field required"}],
                )
            return Principal(user_sub=body.user_sub, source=PrincipalSource.ASSERTED)

        if body.subject_token is None:
            raise SubjectTokenRequired(
                "verified consent is enabled: send the user's IdP token as subject_token; an "
                "asserted user_sub alone is not accepted"
            )
        try:
            verified = await _consent_validator().validate(body.subject_token)
        except oauth_validate.TokenInvalid as exc:
            raise SubjectTokenInvalid(
                f"subject_token did not verify: {exc.check.value}", {"check": exc.check.value}
            ) from exc
        except oauth_validate.IdpUnavailable as exc:
            raise IdpUnavailable(
                "the identity provider's keys could not be obtained; retry",
                {"retryable": True},
            ) from exc

        if body.user_sub is not None and body.user_sub != verified.principal:
            raise SubjectMismatch(
                "user_sub does not match the subject of subject_token; omit user_sub to use "
                "the verified subject"
            )
        # An embedded control plane's IdP is its built-in test one: say so on every session.
        source = (
            PrincipalSource.EMBEDDED_TEST
            if runtime.override() is not None
            else PrincipalSource.VERIFIED
        )
        return Principal(
            user_sub=verified.principal,
            source=source,
            # Recorded only when a mapping chooses the scope (M4); otherwise the client is
            # not what the session's authority came from.
            client_id=verified.client_id if settings.client_mapping_enabled else None,
            subject_token_hash=hashlib.sha256(body.subject_token.encode()).hexdigest(),
        )

    @staticmethod
    def _validate_data_classes(index: PolicyIndex, requested: list[str] | None) -> list[str] | None:
        """Check a consented subset against the pinned policy, before the insert.

        Validating here rather than at first use means a typo surfaces to the integrator
        as a 422 on the consent call, instead of as a refusal three hops into a chain
        where it reads like a policy bug.

        Rejected outright when the feature is off, so a caller cannot believe it pinned a
        narrower consent than it did — silently ignoring the field would be the same
        class of error the guarantee level exists to prevent.
        """
        if requested is None:
            return None
        if not get_settings().consent_granularity_enabled:
            raise QueryValidationError(
                "data_classes requires consent granularity, which is disabled on this "
                "deployment (AGENTIC_AUTH_CONSENT_GRANULARITY_ENABLED)",
                [{"loc": ["body", "data_classes"], "msg": "feature disabled"}],
            )

        declared = {cls for classes in index.data_classes_by_agent.values() for cls in classes}
        unknown = sorted(set(requested) - declared)
        if unknown:
            raise QueryValidationError(
                f"data classes {unknown} are not declared by any agent in scope "
                f"{index.scope!r} at policy version {index.version}",
                [{"loc": ["body", "data_classes"], "msg": f"not declared: {unknown}"}],
            )
        # Deduplicated and ordered so the stored array, the cache and the read model
        # cannot disagree about a set that was written twice.
        return sorted(set(requested))

    async def get(self, db: AsyncSession, redis: Redis | None, session_id: str) -> PinnedSession:
        """Read-through by id. Raises ``SessionExpired`` past ``expires_at``.

        Expiry is checked against this record, not against the token's ``exp``, so a
        still-valid token inside a dead session is refused.
        """
        try:
            sid = uuid.UUID(session_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise NotFoundError(f"unknown session {session_id!r}") from exc

        session: PinnedSession | None = None
        if redis is not None:
            with contextlib.suppress(Exception):
                cached = await redis.get(_key(session_id))
                if cached is not None:
                    session = PinnedSession.from_cache(cached)

        if session is None:
            row = await sessions_repo.get(db, sid)
            if row is None:
                raise NotFoundError(f"unknown session {session_id!r}")
            session = PinnedSession.from_row(row)
            await self._cache(redis, session)

        if session.expires_at <= datetime.now(UTC):
            raise SessionExpired(
                f"session {session_id} expired at {session.expires_at.isoformat()}"
            )
        current = runtime.override()
        if (
            current is not None
            and current.superseded_before is not None
            and session.created_at < current.superseded_before
        ):
            raise SessionSuperseded(
                f"session {session_id} predates this embedded store's last open; consent again"
            )
        return session

    async def _cache(self, redis: Redis | None, session: PinnedSession) -> None:
        if redis is None:
            return
        ttl = int((session.expires_at - datetime.now(UTC)).total_seconds())
        if ttl <= 0:
            return
        with contextlib.suppress(Exception):
            await redis.set(_key(str(session.id)), session.as_cache(), ex=ttl)


def _count_refusal(exc: DomainError, subject_token: str | None) -> None:
    """A consent refusal has no session and no audit row (research F6): the counter and
    this log line are its only record. The token appears as a fingerprint, never itself."""
    if exc.code == "validation_error":
        return  # a malformed request, not a refusal of a human
    get_metrics().consent_refusals.labels(reason=exc.code).inc()
    logger.info(
        "consent refused",
        extra={
            "reason": exc.code,
            "token_fingerprint": (
                oauth_validate.fingerprint(subject_token) if subject_token else None
            ),
        },
    )
