"""Enrollment: challenge, then a signed response; enrolled, quarantined, or rejected.

``begin`` stores a single-use challenge bound to the agent and to a hash of the identity
document. ``complete`` consumes it (``GETDEL``) before doing anything else, verifies the
signature against a key IN THE PRESENTED DOCUMENT (never the issuer's keys, never a key the
agent names but did not present), runs principal binding, then hands every fact to the pure
:func:`app.services.enrollment_rules.decide` and applies the outcome in one transaction.

Completing enrollment grants nothing. It pins a trust anchor; authorization is elsewhere.
"""

from __future__ import annotations

import json
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.errors import (
    IdpUnavailable,
    KeyRevoked,
    NotFoundError,
    ReconciliationRejected,
    UnauthorizedError,
)
from app.repositories import agents as agents_repo
from app.repositories import manifests as manifests_repo
from app.repositories import reconciliation_reports as reports_repo
from app.repositories import trust_anchors as anchors_repo
from app.schemas.identity import (
    EnrollBegin,
    EnrollChallenge,
    EnrollComplete,
    EnrollOutcome,
    IdentityDocument,
)
from app.services.anchors import AnchorCache, thumbprint
from app.services.enrollment_rules import Bound, EnrollDecision, NotConfigured, Unbindable, decide
from app.services.metrics import get_metrics
from app.services.principal import PrincipalBinder
from app.verify.canonical import canonical_json

logger = logging.getLogger(__name__)

AGENT_PREFIX = "agent://"
RESPONSE_MAX_LIFETIME = 120


class ChallengeStoreUnavailable(RuntimeError):
    pass


def challenge_key(challenge_id: uuid.UUID | str) -> str:
    return f"enroll:{challenge_id}"


def _doc_hash(doc: IdentityDocument) -> str:
    import base64
    import hashlib

    digest = hashlib.sha256(canonical_json(doc.public_document())).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class EnrollmentService:
    def __init__(self, binder: PrincipalBinder, anchors: AnchorCache) -> None:
        self._binder = binder
        self._anchors = anchors

    # -- begin ---------------------------------------------------------------------

    async def begin(
        self, db: AsyncSession, redis: Redis | None, agent_id: uuid.UUID, body: EnrollBegin
    ) -> EnrollChallenge:
        agent = await agents_repo.get_by_id(db, agent_id)
        if agent is None:
            raise NotFoundError(f"agent {agent_id} not found")
        if agent.status == "revoked":
            raise KeyRevoked(f"agent {agent.name} is revoked; enrollment is closed")
        if body.identity_doc.sub != f"{AGENT_PREFIX}{agent.name}":
            from app.errors import ManifestValidationError

            raise ManifestValidationError(
                "identity document names another agent",
                {
                    "fields": [
                        {
                            "loc": ["identity_doc", "sub"],
                            "msg": f"expected agent://{agent.name}",
                        }
                    ]
                },
            )

        settings = get_settings()
        challenge_id = uuid.uuid4()
        nonce = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(seconds=settings.enroll_challenge_ttl_seconds)
        record = {
            "agent_id": str(agent.id),
            "doc_hash": _doc_hash(body.identity_doc),
            "nonce": nonce,
            # The public document is kept with the challenge so `complete` verifies against
            # exactly the keys that were presented, and can keep them for quarantine.
            "doc": body.identity_doc.public_document(),
            # The assertion is a short-lived IdP credential. It is held ONLY here, in the
            # control plane's own Redis, for at most enroll_challenge_ttl_seconds, consumed
            # by GETDEL on the first `complete`, and never written to a table, a metric or
            # a log (security audit). Requiring the agent to re-present it at
            # `complete` would let a caller swap in a different principal than the one the
            # challenge was issued for, which is why it is bound to the challenge instead.
            "principal_assertion": body.identity_doc.principal_assertion,
        }
        if redis is None:
            raise ChallengeStoreUnavailable("no challenge store configured")
        try:
            await redis.set(
                challenge_key(challenge_id),
                json.dumps(record),
                ex=settings.enroll_challenge_ttl_seconds,
            )
        except Exception as exc:
            raise ChallengeStoreUnavailable(f"challenge store unreachable: {exc}") from exc
        return EnrollChallenge(challenge_id=challenge_id, nonce=nonce, expires_at=expires_at)

    # -- complete ------------------------------------------------------------------

    async def complete(
        self, db: AsyncSession, redis: Redis | None, agent_id: uuid.UUID, body: EnrollComplete
    ) -> EnrollOutcome:
        metrics = get_metrics()
        agent = await agents_repo.get_by_id(db, agent_id)
        if agent is None:
            raise NotFoundError(f"agent {agent_id} not found")

        record = await self._consume_challenge(redis, body.challenge_id)
        if record is None or record.get("agent_id") != str(agent.id):
            metrics.enrollments.labels(outcome="rejected").inc()
            raise UnauthorizedError("challenge is unknown, expired, or already used")

        doc: dict[str, Any] = record["doc"]
        keys: list[dict[str, Any]] = doc["jwks"]["keys"]
        signature_ok = self._verify_response(
            body.signed_response, keys, record["nonce"], agent.name
        )

        presented = {thumbprint(k) for k in keys}
        revoked = await anchors_repo.revoked_thumbprints(db, agent.id)
        revoked_key = agent.status == "revoked" or bool(presented & revoked)

        principal: Any
        if signature_ok and not revoked_key:
            principal = await self._binder.bind(record.get("principal_assertion"), agent.name)
        else:
            principal = Unbindable("not evaluated")

        latest = await manifests_repo.get_latest(db, agent.id)
        manifest_reconciled = latest is not None and latest.status == "reconciled"

        outcome = decide(
            signature_ok=signature_ok,
            revoked_key=revoked_key,
            principal=principal,
            manifest_reconciled=manifest_reconciled,
        )

        if outcome is EnrollDecision.REJECTED_SIGNATURE:
            metrics.enrollments.labels(outcome="rejected").inc()
            raise UnauthorizedError("signed response does not verify against the presented keys")
        if outcome is EnrollDecision.REJECTED_KEY_REVOKED:
            metrics.enrollments.labels(outcome="key_revoked").inc()
            raise KeyRevoked(
                f"agent {agent.name} is revoked"
                if agent.status == "revoked"
                else "a presented key belongs to a revoked trust anchor and is never re-pinned"
            )
        if outcome is EnrollDecision.FAILED_IDP_UNREACHABLE:
            metrics.enrollments.labels(outcome="idp_unavailable").inc()
            raise IdpUnavailable(getattr(principal, "detail", "identity provider unreachable"))
        if outcome is EnrollDecision.QUARANTINED:
            reason = (
                "PRINCIPAL_IDP_NOT_CONFIGURED"
                if isinstance(principal, NotConfigured)
                else "PRINCIPAL_UNBINDABLE"
            )
            detail = getattr(principal, "detail", None)
            await agents_repo.set_status(
                db,
                agent,
                status="quarantined",
                principal_ref=None,
                trust_anchor_version=None,
                pending_identity=doc,
            )
            await db.commit()
            await self._anchors.invalidate(agent.name)
            metrics.enrollments.labels(outcome="quarantined").inc()
            return EnrollOutcome(status="quarantined", reason=reason, detail=detail)
        if outcome is EnrollDecision.REJECTED_MANIFEST:
            metrics.enrollments.labels(outcome="reconciliation_rejected").inc()
            diff: list[dict[str, Any]] = []
            if latest is not None:
                found = await reports_repo.get_latest_for_agent(db, agent.id)
                if found is not None:
                    diff = found[0].diff
            version_text = latest.version if latest else "?"
            status_text = latest.status if latest else "missing"
            raise ReconciliationRejected(
                f"manifest version {version_text} has status {status_text}; "
                "enrollment requires a reconciled manifest",
                {"diff": diff},
            )

        # ENROLLED
        assert isinstance(principal, Bound) and latest is not None
        now = datetime.now(UTC)
        await anchors_repo.revoke_current(
            db, agent.id, at=now, reason="superseded by re-enrollment"
        )
        version = await anchors_repo.next_version(db, agent.id)
        await anchors_repo.append(
            db,
            agent_id=agent.id,
            version=version,
            jwks=doc["jwks"],
            key_thumbprints=sorted(presented),
            principal_ref=principal.principal_ref,
            manifest_version=latest.version,
        )
        await agents_repo.set_status(
            db,
            agent,
            status="enrolled",
            principal_ref=principal.principal_ref,
            trust_anchor_version=version,
            pending_identity=None,
        )
        await db.commit()
        await self._anchors.invalidate(agent.name)
        metrics.enrollments.labels(outcome="enrolled").inc()
        return EnrollOutcome(
            status="enrolled", trust_anchor_version=version, principal_ref=principal.principal_ref
        )

    # -- helpers -------------------------------------------------------------------

    async def _consume_challenge(
        self, redis: Redis | None, challenge_id: uuid.UUID
    ) -> dict[str, Any] | None:
        if redis is None:
            raise ChallengeStoreUnavailable("no challenge store configured")
        try:
            raw = await redis.getdel(challenge_key(challenge_id))
        except Exception as exc:
            raise ChallengeStoreUnavailable(f"challenge store unreachable: {exc}") from exc
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except ValueError:
            return None

    @staticmethod
    def _verify_response(
        signed: str, keys: list[dict[str, Any]], nonce: str, agent_name: str
    ) -> bool:
        try:
            header = jwt.get_unverified_header(signed)
        except jwt.PyJWTError:
            return False
        if header.get("alg") != "EdDSA":
            return False
        key_entry = next((k for k in keys if k.get("kid") == header.get("kid")), None)
        if key_entry is None:
            return False  # a kid the document does not present proves nothing
        try:
            public = jwt.PyJWK(dict(key_entry), algorithm="EdDSA").key
            claims = jwt.decode(
                signed,
                public,
                algorithms=["EdDSA"],
                audience=get_settings().issuer,
                options={"require": ["exp", "iat", "sub", "aud", "nonce"]},
                leeway=5,
            )
        except jwt.PyJWTError:
            return False
        expected = f"{AGENT_PREFIX}{agent_name}"
        if claims.get("sub") != expected or claims.get("iss") != expected:
            return False
        if claims.get("nonce") != nonce:
            return False
        return int(claims["exp"]) - int(claims["iat"]) <= RESPONSE_MAX_LIFETIME


__all__ = ["ChallengeStoreUnavailable", "EnrollmentService", "challenge_key"]
