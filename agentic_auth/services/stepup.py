"""Step-up consent: raise a challenge, record the human's answer, widen one session.

Three properties this module is responsible for, each of which has a place it is made
true rather than merely intended:

- **A challenge can be answered once.** ``GETDEL`` on ``challenge:{id}`` in Redis, with
  ``UNIQUE (challenge_hash)`` on the table as its durable twin (FR-027).
- **A grant never exceeds the pinned manifest.** The ceiling is checked before the insert,
  so a row outside the policy cannot exist (FR-028).
- **The widening is visible in the audit trail** as its own event, linked to the refusal
  that raised it (FR-025).

**The challenge value itself is never stored.** The table keeps its SHA-256; the value
lives only in Redis under its own TTL, and goes to the human. A stored challenge would be
a bearer credential sitting in a table anyone with read access could use (SC-018).

Who may approve is decided in the API layer (``require_consenting_human``), not here —
but it matters enough to restate: the agent must not be able to approve its own widening,
because the threat model assumes the agent may be under an attacker's influence
(research.md R6).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.config import get_settings
from agentic_auth.errors import DomainError, NotFoundError, PolicyDenied, QueryValidationError
from agentic_auth.models.audit_decision import AuditDecision
from agentic_auth.repositories import audit_decisions as audit_repo
from agentic_auth.repositories import step_up_grants as grants_repo
from agentic_auth.schemas.authorize import DenyReason, StepUpChallenge
from agentic_auth.schemas.stepup import StepUpGrantRead
from agentic_auth.services import stepup_rules
from agentic_auth.services.metrics import get_metrics
from agentic_auth.services.policy_loader import PolicyIndex

logger = logging.getLogger(__name__)


def challenge_key(challenge_id: str) -> str:
    return f"challenge:{challenge_id}"


def stepup_key(session_id: str) -> str:
    return f"stepup:{session_id}"


def hash_challenge(challenge_id: str) -> str:
    """Only this ever lands in the table. The value goes to the human and to Redis."""
    return hashlib.sha256(challenge_id.encode()).hexdigest()


class ChallengeExpired(DomainError):
    """The challenge lifetime passed. The original refusal stands."""

    status_code = 410
    code = "challenge_expired"


class ChallengeAlreadyAnswered(DomainError):
    """A challenge is single use. A second answer does not widen consent twice."""

    status_code = 409
    code = "challenge_already_used"


class NotRecoverable(QueryValidationError):
    """This refusal is not a step-up candidate, so there is no question to ask."""


@dataclass(frozen=True)
class PendingChallenge:
    """What Redis holds between raising a challenge and answering it."""

    challenge_id: str
    session_id: str
    blocked_action_id: str
    blocked_hop: int
    data_class: str
    target: str
    reason: str
    expires_at: datetime

    def dumps(self) -> str:
        return json.dumps(
            {
                "challenge_id": self.challenge_id,
                "session_id": self.session_id,
                "blocked_action_id": self.blocked_action_id,
                "blocked_hop": self.blocked_hop,
                "data_class": self.data_class,
                "target": self.target,
                "reason": self.reason,
                "expires_at": self.expires_at.isoformat(),
            }
        )

    @classmethod
    def loads(cls, raw: str | bytes) -> PendingChallenge:
        d = json.loads(raw)
        return cls(
            challenge_id=d["challenge_id"],
            session_id=d["session_id"],
            blocked_action_id=d["blocked_action_id"],
            blocked_hop=d["blocked_hop"],
            data_class=d["data_class"],
            target=d["target"],
            reason=d["reason"],
            expires_at=datetime.fromisoformat(d["expires_at"]),
        )

    def as_read(self) -> StepUpChallenge:
        return StepUpChallenge(
            challenge_id=self.challenge_id,
            session_id=self.session_id,
            blocked_hop=self.blocked_hop,
            blocked_action_id=uuid.UUID(self.blocked_action_id),
            data_class=self.data_class,
            target=self.target,
            reason=DenyReason(self.reason),
            expires_at=self.expires_at,
        )


class StepUpService:
    def __init__(self, *, ttl_seconds: int | None = None) -> None:
        self._ttl = ttl_seconds or get_settings().step_up_challenge_ttl_seconds

    # -- raising ----------------------------------------------------------------

    async def challenge(
        self,
        db: AsyncSession,
        redis: Redis | None,
        *,
        session_id: uuid.UUID,
        blocked_action_id: uuid.UUID,
        policy: PolicyIndex,
    ) -> StepUpChallenge:
        """Read the refusal, check it can be recovered, and mint a single-use challenge.

        Everything about what is being asked for comes off the audit row. A caller that
        could supply its own data class would be writing its own consent.
        """
        row = await audit_repo.get(db, blocked_action_id)
        if row is None or row.session_id != session_id:
            raise NotFoundError(f"no refusal {blocked_action_id} in session {session_id}")
        if row.outcome != "deny" or row.deny_reason is None:
            raise NotRecoverable(
                "that decision was an allow; there is nothing to step up from",
                [{"loc": ["body", "blocked_action_id"], "msg": "not a refusal"}],
            )

        reason = DenyReason(row.deny_reason)
        if not stepup_rules.recoverable(reason):
            # Injected content cannot be laundered by a consent prompt, an undeclared
            # edge cannot be invented by one, and a budget cannot be refilled by one.
            raise NotRecoverable(
                f"{reason.value} is not recoverable; no step-up challenge is offered",
                [{"loc": ["body", "blocked_action_id"], "msg": f"{reason.value} is final"}],
            )

        holder = stepup_rules.holder_of(row.target, row.caller)
        if not stepup_rules.within_ceiling(policy, holder, row.data_class):
            # Refused here rather than at approval time: an operator should learn that a
            # widening is impossible before a human is asked to approve it.
            get_metrics().step_up_outcomes.labels(outcome="out_of_ceiling").inc()
            raise PolicyDenied(
                f"data class {row.data_class!r} is not declared for {holder!r} in the "
                f"pinned policy; consent widens only within the manifest",
                {
                    "reason": "OUTSIDE_MANIFEST_CEILING",
                    "declared": sorted(stepup_rules.ceiling_for(policy, holder)),
                },
            )

        challenge_id = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(seconds=self._ttl)
        pending = PendingChallenge(
            challenge_id=challenge_id,
            session_id=str(session_id),
            blocked_action_id=str(blocked_action_id),
            blocked_hop=row.hop,
            data_class=row.data_class,
            target=row.target,
            reason=reason.value,
            expires_at=expires_at,
        )

        if redis is not None:
            await redis.set(challenge_key(challenge_id), pending.dumps(), ex=self._ttl)
        get_metrics().step_up_challenges.labels(reason=reason.value).inc()
        return pending.as_read()

    # -- answering ---------------------------------------------------------------

    async def complete(
        self,
        db: AsyncSession,
        redis: Redis | None,
        *,
        challenge_id: str,
        approved: bool,
        approved_by: str,
        session_ttl_seconds: int,
    ) -> StepUpGrantRead:
        """Consume the challenge and record the answer.

        Ordering matters and is deliberate: consume, insert, write the linked audit event,
        commit, *then* publish to Redis. Publishing before the commit would widen a
        session on the strength of a write that might still roll back.
        """
        hashed = hash_challenge(challenge_id)
        pending = await self._consume(db, redis, challenge_id, hashed)

        now = datetime.now(UTC)
        grant = await grants_repo.append(
            db,
            session_id=uuid.UUID(pending.session_id),
            blocked_action_id=uuid.UUID(pending.blocked_action_id),
            data_class=pending.data_class,
            target=pending.target,
            challenge_hash=hashed,
            approved_by=approved_by if approved else None,
            approved_at=now if approved else None,
            declined_at=None if approved else now,
        )

        audit_event_id = await self._record_widening(db, grant, pending, approved=approved)
        await db.commit()

        if approved and redis is not None:
            # After the commit, so the set never claims a widening the table does not
            # hold. A lost SADD costs a refusal, not an over-permission.
            with contextlib.suppress(Exception):
                await redis.sadd(stepup_key(pending.session_id), pending.data_class)
                await redis.expire(stepup_key(pending.session_id), session_ttl_seconds)

        get_metrics().step_up_outcomes.labels(outcome="approved" if approved else "declined").inc()
        return StepUpGrantRead(
            id=grant.id,
            session_id=grant.session_id,
            blocked_action_id=grant.blocked_action_id,
            data_class=grant.data_class,
            target=grant.target,
            approved=approved,
            approved_by=grant.approved_by,
            approved_at=grant.approved_at,
            declined_at=grant.declined_at,
            audit_event_id=audit_event_id,
        )

    async def _consume(
        self, db: AsyncSession, redis: Redis | None, challenge_id: str, hashed: str
    ) -> PendingChallenge:
        raw = None
        if redis is not None:
            with contextlib.suppress(Exception):
                raw = await redis.getdel(challenge_key(challenge_id))

        if raw is None:
            # Either it expired, or it was already answered. The table tells them apart,
            # and the difference matters: one invites a fresh challenge, the other does
            # not.
            existing = await grants_repo.by_challenge(db, hashed)
            if existing is not None:
                get_metrics().step_up_outcomes.labels(outcome="replayed").inc()
                raise ChallengeAlreadyAnswered("that challenge has already been answered")
            get_metrics().step_up_outcomes.labels(outcome="expired").inc()
            raise ChallengeExpired("that challenge has expired; the original refusal stands")

        pending = PendingChallenge.loads(raw)
        if pending.expires_at <= datetime.now(UTC):
            get_metrics().step_up_outcomes.labels(outcome="expired").inc()
            raise ChallengeExpired("that challenge has expired; the original refusal stands")
        return pending

    @staticmethod
    async def _record_widening(
        db: AsyncSession, grant: Any, pending: PendingChallenge, *, approved: bool
    ) -> uuid.UUID | None:
        """The widening as its own audit row, linked to the refusal that raised it.

        Written directly rather than through ``AuditService.record()`` because there is no
        decision and no presented token here — this is a human act, not a hop. It carries
        ``step_up_ref`` so a reader following the refusal finds the approval, and the
        approval's ``parent_action_id`` points back at the refusal.
        """
        if not approved:
            return None
        blocked = await audit_repo.get(db, uuid.UUID(pending.blocked_action_id))
        if blocked is None:  # pragma: no cover - checked when the challenge was raised
            return None

        event_id = uuid.uuid4()
        db.add(
            AuditDecision(
                id=event_id,
                session_id=blocked.session_id,
                caller=grant.approved_by or blocked.caller,
                acting_agent=blocked.acting_agent,
                target=blocked.target,
                target_kind=blocked.target_kind,
                data_class=blocked.data_class,
                hop=blocked.hop,
                outcome="allow",
                deny_reason=None,
                recoverable=False,
                enforced=True,
                policy_version=blocked.policy_version,
                act_chain=blocked.act_chain,
                guarantee_level=blocked.guarantee_level,
                step_up_ref=grant.id,
                parent_action_id=blocked.parent_action_id,
                chain=None,
                chain_complete=False,
                chain_break="STEP_UP_EVENT",
            )
        )
        await db.flush()
        return event_id


async def granted_classes(
    db: AsyncSession, redis: Redis | None, session_id: str, *, ttl_seconds: int
) -> frozenset[str]:
    """What a human has approved for this session, for the decision to read.

    Redis is the read path; the table is the truth. On a cache miss the set is rebuilt
    from ``step_up_grants``, mirroring how ``RevocationService.rebuild()`` restores the
    revoked set — a flushed cache must never silently narrow OR widen a session.

    A failure here returns the empty set, which refuses a hop that a grant would have
    allowed. That is the safe direction: the caller sees the original refusal again and
    can ask again.
    """
    if redis is None:
        return frozenset()
    try:
        cached = await redis.smembers(stepup_key(session_id))
    except Exception:
        logger.warning("step-up set unavailable for session %s", session_id)
        return frozenset()

    if cached:
        return frozenset(value.decode() if isinstance(value, bytes) else value for value in cached)

    # Empty could mean "nothing granted" or "cache lost". Ask the table; it is cheap
    # because the overwhelming majority of sessions never raise a challenge at all.
    approved = await grants_repo.approved_classes(db, uuid.UUID(session_id))
    if approved:
        with contextlib.suppress(Exception):
            await redis.sadd(stepup_key(session_id), *approved)
            await redis.expire(stepup_key(session_id), ttl_seconds)
    return frozenset(approved)


__all__ = [
    "ChallengeAlreadyAnswered",
    "ChallengeExpired",
    "NotRecoverable",
    "PendingChallenge",
    "StepUpService",
    "challenge_key",
    "granted_classes",
    "hash_challenge",
    "stepup_key",
]
