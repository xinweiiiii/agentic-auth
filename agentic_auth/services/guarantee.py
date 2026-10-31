"""Tracking the guarantee level in force, and making a degrade impossible to miss.

The enum and the ordering live in :mod:`agentic_auth.boundary.guarantee`. This module is the part
that needs state: noticing when the level a session runs under gets *weaker*, and writing
that as its own audit event (FR-019).

Why an audit row rather than a log line: a degrade matters exactly in relation to the
decisions around it. An operator reading a session should see "hop 3 ran at full, then
the level dropped, then hop 4 ran at consent_only" in one timeline, not have to correlate
two systems by timestamp. PRD §8.3's rule is that a reduced guarantee is *surfaced*, and
something you have to go and find is not surfaced.

A deployment that starts weak is **not** a degrade. It is a configuration, reported on
every response from the first one, and writing an event for it would train operators to
ignore the event that matters.
"""

from __future__ import annotations

import contextlib
import logging
import uuid

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.boundary.guarantee import Guarantee, is_degrade
from agentic_auth.models.audit_decision import AuditDecision, target_kind_of
from agentic_auth.services.metrics import get_metrics

logger = logging.getLogger(__name__)


def level_key(session_id: str) -> str:
    return f"guarantee:{session_id}"


async def note_level(
    db: AsyncSession,
    redis: Redis | None,
    *,
    session_id: str,
    level: Guarantee,
    caller: str,
    target: str,
    policy_version: int,
    act_chain: list,
    ttl_seconds: int,
) -> Guarantee | None:
    """Record the level in force, and write an event if it just got weaker.

    Returns the previous level when a degrade happened, otherwise ``None``.

    Failing to read the previous level is not an error: the worst case is a degrade that
    goes unrecorded once, and refusing the call over it would turn an observability
    feature into an availability risk. The level is still on the decision row itself —
    which is the durable record — so nothing is actually lost, only the marker.
    """
    if redis is None:
        return None

    previous_raw = None
    try:
        previous_raw = await redis.getset(level_key(session_id), level.value)
        await redis.expire(level_key(session_id), ttl_seconds)
    except Exception:
        logger.warning("could not track the guarantee level for session %s", session_id)
        return None

    if previous_raw is None:
        return None  # first decision in this session: a configuration, not a degrade
    previous_value = previous_raw.decode() if isinstance(previous_raw, bytes) else str(previous_raw)
    try:
        previous = Guarantee(previous_value)
    except ValueError:
        return None
    if not is_degrade(previous, level):
        return None

    get_metrics().guarantee_degrades.labels(from_level=previous.value, to_level=level.value).inc()
    with contextlib.suppress(Exception):
        await _write_event(
            db,
            session_id=session_id,
            previous=previous,
            current=level,
            caller=caller,
            target=target,
            policy_version=policy_version,
            act_chain=act_chain,
        )
    return previous


async def _write_event(
    db: AsyncSession,
    *,
    session_id: str,
    previous: Guarantee,
    current: Guarantee,
    caller: str,
    target: str,
    policy_version: int,
    act_chain: list,
) -> None:
    """The degrade as an ordinary row in the session's timeline.

    ``outcome='allow'`` with no deny reason, because nothing was refused — this records a
    change in what enforcement *means*, not a decision. ``chain_break`` names it so a
    chain query does not mistake it for a hop that lost its parent.
    """
    db.add(
        AuditDecision(
            id=uuid.uuid4(),
            session_id=uuid.UUID(session_id),
            caller=caller,
            acting_agent=None,
            target=target,
            target_kind=target_kind_of(target),
            data_class="-",
            hop=1,
            outcome="allow",
            deny_reason=None,
            recoverable=False,
            enforced=True,
            policy_version=policy_version,
            act_chain=act_chain,
            guarantee_level=current.value,
            chain=None,
            chain_complete=False,
            chain_break="GUARANTEE_DEGRADE",
        )
    )
    await db.flush()
    logger.warning(
        "guarantee level changed for session %s: %s -> %s",
        session_id,
        previous.value,
        current.value,
    )


def consent_only_refusal(level: Guarantee) -> dict | None:
    """What a consent-only deployment answers when asked for a per-hop decision.

    It genuinely cannot supply one — there is no per-hop enforcement in that posture —
    and approximating would be the silent claim the whole field exists to prevent. So it
    declines, in a shape that says why (FR-015, contracts/guarantee-level.md §6).
    """
    if level is not Guarantee.CONSENT_ONLY:
        return None
    return {
        "code": "guarantee_insufficient",
        "message": (
            "this deployment enforces consent and revocation at the edge only; it "
            "cannot make a per-hop decision, and will not approximate one"
        ),
        "details": {"reason": "GUARANTEE_INSUFFICIENT", "guarantee_level": level.value},
    }


__all__ = ["consent_only_refusal", "level_key", "note_level"]
