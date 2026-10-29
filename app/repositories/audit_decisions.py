"""Append-only persistence for ``audit_decisions``.

Append and read only. There is deliberately no update or delete function in this module —
and if one were added, the database would refuse to run it (``app/models/audit_decision.py``).

``append`` takes every chain field explicitly, with no defaults: a row that silently claimed
a chain state nobody computed would be exactly the kind of record this table exists to rule
out. :class:`app.services.audit.AuditService` is its only caller.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession as DbSession

from app.models import AuditDecision
from app.models.audit_decision import target_kind_of
from app.schemas.audit import AuditDecisionFilter


async def append(
    db: DbSession,
    *,
    action_id: uuid.UUID,
    ts: datetime,
    session_id: uuid.UUID,
    caller: str,
    target: str,
    data_class: str,
    hop: int,
    outcome: str,
    deny_reason: str | None,
    recoverable: bool,
    enforced: bool,
    taint: str | None,
    taint_source: str | None,
    privileged: bool,
    policy_version: int,
    act_chain: list[Any],
    acting_agent: str | None,
    subject_jti: str | None,
    parent_action_id: uuid.UUID | None,
    chain: list[dict[str, Any]] | None,
    chain_complete: bool,
    chain_break: str | None,
    guarantee_level: str | None = None,
    step_up_ref: uuid.UUID | None = None,
) -> AuditDecision:
    row = AuditDecision(
        id=action_id,
        ts=ts,
        session_id=session_id,
        caller=caller,
        acting_agent=acting_agent,
        target=target,
        target_kind=target_kind_of(target),
        data_class=data_class,
        hop=hop,
        outcome=outcome,
        deny_reason=deny_reason,
        recoverable=recoverable,
        enforced=enforced,
        taint=taint,
        taint_source=taint_source,
        privileged=privileged,
        policy_version=policy_version,
        act_chain=act_chain,
        subject_jti=subject_jti,
        guarantee_level=guarantee_level,
        step_up_ref=step_up_ref,
        parent_action_id=parent_action_id,
        chain=chain,
        chain_complete=chain_complete,
        chain_break=chain_break,
    )
    db.add(row)
    await db.flush()
    return row


async def get(db: DbSession, action_id: uuid.UUID) -> AuditDecision | None:
    return await db.get(AuditDecision, action_id)


async def get_committed_allow(db: DbSession, action_id: uuid.UUID) -> AuditDecision | None:
    """The row a token exchange spends.

    Called from the exchange's own request, whose session can only see committed rows — so
    a decision whose commit never landed is simply not found here. The caller distinguishes
    "not found" from "found, but a deny".
    """
    return await db.get(AuditDecision, action_id)


async def list_page(
    db: DbSession,
    *,
    filters: AuditDecisionFilter,
    limit: int,
    position: tuple[int, int] | None,
) -> tuple[list[AuditDecision], bool, int | None]:
    """One page, newest first, by insertion sequence. Returns ``(rows, has_more, hwm)``.

    ``position`` is ``(before, hwm)`` from a cursor, or ``None`` for the first page, which
    fixes the high-water mark. Ordering by ``seq`` rather than ``ts`` matters: ``ts`` is
    taken before commit, so commit order and ``ts`` order can disagree, and a keyset on
    ``ts`` can skip a row that commits late.
    """
    if position is None:
        hwm = await db.scalar(select(func.max(AuditDecision.seq)))
        if hwm is None:
            return [], False, None
        before = hwm + 1
    else:
        before, hwm = position

    stmt = (
        select(AuditDecision)
        .where(AuditDecision.seq <= hwm, AuditDecision.seq < before)
        .order_by(AuditDecision.seq.desc())
        .limit(limit + 1)
    )
    if filters.session_id is not None:
        stmt = stmt.where(AuditDecision.session_id == filters.session_id)
    if filters.agent is not None:
        stmt = stmt.where(AuditDecision.acting_agent == filters.agent)
    if filters.outcome is not None:
        stmt = stmt.where(AuditDecision.outcome == filters.outcome)
    if filters.deny_reason is not None:
        stmt = stmt.where(AuditDecision.deny_reason == filters.deny_reason.value)
    if filters.enforced is not None:
        stmt = stmt.where(AuditDecision.enforced == filters.enforced)
    if filters.target_kind is not None:
        stmt = stmt.where(AuditDecision.target_kind == filters.target_kind)
    if filters.since is not None:
        stmt = stmt.where(AuditDecision.ts >= filters.since)
    if filters.until is not None:
        stmt = stmt.where(AuditDecision.ts <= filters.until)
    if filters.taint is not None:
        stmt = stmt.where(AuditDecision.taint == filters.taint)
    if filters.privileged is not None:
        stmt = stmt.where(AuditDecision.privileged == filters.privileged)

    rows = list((await db.execute(stmt)).scalars().all())
    return rows[:limit], len(rows) > limit, hwm
