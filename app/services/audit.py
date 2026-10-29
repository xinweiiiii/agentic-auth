"""Recording decisions — the audit write path.

Every decision passes through :meth:`AuditService.record`, and ``record`` **commits before it
returns**. That ordering is the guarantee, and it is deliberately not left to the request
session's teardown. On FastAPI 0.141 a ``yield`` dependency's exit code runs *after* the
response has been sent, so a commit placed
there lets an allow reach the sidecar before its row exists — and if that commit then fails,
the call has already left with no record.

A failure never raises out of here. It returns ``recorded=False`` and the caller decides
what that means: a call that would leave the host is refused (``AUDIT_UNAVAILABLE``), and a
deny stays a deny.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.audit_decision import AuditDecision, target_kind_of
from app.observability import logs, surface
from app.repositories import audit_decisions as audit_repo
from app.services.audit_chain import ChainEntry, ChainResult, ParentSnapshot, extend_chain
from app.services.metrics import get_metrics
from app.services.pdp import Decision
from app.services.tokens.profile import VerifiedToken

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RecordResult:
    """The action id when the row committed, ``None`` when it did not.

    Holds the id rather than the ORM row on purpose: after a rollback the row is expired,
    and touching it would try to lazy-load on an async session.
    """

    action_id: uuid.UUID | None
    # The parent row's chain document, when one was loaded. Phase 4's taint propagation
    # reads ancestor `subject_jti`s off it without a second query.
    parent_chain: list[dict[str, Any]] | None = None

    @property
    def recorded(self) -> bool:
        return self.action_id is not None


def _normalized_session_id(session_id: str) -> str:
    try:
        return str(uuid.UUID(session_id))
    except (ValueError, TypeError, AttributeError):
        return session_id


def _snapshot(row: AuditDecision) -> ParentSnapshot:
    return ParentSnapshot(
        action_id=str(row.id),
        session_id=str(row.session_id),
        hop=row.hop,
        outcome=row.outcome,
        target=row.target,
        chain=row.chain,
        chain_complete=row.chain_complete,
    )


class AuditService:
    def __init__(self, *, write_timeout_seconds: float | None = None) -> None:
        seconds = (
            write_timeout_seconds
            if write_timeout_seconds is not None
            else get_settings().audit_write_timeout_seconds
        )
        self._timeout_ms = max(1, int(seconds * 1000))

    async def record(
        self,
        db: AsyncSession,
        *,
        session_id: str,
        caller: str,
        target: str,
        data_class: str,
        decision: Decision,
        enforced: bool,
        taint: str | None,
        policy_version: int,
        token: VerifiedToken,
        taint_source: str | None = None,
        privileged: bool = False,
        guarantee_level: str | None = None,
        step_up_ref: uuid.UUID | None = None,
    ) -> RecordResult:
        action_id = uuid.uuid4()
        ts = datetime.now(UTC)
        try:
            # Bound the whole append. An allow whose record cannot land in time is refused,
            # not dispatched while the write is still pending.
            await db.execute(text(f"SET LOCAL statement_timeout = {self._timeout_ms}"))

            parent: ParentSnapshot | None = None
            if token.action_id is not None:
                parent_row = await audit_repo.get(db, uuid.UUID(token.action_id))
                parent = _snapshot(parent_row) if parent_row is not None else None

            entry = ChainEntry(
                hop=decision.hop,
                action_id=str(action_id),
                acting_agent=token.holder,
                target=target,
                target_kind=target_kind_of(target),
                data_class=data_class,
                decision=decision.outcome,
                deny_reason=decision.reason.value if decision.reason else None,
                enforced=enforced,
                ts=ts.isoformat(),
                subject_jti=token.jti,
                taint=taint,
                taint_source=taint_source,
                privileged=privileged,
            )
            chain = extend_chain(
                parent,
                entry,
                session_id=_normalized_session_id(session_id),
                token_action_id=token.action_id,
                token_next_hop=token.next_hop,
                token_act_chain=token.act_chain,
            )

            await audit_repo.append(
                db,
                action_id=action_id,
                ts=ts,
                session_id=uuid.UUID(session_id),
                caller=caller,
                target=target,
                data_class=data_class,
                hop=decision.hop,
                outcome=decision.outcome,
                deny_reason=entry.deny_reason,
                recoverable=decision.recoverable,
                enforced=enforced,
                taint=taint,
                taint_source=taint_source,
                privileged=privileged,
                policy_version=policy_version,
                act_chain=token.act_chain,
                acting_agent=token.holder,
                subject_jti=token.jti,
                # Only a parent that exists can be referenced; a dangling id is recorded as
                # PARENT_NOT_FOUND in `chain_break` instead.
                parent_action_id=uuid.UUID(parent.action_id) if parent is not None else None,
                chain=chain.chain,
                chain_complete=chain.complete,
                chain_break=chain.break_reason.value if chain.break_reason else None,
                # Phase 5. Reported by the enforcement point; recorded verbatim so the row
                # says what actually enforced it. NULL only on a legacy row.
                guarantee_level=guarantee_level,
                step_up_ref=step_up_ref,
            )
            await self._commit(db)
        except Exception as exc:
            # Never the token, never the SQL parameters: the error type is enough to page on.
            # The single most important operational record in the system: an uncommitted
            # audit row means a call was blocked for lack of evidence. `target` stays out of
            # the fields — it is an identity, and identities belong behind the audit-reader
            # check; the session id is the handle an operator uses to find the rest.
            logger.error(
                "audit record failed; the call will be refused rather than dispatched",
                extra=logs.fields(
                    surface.COMPONENT_CONTROL_PLANE,
                    session_id=session_id,
                    hop=decision.hop,
                    error_type=type(exc).__name__,
                ),
            )
            with contextlib.suppress(Exception):
                await db.rollback()
            get_metrics().audit_write_failures.labels(outcome=decision.outcome).inc()
            return RecordResult(action_id=None)

        self._count_recorded(decision, enforced=enforced, target=target, chain=chain)
        return RecordResult(
            action_id=action_id, parent_chain=parent.chain if parent is not None else None
        )

    @staticmethod
    def _count_recorded(
        decision: Decision, *, enforced: bool, target: str, chain: ChainResult
    ) -> None:
        """Counted only once durable — a metric must never claim a decision the log lacks."""
        metrics = get_metrics()
        metrics.decisions.labels(
            outcome=decision.outcome,
            enforced=str(enforced).lower(),
            target_kind=target_kind_of(target),
        ).inc()
        # Positional: `break` is a Python keyword, so it cannot be passed by name.
        metrics.chain_writes.labels(
            str(chain.complete).lower(),
            chain.break_reason.value if chain.break_reason else "none",
        ).inc()

    async def _commit(self, db: AsyncSession) -> None:
        """Separate so tests can make the audit store fail, or lie, at exactly this step."""
        await db.commit()
