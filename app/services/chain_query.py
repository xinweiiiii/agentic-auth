"""The delegation-chain query — "who authorized this, and through which agents?"

One read: the action's own audit row, joined to its (immutable) session for the root
consent. The chain comes from the row's materialized ``chain`` document, written when the
decision was made; nothing here correlates other decision rows (FR-011). Completeness was
decided at write time too, so the answer cannot depend on what happens to be in the table
when the question is asked.

A legacy row — written before Phase 3 — is still answered, marked incomplete, with every
field that was never captured reported as unavailable rather than inferred (FR-008).

Every query is timed and counted by result, which is how the SLO (p95 < 500 ms, 100% complete)
is observed in production rather than asserted once in a test.
"""

from __future__ import annotations

import time
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.errors import NotFoundError
from app.models import AuditDecision, Session
from app.repositories import transaction_tokens as txn_repo
from app.schemas.audit import (
    ChainBreakRead,
    ChainHop,
    ChainRead,
    RootConsent,
    TransactionFingerprint,
)
from app.services.audit_chain import AGENT_PREFIX, ChainBreak
from app.services.metrics import get_metrics


def _own_hop(row: AuditDecision) -> ChainHop:
    return ChainHop(
        hop=row.hop,
        action_id=row.id,
        acting_agent=row.acting_agent,
        target=row.target,
        target_kind=row.target_kind,
        data_class=row.data_class,
        decision=row.outcome,
        deny_reason=row.deny_reason,
        enforced=row.enforced,
        ts=row.ts,
        taint=row.taint,
        taint_source=row.taint_source,
        privileged=row.privileged,
    )


def _legacy_hops(row: AuditDecision) -> list[ChainHop]:
    """Rebuild what a pre-Phase-3 row can honestly say.

    ``act_chain`` is ``[human, agent at hop 1, ..., agent at hop n-1]`` — verified actor
    names, and nothing else. Earlier hops therefore get their acting agent and no other
    detail; only the row's own hop is known in full.
    """
    earlier = [
        ChainHop(
            hop=index,
            action_id=None,
            acting_agent=str(actor).removeprefix(AGENT_PREFIX),
            target=None,
            target_kind=None,
            data_class=None,
            decision=None,
            deny_reason=None,
            enforced=None,
            ts=None,
            unavailable=True,
        )
        for index, actor in enumerate(row.act_chain[1:], start=1)
        if index < row.hop
    ]
    return [*earlier, _own_hop(row)]


def _break_point(chain: list[ChainHop]) -> int:
    """The first hop whose link is missing: the hop just before the earliest one we hold."""
    return max(1, chain[0].hop - 1)


class ChainQueryService:
    async def get(self, db: AsyncSession, action_id: uuid.UUID) -> ChainRead:
        started = time.perf_counter()
        try:
            chain = await self._read(db, action_id)
        except NotFoundError:
            self._observe("not_found", started)
            raise
        self._observe("complete" if chain.complete else "incomplete", started)
        return chain

    @staticmethod
    def _observe(result: str, started: float) -> None:
        metrics = get_metrics()
        metrics.chain_query_duration.labels(result=result).observe(time.perf_counter() - started)
        metrics.chain_queries.labels(result=result).inc()

    async def _read(self, db: AsyncSession, action_id: uuid.UUID) -> ChainRead:
        result = await db.execute(
            select(AuditDecision, Session)
            .join(Session, Session.id == AuditDecision.session_id)
            .where(AuditDecision.id == action_id)
        )
        found = result.one_or_none()
        if found is None:
            raise NotFoundError(f"no recorded action {action_id}")
        row, session = found

        root = RootConsent(
            user_sub=session.user_sub,
            scope=session.scope,
            consented_at=session.created_at,
            session_id=session.id,
        )

        if row.chain is None:
            hops = _legacy_hops(row)
            reason = ChainBreak(row.chain_break) if row.chain_break else ChainBreak.LEGACY_RECORD
            chain_break: ChainBreakRead | None = ChainBreakRead(at_hop=1, reason=reason)
        else:
            hops = [ChainHop.model_validate(hop) for hop in row.chain]
            if row.privileged:
                # Phase 4: the queried action's own transaction fingerprint, if minted.
                txn = await txn_repo.get_by_action(db, row.id)
                if txn is not None and hops:
                    hops[-1] = hops[-1].model_copy(
                        update={"transaction": TransactionFingerprint.model_validate(txn)}
                    )
            chain_break = (
                None
                if row.chain_complete
                else ChainBreakRead(
                    at_hop=_break_point(hops),
                    reason=ChainBreak(row.chain_break or ChainBreak.PARENT_INCOMPLETE),
                )
            )

        return ChainRead(
            action_id=row.id,
            complete=row.chain_complete,
            chain_break=chain_break,
            root_consent=root,
            policy_version=row.policy_version,
            chain=hops,
        )
