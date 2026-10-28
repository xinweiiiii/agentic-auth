"""``/v1/audit`` — the read-only audit plane.

Every route requires an audit-reader bearer (the dedicated reader token or the admin token).
No route here writes: audit rows are created only by the decision path, and the database
refuses to change them afterwards.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import AuditReaderDep, PaginationDep, SessionDep
from app.api.service_deps import ChainQueryServiceDep
from app.schemas.audit import AuditDecisionPage, ChainRead
from app.services.decision_history import history_page

router = APIRouter(prefix="/v1/audit", tags=["audit"], dependencies=[AuditReaderDep])

# Filters are accepted as strings and validated together in the service, so a bad value
# and a bad combination produce the same error shape.
OptionalQuery = Annotated[str | None, Query()]


@router.get("/actions/{action_id}/chain", response_model=ChainRead)
async def get_chain(
    action_id: uuid.UUID, db: SessionDep, chains: ChainQueryServiceDep
) -> ChainRead:
    """The full delegation chain for one recorded action, back to the consenting human."""
    return await chains.get(db, action_id)


@router.get("/decisions", response_model=AuditDecisionPage)
async def list_decisions(
    db: SessionDep,
    pagination: PaginationDep,
    session_id: OptionalQuery = None,
    agent: OptionalQuery = None,
    outcome: OptionalQuery = None,
    deny_reason: OptionalQuery = None,
    enforced: OptionalQuery = None,
    target_kind: OptionalQuery = None,
    since: OptionalQuery = None,
    until: OptionalQuery = None,
    taint: OptionalQuery = None,
    privileged: OptionalQuery = None,
) -> AuditDecisionPage:
    """Filtered decision history, newest first, stable under concurrent appends."""
    return await history_page(
        db,
        raw_filters={
            "session_id": session_id,
            "agent": agent,
            "outcome": outcome,
            "deny_reason": deny_reason,
            "enforced": enforced,
            "target_kind": target_kind,
            "since": since,
            "until": until,
            "taint": taint,
            "privileged": privileged,
        },
        limit=pagination.limit,
        cursor=pagination.cursor,
    )
