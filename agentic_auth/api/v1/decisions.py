"""``GET /v1/decisions`` — the Phase 2 observe-mode report. **Deprecated.**

Kept for one phase so existing observe-mode tooling keeps working, served by the same
history query as ``GET /v1/audit/decisions`` and accepting Phase 2's filters.
``?enforced=false&outcome=deny`` is still the report proper: everything that would have been
blocked, while nothing was. New callers should use ``/v1/audit/decisions``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from agentic_auth.api.deps import AuditReaderDep, PaginationDep, SessionDep
from agentic_auth.schemas.audit import AuditDecisionPage
from agentic_auth.services.decision_history import history_page

router = APIRouter(prefix="/v1", tags=["decisions"], dependencies=[AuditReaderDep])

OptionalQuery = Annotated[str | None, Query()]


@router.get("/decisions", response_model=AuditDecisionPage, deprecated=True)
async def list_decisions(
    db: SessionDep,
    pagination: PaginationDep,
    session_id: OptionalQuery = None,
    outcome: OptionalQuery = None,
    deny_reason: OptionalQuery = None,
    enforced: OptionalQuery = None,
) -> AuditDecisionPage:
    return await history_page(
        db,
        raw_filters={
            "session_id": session_id,
            "outcome": outcome,
            "deny_reason": deny_reason,
            "enforced": enforced,
        },
        limit=pagination.limit,
        cursor=pagination.cursor,
    )
