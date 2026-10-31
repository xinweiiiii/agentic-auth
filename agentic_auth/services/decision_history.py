"""The decision history — "show me the pattern", where the chain query is "explain this one".

Query parameters arrive as raw strings and are validated here as one model, so every
invalid filter — including one that is only invalid in combination, like ``since`` after
``until`` — comes back as the same ``422 validation_error`` naming the parameter.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.errors import QueryValidationError
from agentic_auth.repositories import audit_decisions as audit_repo
from agentic_auth.repositories import transaction_tokens as txn_repo
from agentic_auth.schemas.audit import (
    AuditDecisionFilter,
    AuditDecisionListItem,
    AuditDecisionPage,
    AuditPageInfo,
    TransactionFingerprint,
)
from agentic_auth.services.audit_cursor import decode_cursor, encode_cursor


def parse_filters(raw: Mapping[str, str | None]) -> AuditDecisionFilter:
    try:
        return AuditDecisionFilter.model_validate({k: v for k, v in raw.items() if v is not None})
    except ValidationError as exc:
        fields = [
            {
                # A cross-field failure has no location of its own; it is about the range.
                "loc": ["query", str(error["loc"][0]) if error["loc"] else "since"],
                "msg": error["msg"],
            }
            for error in exc.errors()
        ]
        raise QueryValidationError("invalid decision history filter", fields) from exc


async def history_page(
    db: AsyncSession,
    *,
    raw_filters: Mapping[str, str | None],
    limit: int,
    cursor: str | None,
) -> AuditDecisionPage:
    filters = parse_filters(raw_filters)
    position = decode_cursor(cursor) if cursor else None

    rows, has_more, hwm = await audit_repo.list_page(
        db, filters=filters, limit=limit, position=position
    )
    next_cursor = encode_cursor(rows[-1].seq, hwm) if has_more and rows and hwm else None
    # Phase 4: the transaction fingerprint for any privileged allow on this page.
    fingerprints = await txn_repo.get_by_actions(db, [r.id for r in rows if r.privileged])
    items = []
    for row in rows:
        item = AuditDecisionListItem.model_validate(row)
        txn = fingerprints.get(row.id)
        if txn is not None:
            item = item.model_copy(
                update={"transaction": TransactionFingerprint.model_validate(txn)}
            )
        items.append(item)
    return AuditDecisionPage(
        data=items,
        page=AuditPageInfo(next_cursor=next_cursor, limit=limit, as_of_seq=hwm),
    )
