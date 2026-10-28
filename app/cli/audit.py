"""``agentic-auth audit export`` — read-only archival of the append-only audit log.

Exports rows older than a cutoff as JSON lines, oldest first. It never deletes anything: a
command that could remove audit rows is a mutation path the runtime must never have. Purging
after an export is a documented, owner-run maintenance step
(https://authzai.dev/how-to/query-a-delegation-chain).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import typer
from rich import print as rprint
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.models import AuditDecision

audit_app = typer.Typer(help="Read and archive the append-only audit log")

EXIT_OK = 0
EXIT_ERROR = 2
EXPORT_BATCH = 1000


def _jsonable(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def serialize(row: AuditDecision) -> dict[str, Any]:
    return {
        column.name: _jsonable(getattr(row, column.name))
        for column in AuditDecision.__table__.columns
    }


async def export_before(database_url: str, before: datetime, out: Path) -> int:
    """Write every row with ``ts < before`` to ``out``, oldest first. Returns the count.

    Pages on ``seq`` so a very large table never loads into memory at once.
    """
    engine = create_async_engine(database_url, poolclass=NullPool)
    count = 0
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            with out.open("w", encoding="utf-8") as handle:
                last_seq = 0
                while True:
                    rows = (
                        (
                            await db.execute(
                                select(AuditDecision)
                                .where(AuditDecision.ts < before, AuditDecision.seq > last_seq)
                                .order_by(AuditDecision.seq)
                                .limit(EXPORT_BATCH)
                            )
                        )
                        .scalars()
                        .all()
                    )
                    if not rows:
                        break
                    for row in rows:
                        handle.write(json.dumps(serialize(row), sort_keys=True) + "\n")
                        count += 1
                    last_seq = rows[-1].seq
    finally:
        await engine.dispose()
    return count


def _parse_cutoff(raw: str) -> datetime | None:
    try:
        cutoff = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return cutoff if cutoff.tzinfo is not None else None


@audit_app.command("export")
def export(
    before: str = typer.Option(
        ..., "--before", help="RFC 3339 cutoff; strictly older rows are exported"
    ),
    out: Path = typer.Option(..., "--out", help="Destination JSON-lines file"),
    database_url: str | None = typer.Option(
        None, "--database-url", help="Defaults to AGENTIC_AUTH_DATABASE_URL"
    ),
) -> None:
    """Export audit rows older than a cutoff. Read-only: never deletes."""
    cutoff = _parse_cutoff(before)
    if cutoff is None:
        rprint(f"[red]--before must be an RFC 3339 timestamp with a timezone, got {before!r}[/red]")
        raise typer.Exit(EXIT_ERROR)
    if not out.parent.is_dir():
        rprint(f"[red]cannot write {out}: directory {out.parent} does not exist[/red]")
        raise typer.Exit(EXIT_ERROR)

    try:
        count = asyncio.run(export_before(database_url or get_settings().database_url, cutoff, out))
    except Exception as exc:
        rprint(f"[red]export failed: {type(exc).__name__}[/red]")
        raise typer.Exit(EXIT_ERROR) from exc

    rprint(f"exported {count} audit rows older than {cutoff.isoformat()} to {out}")
