"""Column types and DDL that mean the same thing on PostgreSQL and SQLite.

PostgreSQL is the control plane's database. SQLite is the embedded control plane's
(``agentic_auth.embedded``): the same models, the same repositories, the same services, in
one process with no server. Every type here renders *exactly* the PostgreSQL DDL it replaced,
so the server schema and its migrations are unchanged; only the SQLite rendering is new.

The three things SQLite does not do natively, and what stands in for each:

- ``JSONB`` and ``ARRAY`` — JSON text.
- ``timestamptz`` — SQLite keeps no offset, so a stored UTC value comes back naive and then
  fails every comparison against ``datetime.now(UTC)``. Values are normalised to UTC going in
  and re-attached to UTC coming out.
- Append-only enforcement — a ``BEFORE UPDATE``/``BEFORE DELETE`` trigger that aborts, the
  SQLite counterpart of the PL/pgSQL triggers in migrations 0003–0005.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DDL, JSON, DateTime, Uuid, event
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.engine import Dialect
from sqlalchemy.sql import FromClause
from sqlalchemy.types import TypeDecorator, TypeEngine

PortableJSON = JSON().with_variant(JSONB(), "postgresql")


class PortableArray(TypeDecorator[list[Any]]):
    """``ARRAY(item_type)`` on PostgreSQL; a JSON list elsewhere. UUID items round-trip."""

    impl = JSON
    cache_ok = True

    def __init__(self, item_type: TypeEngine[Any] | type[TypeEngine[Any]]) -> None:
        super().__init__()
        self.item_type = item_type() if isinstance(item_type, type) else item_type

    def load_dialect_impl(self, dialect: Dialect) -> TypeEngine[Any]:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(ARRAY(self.item_type))
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value: list[Any] | None, dialect: Dialect) -> Any:
        if value is None or dialect.name == "postgresql":
            return value
        return [str(item) if isinstance(item, uuid.UUID) else item for item in value]

    def process_result_value(self, value: Any, dialect: Dialect) -> list[Any] | None:
        if value is None or dialect.name == "postgresql":
            return value
        if isinstance(self.item_type, Uuid):
            return [uuid.UUID(item) for item in value]
        return list(value)


class _UTCDateTime(TypeDecorator[datetime]):
    """SQLite only: stores naive UTC, returns aware UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None or value.tzinfo is None:
            return value
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


TZDateTime = DateTime(timezone=True).with_variant(_UTCDateTime(), "sqlite")


def install_append_only(table: FromClause, postgresql: tuple[str, ...]) -> None:
    """Attach append-only enforcement to ``table`` for whichever dialect creates it.

    ``postgresql`` is the frozen PL/pgSQL from the migrations (tests/unit/test_audit_ddl.py
    holds the two equal). The SQLite triggers are generated: same table, same refusal.
    """
    for statement in postgresql:
        event.listen(table, "after_create", DDL(statement).execute_if(dialect="postgresql"))
    name = table.name  # type: ignore[attr-defined]  # a mapped class's __table__ is a Table
    for op in ("UPDATE", "DELETE"):
        sqlite = (
            f"CREATE TRIGGER {name}_no_{op.lower()} BEFORE {op} ON {name} "
            f"BEGIN SELECT RAISE(ABORT, '{name} is append-only'); END"
        )
        event.listen(table, "after_create", DDL(sqlite).execute_if(dialect="sqlite"))
