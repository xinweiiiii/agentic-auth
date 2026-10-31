"""The embedded control plane's database: SQLite, in a temporary file or a durable one.

The schema is the server's own models (``Base.metadata``), rendered for SQLite by the portable
types in ``agentic_auth/models/types.py``, append-only triggers included. One extra table,
``embedded_meta``, records what created the file and when it was last opened.

Concurrency. Every transaction begins ``IMMEDIATE``, so it holds SQLite's write lock from its
first statement. Two transactions therefore never interleave, which is what makes reading
the audit chain's parent and numbering the next row safe without PostgreSQL's isolation.
Waiters block on ``busy_timeout`` rather than failing. Throughput is a single writer — right
for a development and test control plane, and the reason this is not one for production.

``":memory:"`` is a temporary *file*, deleted on close, not SQLite's ``:memory:``: an in-memory
database lives in one connection, and sharing one connection between concurrent requests
would let their transactions interleave.
"""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Column, DateTime, MetaData, String, Table, Text, event, insert, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import agentic_auth
from agentic_auth.embedded._schema import ADDITIVE_FROM, SCHEMA_REVISION
from agentic_auth.models import Base

MEMORY = ":memory:"
BUSY_TIMEOUT_MS = 5000

_meta = MetaData()
embedded_meta = Table(
    "embedded_meta",
    _meta,
    Column("schema_revision", String(64), nullable=False),
    Column("package_version", String(32), nullable=False),
    Column("created_at", DateTime, nullable=False),
    Column("opened_at", DateTime, nullable=False),
    # Durable stores only. The issuer's signing key, so tokens survive a restart. Acceptable
    # only because embedded mode is development and testing only: the file is mode 0600.
    Column("issuer_private_key", Text, nullable=True),
)


class StoreLocked(RuntimeError):
    """Another process has this store open."""

    def __init__(self, path: Path, pid: int | None) -> None:
        holder = f"process {pid}" if pid else "another process"
        super().__init__(f"embedded store {path} is open in {holder}")
        self.path = path
        self.pid = pid


class StoreVersionMismatch(RuntimeError):
    """The store was created by a package with a different schema."""

    def __init__(self, found: str, expected: str) -> None:
        super().__init__(
            f"embedded store schema is {found!r}, this package needs {expected!r}. "
            "Export it with the version that created it (EmbeddedControlPlane.export) and "
            "start a new store, or open it with that version."
        )
        self.found = found
        self.expected = expected


@dataclass
class StoreHandle:
    path: Path
    durable: bool
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    # When this open happened. For a durable store, every session older than this is
    # superseded (agentic_auth/runtime.py); for a temporary one there is nothing older.
    opened_at: datetime
    issuer_private_key: str | None = None
    _lock: Any = field(default=None, repr=False)
    _tmpdir: tempfile.TemporaryDirectory[str] | None = field(default=None, repr=False)

    async def close(self) -> None:
        await self.engine.dispose()
        if self._lock is not None:
            _release(self._lock)
            self._lock = None
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None


def _engine(path: Path) -> AsyncEngine:
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{path}", connect_args={"timeout": BUSY_TIMEOUT_MS / 1000}
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        # Hand transaction control to the "begin" hook below instead of pysqlite's own
        # deferred BEGIN, which takes the write lock only at the first write.
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        cursor.close()

    @event.listens_for(engine.sync_engine, "begin")
    def _on_begin(connection: Any) -> None:
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


async def open_store(target: str | os.PathLike[str] = MEMORY) -> StoreHandle:
    """Open (and on first use, create) a store. Raises ``StoreLocked`` or
    ``StoreVersionMismatch``; never opens a store it cannot use correctly."""
    tmpdir: tempfile.TemporaryDirectory[str] | None = None
    lock = None
    if os.fspath(target) == MEMORY:
        tmpdir = tempfile.TemporaryDirectory(prefix="agentic-auth-embedded-")
        path, durable = Path(tmpdir.name) / "store.db", False
    else:
        path, durable = Path(target).resolve(), True
        path.parent.mkdir(parents=True, exist_ok=True)
        lock = _acquire(path.with_name(path.name + ".lock"), path)

    created = not path.exists()
    if created and durable:
        # Create it 0600 before SQLite writes anything into it.
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    engine = _engine(path)
    now = datetime.now(UTC)
    try:
        async with engine.begin() as conn:
            if created or not await conn.run_sync(
                lambda c: c.dialect.has_table(c, "embedded_meta")
            ):
                await conn.run_sync(Base.metadata.create_all)
                await conn.run_sync(_meta.create_all)
                await conn.execute(
                    insert(embedded_meta).values(
                        schema_revision=SCHEMA_REVISION,
                        package_version=agentic_auth.__version__,
                        created_at=now.replace(tzinfo=None),
                        opened_at=now.replace(tzinfo=None),
                    )
                )
                key = None
            else:
                row = (await conn.execute(select(embedded_meta))).one()
                if row.schema_revision in ADDITIVE_FROM:
                    # Only new tables since: create them, leave every existing row alone.
                    await conn.run_sync(Base.metadata.create_all)
                elif row.schema_revision != SCHEMA_REVISION:
                    raise StoreVersionMismatch(row.schema_revision, SCHEMA_REVISION)
                await conn.execute(
                    embedded_meta.update().values(
                        opened_at=now.replace(tzinfo=None),
                        schema_revision=SCHEMA_REVISION,
                        package_version=agentic_auth.__version__,
                    )
                )
                key = row.issuer_private_key
    except BaseException:
        await engine.dispose()
        if lock is not None:
            _release(lock)
        if tmpdir is not None:
            tmpdir.cleanup()
        raise

    return StoreHandle(
        path=path,
        durable=durable,
        engine=engine,
        sessionmaker=async_sessionmaker(engine, expire_on_commit=False, autoflush=False),
        opened_at=now,
        issuer_private_key=key,
        _lock=lock,
        _tmpdir=tmpdir,
    )


async def remember_issuer_key(handle: StoreHandle, pem: str) -> None:
    """Durable stores keep the issuer key, so tokens and anchors outlive a restart."""
    if not handle.durable:
        return
    async with handle.engine.begin() as conn:
        await conn.execute(embedded_meta.update().values(issuer_private_key=pem))
    handle.issuer_private_key = pem


# -- single-writer lock --------------------------------------------------------------------
#
# An OS advisory lock on a sidecar file, held for the instance's lifetime. The OS releases it
# when the process dies, so a crashed process never leaves a store permanently locked; the PID
# written into the file is only there to name the holder in the error.


def _acquire(lock_path: Path, store: Path) -> Any:
    handle = open(lock_path, "a+")  # noqa: SIM115 - held open for the store's lifetime
    try:
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.seek(0)
        holder = handle.read().strip()
        handle.close()
        raise StoreLocked(store, int(holder) if holder.isdigit() else None) from None
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def _release(handle: Any) -> None:
    with contextlib.suppress(OSError):
        if sys.platform == "win32":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    handle.close()
