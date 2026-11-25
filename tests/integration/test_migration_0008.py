"""Migration 0008 upgrades, downgrades and upgrades again on PostgreSQL (feature 011).

The rest of the suite builds its schema with ``create_all``, so without this nothing runs the
migration a deployment actually applies. It runs in a throwaway database so it can never
disturb the suite's own schema.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from agentic_auth.config import get_settings

ROOT = Path(__file__).resolve().parents[2]


def _alembic(url: str, *args: str) -> None:
    env = {**os.environ, "AGENTIC_AUTH_DATABASE_URL": url}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]


@pytest.fixture
async def scratch_database():
    base = make_url(get_settings().database_url)
    name = f"aa_migrations_{uuid.uuid4().hex[:8]}"
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await admin.dispose()


async def _columns(url: str, table: str) -> set[str]:
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = :t"),
            {"t": table},
        )
        names = {r[0] for r in rows}
    await engine.dispose()
    return names


async def test_0008_round_trips_and_keeps_audit_append_only(scratch_database) -> None:
    _alembic(scratch_database, "upgrade", "head")
    assert {"principal_source", "client_id", "subject_token_hash"} <= await _columns(
        scratch_database, "sessions"
    )
    assert {"principal_source", "client_id"} <= await _columns(scratch_database, "audit_decisions")
    assert await _columns(scratch_database, "agent_clients")

    _alembic(scratch_database, "downgrade", "0007_imported_audit")
    assert "principal_source" not in await _columns(scratch_database, "sessions")
    assert not await _columns(scratch_database, "agent_clients")

    _alembic(scratch_database, "upgrade", "head")

    engine = create_async_engine(scratch_database)
    try:
        async with engine.connect() as conn:
            trigger = await conn.execute(
                text("SELECT 1 FROM pg_trigger WHERE tgname = 'audit_decisions_no_update_delete'")
            )
            assert trigger.scalar() == 1
            index = await conn.execute(
                text("SELECT indexdef FROM pg_indexes WHERE indexname = 'uq_agent_clients_active'")
            )
            assert "WHERE (removed_at IS NULL)" in index.scalar()
    finally:
        await engine.dispose()
