"""A file-backed embedded store survives a restart, and fails closed across it (US3).

What survives: pinned manifests and compiled policies, enrollments, the issuer key, and the
audit log. What does not: sessions. Their taint marks and replay records lived in memory and
are gone, so a session from before the restart is refused (``session_superseded``) rather
than honoured with less protection than it had.
"""

from __future__ import annotations

import sqlite3
import stat

import pytest

from agentic_auth.embedded import EmbeddedControlPlane, StoreVersionMismatch
from agentic_auth.sdk import ControlPlaneRejected, ControlPlaneUnavailable
from tests.fixtures.chains import KB_SEARCH, ORCHESTRATOR, chain_docs
from tests.fixtures.discovery.server import RESOURCES

USER = "user:alice"


async def test_state_survives_a_restart_and_old_sessions_do_not(tmp_path) -> None:
    store = tmp_path / "auth.db"
    async with EmbeddedControlPlane.open(chain_docs(), store=store, capabilities=RESOURCES) as cp:
        kid = cp.jwks()["keys"][0]["kid"]
        client = cp.client()
        session = await client.consent(scope=ORCHESTRATOR, user_sub=USER)
        grant, _ = await client.hop(
            session.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal"
        )

    async with EmbeddedControlPlane.open(store=store, capabilities=RESOURCES) as cp:
        client = cp.client()
        # The key, and therefore every grant already issued, is the same.
        assert cp.jwks()["keys"][0]["kid"] == kid
        # The audit log and the chain are intact.
        chain = await client.audit.chain(grant.action_id)
        assert chain["complete"]
        assert len((await client.audit.decisions())["data"]) == 1
        # The session from before the restart is refused, recoverably: consent again.
        with pytest.raises((ControlPlaneRejected, ControlPlaneUnavailable)) as exc:
            await client.hop(
                session.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal"
            )
        assert "session_superseded" in str(exc.value)
        fresh = await client.consent(scope=ORCHESTRATOR, user_sub=USER)
        await client.hop(fresh.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal")
        # The pinned policy compiled before the restart is the one the new session got.
        assert fresh.policy_version == session.policy_version


async def test_the_audit_log_refuses_changes_to_past_entries(tmp_path) -> None:
    store = tmp_path / "auth.db"
    async with EmbeddedControlPlane.open(chain_docs(), store=store, capabilities=RESOURCES) as cp:
        client = cp.client()
        session = await client.consent(scope=ORCHESTRATOR, user_sub=USER)
        await client.hop(session.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal")

    with sqlite3.connect(store) as raw:
        for statement in (
            "UPDATE audit_decisions SET outcome = 'deny'",
            "DELETE FROM audit_decisions",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                raw.execute(statement)


async def test_a_new_durable_store_is_private_to_its_owner(tmp_path) -> None:
    store = tmp_path / "auth.db"
    async with EmbeddedControlPlane.open(store=store):
        pass
    assert stat.S_IMODE(store.stat().st_mode) == 0o600


async def test_a_store_from_another_schema_is_refused(tmp_path) -> None:
    store = tmp_path / "auth.db"
    async with EmbeddedControlPlane.open(store=store):
        pass
    with sqlite3.connect(store) as raw:
        raw.execute("UPDATE embedded_meta SET schema_revision = '0001_manifest_and_dag'")
    with pytest.raises(StoreVersionMismatch) as exc:
        async with EmbeddedControlPlane.open(store=store):
            pass
    assert exc.value.found == "0001_manifest_and_dag"
    assert "export" in str(exc.value).lower()
