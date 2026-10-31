"""The migrated schema and the test schema enforce the same append-only rule.

The trigger and grants exist twice: frozen in migration 0003, and on the model so that
``Base.metadata.create_all`` (which the test suite uses) installs them too. If the two
drift, the tests would be proving a rule production does not have.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from agentic_auth.models import audit_decision, step_up_grant, transaction_token

MIGRATION = (
    Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0003_audit_decisions.py"
)
MIGRATION_0004 = (
    Path(__file__).resolve().parents[2]
    / "migrations"
    / "versions"
    / "0004_identity_taint_transactions.py"
)
MIGRATION_0005 = (
    Path(__file__).resolve().parents[2]
    / "migrations"
    / "versions"
    / "0005_stepup_coldstart_guarantee.py"
)


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _migration() -> ModuleType:
    return _load(MIGRATION, "migration_0003_audit_decisions")


def _migration_0004() -> ModuleType:
    return _load(MIGRATION_0004, "migration_0004_identity_taint_transactions")


def _migration_0005() -> ModuleType:
    return _load(MIGRATION_0005, "migration_0005_stepup_coldstart_guarantee")


def test_append_only_trigger_sql_matches_the_migration() -> None:
    assert _migration().APPEND_ONLY_SQL == audit_decision.APPEND_ONLY_SQL


def test_writer_role_sql_matches_the_migration() -> None:
    assert _migration().WRITER_ROLE_SQL == audit_decision.WRITER_ROLE_SQL


def test_writer_grants_match_the_migration() -> None:
    migration = _migration()
    assert migration.WRITER_GRANTS_SQL == audit_decision.WRITER_GRANTS_SQL
    # The runtime role must never be able to change an audit row.
    audit_grants = [
        g
        for g in migration.WRITER_GRANTS_SQL
        if g.endswith("audit_decisions TO agentic_auth_writer")
    ]
    assert audit_grants == ["GRANT SELECT, INSERT ON audit_decisions TO agentic_auth_writer"]


def test_target_kind_is_derived_from_the_target() -> None:
    assert audit_decision.target_kind_of("agent://kb-search") == "agent"
    assert audit_decision.target_kind_of("mcp://kb.internal/search") == "tool"


# -- Phase 4: transaction_tokens is append-only the same way ---------------------


def test_transaction_tokens_trigger_sql_matches_the_migration() -> None:
    assert _migration_0004().TXN_APPEND_ONLY_SQL == transaction_token.TXN_APPEND_ONLY_SQL


def test_phase_4_writer_grants_match_the_migration() -> None:
    migration = _migration_0004()
    assert migration.WRITER_GRANTS_SQL_0004 == transaction_token.WRITER_GRANTS_SQL_0004
    txn_grants = [
        g
        for g in migration.WRITER_GRANTS_SQL_0004
        if g.endswith("transaction_tokens TO agentic_auth_writer")
    ]
    # The runtime role must never be able to change a transaction fingerprint.
    assert txn_grants == ["GRANT SELECT, INSERT ON transaction_tokens TO agentic_auth_writer"]


# -- Phase 5: step_up_grants is append-only the same way ------------------------


def test_step_up_grants_trigger_sql_matches_the_migration() -> None:
    assert _migration_0005().STEP_UP_APPEND_ONLY_SQL == step_up_grant.STEP_UP_APPEND_ONLY_SQL


def test_phase_5_writer_grants_match_the_migration() -> None:
    migration = _migration_0005()
    assert migration.WRITER_GRANTS_SQL_0005 == step_up_grant.WRITER_GRANTS_SQL_0005
    grant_rows = [g for g in migration.WRITER_GRANTS_SQL_0005 if "step_up_grants" in g]
    # A human's approval is evidence. The runtime role must never be able to change one.
    assert grant_rows == ["GRANT SELECT, INSERT ON step_up_grants TO agentic_auth_writer"]


def test_sandbox_runs_is_updatable_and_step_up_grants_is_not() -> None:
    """A run legitimately transitions running -> completed, so it needs UPDATE. A grant
    never changes, so it must not have it. Asserting the asymmetry keeps a future
    copy-paste from quietly making approvals editable."""
    grants = {
        g.rsplit(" ON ", 1)[1].split(" TO ")[0]: g.split("GRANT ")[1].split(" ON ")[0]
        for g in step_up_grant.WRITER_GRANTS_SQL_0005
    }
    assert grants["step_up_grants"] == "SELECT, INSERT"
    assert grants["sandbox_runs"] == "SELECT, INSERT, UPDATE"
