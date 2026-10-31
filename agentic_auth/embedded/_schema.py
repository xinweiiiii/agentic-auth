"""The schema an embedded store is created with: the Alembic head this package was built at.

The migrations are not shipped in the wheel, so the revision is recorded here.
``tests/unit/test_embedded_schema_revision.py`` fails when a new migration lands without this
moving with it. A store created at a different revision is refused rather than half-read.
"""

SCHEMA_REVISION = "0007_imported_audit"

# Revisions an older store may be at that differ from SCHEMA_REVISION only by new tables, so
# opening one creates the missing tables and moves it forward. Anything not listed here is
# refused rather than guessed at. Add a revision only when the step after it is purely
# additive for the embedded store.
ADDITIVE_FROM = frozenset(
    {
        # 0007 adds imported_audit, which the embedded store never writes.
        "0006_audit_deployment",
    }
)
