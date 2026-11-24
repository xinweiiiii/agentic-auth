"""The schema an embedded store is created with: the Alembic head this package was built at.

The migrations are not shipped in the wheel, so the revision is recorded here.
``tests/unit/test_embedded_schema_revision.py`` fails when a new migration lands without this
moving with it. A store created at a different revision is refused rather than half-read.
"""

SCHEMA_REVISION = "0008_mcp_oauth_baseline"

# Revisions an older store may be at that differ from SCHEMA_REVISION only by new tables, so
# opening one creates the missing tables and moves it forward. Anything not listed here is
# refused rather than guessed at. Add a revision only when the step after it is purely
# additive for the embedded store.
#
# Empty since 0008: it adds columns to sessions and audit_decisions, which creating missing
# tables cannot do, so a 0.2.0 or 0.3.0 store is refused and must be re-created. This is the
# embedded-only exception listed in feature 011's spec (FR-019); server deployments migrate.
ADDITIVE_FROM: frozenset[str] = frozenset()
