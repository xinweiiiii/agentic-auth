"""The schema an embedded store is created with: the Alembic head this package was built at.

The migrations are not shipped in the wheel, so the revision is recorded here.
``tests/unit/test_embedded_schema_revision.py`` fails when a new migration lands without this
moving with it. A store created at a different revision is refused rather than half-read.
"""

SCHEMA_REVISION = "0006_audit_deployment"
