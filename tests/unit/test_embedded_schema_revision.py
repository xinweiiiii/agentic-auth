"""The embedded store's schema revision follows the migrations' head."""

from __future__ import annotations

import re
from pathlib import Path

from agentic_auth.embedded._schema import SCHEMA_REVISION

VERSIONS = Path(__file__).resolve().parents[2] / "migrations" / "versions"


def test_schema_revision_is_the_alembic_head() -> None:
    revisions: dict[str, str | None] = {}
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = re.search(r'^revision = "([^"]+)"', text, re.M)
        down = re.search(r'^down_revision = (?:"([^"]+)"|None)', text, re.M)
        assert rev and down, path
        revisions[rev.group(1)] = down.group(1)
    heads = set(revisions) - {d for d in revisions.values() if d}
    assert heads == {SCHEMA_REVISION}
