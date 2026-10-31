"""The version has one source: ``agentic_auth.__version__``.

The release workflow refuses to publish when the built wheel's version differs from the tag,
so a second, hand-maintained copy of the number would be a release that cannot ship.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_main_version_is_read_from_the_package() -> None:
    main = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "version" in main["project"]["dynamic"]
    assert main["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "agentic_auth.__version__"}
