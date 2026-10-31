"""``authzai`` and ``authzai-compat`` are released together, at one version.

The version lives in ``agentic_auth.__version__``. compat pins ``authzai==<that version>``, so
a compat wheel built at a stale number could never install next to the release it ships with.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import agentic_auth

ROOT = Path(__file__).resolve().parents[2]


def test_compat_version_and_pin_match_the_package() -> None:
    compat = tomllib.loads((ROOT / "compat" / "pyproject.toml").read_text())["project"]
    assert compat["version"] == agentic_auth.__version__
    assert compat["dependencies"] == [f"authzai=={agentic_auth.__version__}"]


def test_main_version_is_read_from_the_package() -> None:
    main = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "version" in main["project"]["dynamic"]
    assert main["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "agentic_auth.__version__"}
