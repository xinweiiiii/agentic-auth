"""Importing a surface without its extra names the extra (contracts/packaging.md).

The alternative is a bare ``ModuleNotFoundError: No module named 'fastapi'`` raised from three
frames deep in a module the integrator never imported directly, which reads as a broken
package rather than a missing install option.
"""

from __future__ import annotations

import re

import pytest

pytestmark = pytest.mark.packaging

MESSAGE = re.compile(
    r"^ImportError: (agentic_auth\.[\w.]+) needs the '(\w+)' extra: "
    r"pip install 'authzai\[(\w+)\]'$",
    re.M,
)


@pytest.mark.parametrize(
    ("module", "extra"),
    [
        ("agentic_auth.sdk", "client"),
        ("agentic_auth.embedded", "embedded"),
        ("agentic_auth.main", "server"),
        ("agentic_auth.cli", "drift"),
    ],
)
def test_base_install_names_the_missing_extra(venv_factory, module, extra) -> None:
    result = venv_factory(None).run(f"import {module}")
    assert result.returncode != 0
    match = MESSAGE.search(result.stderr)
    assert match, result.stderr[-2000:]
    assert match.group(1) == module
    assert match.group(2) == match.group(3) == extra


def test_client_install_names_the_embedded_extra(venv_factory) -> None:
    """One extra short, not zero: the client has pydantic and httpx but not SQLAlchemy."""
    result = venv_factory("client").run("import agentic_auth.embedded")
    match = MESSAGE.search(result.stderr)
    assert match and match.group(2) == "embedded", result.stderr[-2000:]
