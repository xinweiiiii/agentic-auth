"""Name the missing install option instead of failing three imports deep.

``authzai`` ships one wheel with optional dependency sets (see ``pyproject.toml``). Importing a
surface whose set is not installed would otherwise raise ``No module named 'fastapi'`` from a
module the integrator never imported directly, which reads as a broken package rather than a
missing ``pip install 'authzai[server]'``. The message format is fixed by
contracts/packaging.md and asserted by ``tests/packaging/test_missing_extra.py``.

Stdlib only: this runs before any optional dependency is known to be present.
"""

from __future__ import annotations

import importlib.util


def require_extra(module: str, extra: str, *dependencies: str) -> None:
    """Raise ``ImportError`` naming ``extra`` if any of ``dependencies`` is not importable."""
    for dependency in dependencies:
        if importlib.util.find_spec(dependency) is None:
            raise ImportError(
                f"{module} needs the '{extra}' extra: pip install 'authzai[{extra}]'",
                name=dependency,
            )
