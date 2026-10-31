"""``app.*`` → ``agentic_auth.*``, for code written against 0.1.x. Removed in 0.3.0.

0.1.x installed its code as a top-level package named ``app``, which collided with the
application package of nearly every project that installed it. 0.2.0 moved everything to
``agentic_auth``. This package exists only so existing imports keep working while they are
migrated; it is a separate, opt-in install because a top-level ``app`` is exactly the
collision the rename removed.

Every ``app.<x>`` import resolves to the *same module object* as ``agentic_auth.<x>``, so
``isinstance`` checks and module-level state behave as if there were one package — because
there is.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
import warnings
from types import ModuleType

OLD = "app"
NEW = "agentic_auth"
REMOVED_IN = "0.3.0"

_warned: set[str] = set()


def _warn(old: str) -> None:
    # One warning per top-level submodule: `app.sdk` and `app.sdk.client` are one migration.
    top = ".".join(old.split(".")[:2])
    if top in _warned:
        return
    _warned.add(top)
    new = NEW + top[len(OLD) :]
    warnings.warn(
        f"'{top}' is deprecated; import '{new}' (removed in {REMOVED_IN})",
        DeprecationWarning,
        stacklevel=3,
    )


class _AliasFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Answers for ``app.<anything>`` by handing back the ``agentic_auth`` module."""

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if not fullname.startswith(OLD + "."):
            return None
        return importlib.util.spec_from_loader(fullname, self)

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType:
        _warn(spec.name)
        # Returning the existing module: the import system registers it under the old name
        # too, and leaves its own __name__/__spec__ alone because they are already set.
        return importlib.import_module(NEW + spec.name[len(OLD) :])

    def exec_module(self, module: ModuleType) -> None:
        """Already executed under its real name."""


if not any(isinstance(finder, _AliasFinder) for finder in sys.meta_path):
    sys.meta_path.insert(0, _AliasFinder())

_warn(OLD)
