"""Installing authzai next to a project with its own ``app`` package breaks neither (SC-005).

The defect this exists for: 0.1.x installed a top-level ``app``, so ``import app`` in the
customer's own project resolved to whichever of the two came first on ``sys.path``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.packaging

CHECK = "import app, agentic_auth.sdk; assert app.MARKER == 'customer', app.__file__"


def _customer_project(root: Path) -> Path:
    (root / "app").mkdir(parents=True)
    (root / "app" / "__init__.py").write_text('MARKER = "customer"\n')
    return root


def _run_from(env, project: Path):
    # Not -I: a customer runs their app from its directory, with that directory on sys.path.
    return subprocess.run(
        [str(env.python), "-c", CHECK], capture_output=True, text=True, cwd=project
    )


def test_customer_app_and_sdk_both_import(venv_factory, tmp_path) -> None:
    result = _run_from(venv_factory("all"), _customer_project(tmp_path / "proj"))
    assert result.returncode == 0, result.stderr[-2000:]
