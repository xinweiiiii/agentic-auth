"""The opt-in ``app.*`` aliases (compat/, FR-003): same module objects, one warning each.

Each case runs in a fresh interpreter with ``compat/`` on the path. The finder installs itself
into ``sys.meta_path`` process-wide, which must never leak into the rest of the suite.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

COMPAT = Path(__file__).resolve().parents[2] / "compat"


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-W", "always::DeprecationWarning", "-c", code],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(COMPAT)},
    )


def test_alias_is_the_same_module_object() -> None:
    result = _run(
        "import app.sdk, agentic_auth.sdk as new, app.verify, agentic_auth.verify as v\n"
        "assert app.sdk is new and app.verify is v\n"
        "from app.sdk import AgenticAuthClient\n"
        "from agentic_auth.sdk import AgenticAuthClient as A\n"
        "assert AgenticAuthClient is A\n"
    )
    assert result.returncode == 0, result.stderr


def test_one_warning_per_top_level_module() -> None:
    result = _run("import app.sdk, app.sdk.client, app.sdk.errors, app.verify")
    assert result.returncode == 0, result.stderr
    lines = [line for line in result.stderr.splitlines() if "DeprecationWarning" in line]
    messages = sorted(line.split("DeprecationWarning: ", 1)[1] for line in lines)
    assert messages == [
        "'app' is deprecated; import 'agentic_auth' (removed in 0.3.0)",
        "'app.sdk' is deprecated; import 'agentic_auth.sdk' (removed in 0.3.0)",
        "'app.verify' is deprecated; import 'agentic_auth.verify' (removed in 0.3.0)",
    ]


def test_asgi_app_path_still_resolves() -> None:
    """``uvicorn app.main:app`` imports the module by name, then reads the attribute."""
    result = _run(
        "import importlib\n"
        "m = importlib.import_module('app.main')\n"
        "import agentic_auth.main\n"
        "assert m is agentic_auth.main and m.app is agentic_auth.main.app\n"
    )
    assert result.returncode == 0, result.stderr


def test_unknown_submodule_fails_like_the_real_one() -> None:
    result = _run("import app.no_such_module")
    assert "No module named 'agentic_auth.no_such_module'" in result.stderr
