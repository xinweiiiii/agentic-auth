"""What each wheel puts at the top level of site-packages (contracts/packaging.md, FR-002).

``authzai`` must ship exactly one import root. A second one, and above all a top-level
``app``, would shadow or be shadowed by the installing project's own package.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.packaging


def _top_level(wheel: Path) -> set[str]:
    with zipfile.ZipFile(wheel) as zf:
        return {name.split("/", 1)[0] for name in zf.namelist()}


def _dist_info(wheel: Path) -> str:
    name, version = wheel.name.split("-")[:2]
    return f"{name}-{version}.dist-info"


def test_main_wheel_ships_only_agentic_auth(built_wheels) -> None:
    assert _top_level(built_wheels.main) == {"agentic_auth", _dist_info(built_wheels.main)}


def test_main_wheel_has_every_subpackage(built_wheels) -> None:
    """The 0.1.1 regression: a wheel with the root package and none of its children. The
    expected set is every package in the source tree, so a new one is covered by default."""
    source = ROOT / "agentic_auth"
    expected = {
        str(init.relative_to(ROOT))
        for init in source.rglob("__init__.py")
        if "__pycache__" not in init.parts
    }
    with zipfile.ZipFile(built_wheels.main) as zf:
        names = set(zf.namelist())
    assert expected - names == set()


# The Phase 5 gateway, boundary adapters and cold start (agentic_auth/gateway, the rungs
# under agentic_auth/boundary, agentic_auth/coldstart) were built on feature branches that
# never merged to the planning repository's main, so the open-source split never carried
# them here. Their console scripts have shipped since 0.1.0 pointing at modules that do not
# exist. Strict: restoring them makes these XPASS and fail, the prompt to delete the marker.
PHASE5_MISSING = pytest.mark.xfail(
    strict=True, reason="Phase 5 enforcement modules never reached this repository"
)


@pytest.mark.parametrize(
    "script",
    [
        "agentic-auth",
        "agentic-auth-sidecar",
        pytest.param("agentic-auth-gateway", marks=PHASE5_MISSING),
        pytest.param("agentic-auth-boundary", marks=PHASE5_MISSING),
    ],
)
def test_every_console_script_resolves(venv_factory, script) -> None:
    code = (
        "import importlib.metadata as m, importlib; "
        f"(ep,) = [e for e in m.entry_points(group='console_scripts') if e.name == {script!r}]; "
        "mod, _, attr = ep.value.partition(':'); "
        "getattr(importlib.import_module(mod), attr)"
    )
    result = venv_factory("server").run(code)
    assert result.returncode == 0, result.stderr[-2000:]


def test_compat_wheel_ships_only_app(built_wheels) -> None:
    assert _top_level(built_wheels.compat) == {"app", _dist_info(built_wheels.compat)}
