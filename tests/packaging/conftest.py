"""Install the built wheels into throwaway environments and look at what they bring.

Everything here runs against ``python -m build`` output, never the editable checkout: an
editable install hides exactly the packaging mistakes these tests exist to catch (0.1.1 shipped
``app/__init__.py`` and nothing under it, and every editable test passed).

Slow and network-bound, so the ``packaging`` marker keeps it out of the default run. CI runs it
as its own job: ``pytest -m packaging tests/packaging``.
"""

from __future__ import annotations

import subprocess
import sys
import venv
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import pytest_asyncio

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.packaging


@pytest_asyncio.fixture(autouse=True)
async def _clean() -> AsyncIterator[None]:
    """Shadows the root conftest's database cleanup: nothing here touches PostgreSQL or Redis,
    and the CI job that runs these has neither."""
    yield


@dataclass(frozen=True)
class Wheels:
    main: Path
    compat: Path


@dataclass(frozen=True)
class Env:
    root: Path

    @property
    def python(self) -> Path:
        return self.root / ("Scripts" if sys.platform == "win32" else "bin") / "python"

    def run(self, code: str, *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        # -I: an isolated interpreter, so the checkout on the current directory or PYTHONPATH
        # can never stand in for the installed wheel.
        return subprocess.run(
            [str(self.python), "-I", "-c", code],
            capture_output=True,
            text=True,
            cwd=cwd,
        )

    def installed(self) -> list[str]:
        out = subprocess.run(
            [str(self.python), "-m", "pip", "list", "--format=freeze"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return [line.split("==")[0].lower() for line in out.splitlines() if line]


def _build(source: Path, outdir: Path) -> Path:
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(outdir), str(source)],
        check=True,
        capture_output=True,
    )
    (wheel,) = outdir.glob("*.whl")
    return wheel


@pytest.fixture(scope="session")
def built_wheels(tmp_path_factory: pytest.TempPathFactory) -> Wheels:
    base = tmp_path_factory.mktemp("wheels")
    return Wheels(
        main=_build(ROOT, base / "main"),
        compat=_build(ROOT / "compat", base / "compat"),
    )


def fresh_venv(where: Path, *requirements: str, find_links: Path | None = None) -> Env:
    """A new virtual environment with ``requirements`` installed and nothing else."""
    venv.create(where, with_pip=True, clear=True)
    env = Env(where)
    if requirements:
        cmd = [str(env.python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check"]
        if find_links is not None:
            cmd += ["--find-links", str(find_links)]
        subprocess.run([*cmd, *requirements], check=True, capture_output=True)
    return env


@pytest.fixture(scope="session")
def venv_factory(tmp_path_factory: pytest.TempPathFactory, built_wheels: Wheels) -> Iterator:
    """``make(extra)`` → an environment with ``authzai[extra]`` from the built wheel, cached
    per extra for the session. ``extra=None`` is the base install."""
    cache: dict[tuple[str | None, bool], Env] = {}

    def make(extra: str | None, *, compat: bool = False) -> Env:
        key = (extra, compat)
        if key not in cache:
            spec = f"{built_wheels.main}[{extra}]" if extra else str(built_wheels.main)
            reqs = [spec, str(built_wheels.compat)] if compat else [spec]
            name = f"venv-{extra or 'base'}{'-compat' if compat else ''}"
            cache[key] = fresh_venv(
                tmp_path_factory.mktemp(name), *reqs, find_links=built_wheels.main.parent
            )
        return cache[key]

    yield make
