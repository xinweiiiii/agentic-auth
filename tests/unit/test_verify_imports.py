"""``app.verify`` must be importable without the control plane.

A resource server installs this package to guard its tools. If any module under
``app/verify/`` imported FastAPI, SQLAlchemy, Redis or the control plane's own services at
module level, that promise would be broken silently. Checked in a subprocess so nothing
the test process already imported can hide it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

FORBIDDEN = ("app.services", "app.api", "app.models", "fastapi", "sqlalchemy", "redis")

PROBE = r"""
import importlib, pkgutil, sys
import app.verify
for m in pkgutil.iter_modules(app.verify.__path__, "app.verify."):
    importlib.import_module(m.name)
loaded = sorted(n for n in sys.modules if n.startswith(%r))
print("\n".join(loaded))
"""


def test_the_verifier_library_has_a_closed_import_graph() -> None:
    result = subprocess.run(
        [sys.executable, "-c", PROBE % (FORBIDDEN,)],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
        check=True,
    )
    leaked = [line for line in result.stdout.splitlines() if line]
    assert leaked == [], f"app.verify imported the control plane or a heavy dependency: {leaked}"


def test_only_pyjwt_and_cryptography_are_required_for_static_verification() -> None:
    """The Http* stores import httpx lazily; a static deployment never touches it."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, app.verify; assert 'httpx' not in sys.modules, sorted(sys.modules)",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
    )
    assert result.returncode == 0, result.stderr[-2000:]


# ---------------------------------------------------------------------------------------
# Phase 6: the telemetry seam must not widen this floor.
#
# Appended, not edited: the cases above are the Phase 4 contract and stay exactly as they were
# (see the no-regression gate in tests/conftest.py).
# ---------------------------------------------------------------------------------------

PHASE_6_FORBIDDEN = ("opentelemetry", "app.observability", "prometheus_client")


def test_the_telemetry_seam_adds_no_imports() -> None:
    """``Verifier(telemetry=...)`` takes a ``TelemetrySink`` Protocol, so the OTel-backed
    implementation can live in ``app.observability`` without this package importing it."""
    result = subprocess.run(
        [sys.executable, "-c", PROBE % (PHASE_6_FORBIDDEN,)],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
        check=True,
    )
    leaked = [line for line in result.stdout.splitlines() if line]
    assert leaked == [], f"app.verify pulled in telemetry machinery: {leaked}"


def test_the_package_imports_with_only_pyjwt_installed() -> None:
    """The end-to-end claim: block every optional dependency and the package still imports.

    ``prometheus_client`` is blocked too — it is a base dependency of the control plane, but the
    verifier builds its metrics lazily in ``_build_metrics`` so a resource server that supplies
    no registry never needs it.
    """
    blocker = """
import sys

class _Blocker:
    def find_module(self, name, path=None):
        return self.find_spec(name, path)
    def find_spec(self, name, path=None, target=None):
        root = name.split(".")[0]
        if root in {"opentelemetry", "prometheus_client", "fastapi", "sqlalchemy", "redis"}:
            raise ImportError("blocked for test: " + name)
        return None

sys.meta_path.insert(0, _Blocker())

import importlib, pkgutil
import app.verify
for m in pkgutil.iter_modules(app.verify.__path__, "app.verify."):
    importlib.import_module(m.name)
from app.verify import TelemetrySink, Verifier
assert TelemetrySink is not None and Verifier is not None
print("IMPORTED")
"""
    result = subprocess.run(
        [sys.executable, "-c", blocker],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
    )
    assert "IMPORTED" in result.stdout, result.stderr[-2000:]


def test_the_verifier_never_installs_global_telemetry() -> None:
    """``set_tracer_provider`` is process-global and warns-and-ignores on a second call, so a
    library that calls it either hijacks the host's pipeline or silently emits nothing.

    Parsed rather than grepped: the module docstrings explain *why* these are not called, and a
    plain substring search cannot tell an explanation from a call.
    """
    import ast

    installers = {"set_tracer_provider", "set_logger_provider", "set_meter_provider"}
    for path in (Path(__file__).resolve().parents[2] / "app" / "verify").glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            assert name not in installers, (
                f"{path.name} calls {name}(), which would hijack the host's telemetry"
            )


def test_a_sink_that_raises_cannot_break_admission() -> None:
    """Telemetry is fail-open. A resource server must not refuse a legitimate call, or admit an
    illegitimate one, because the integrator's exporter is broken."""
    from app.verify import Verifier

    class _Broken:
        def span(self, name, attributes):  # noqa: ANN001, ANN202
            raise RuntimeError("exporter exploded")

        def event(self, name, attributes):  # noqa: ANN001, ANN202
            raise RuntimeError("exporter exploded")

    class _Admission:
        admitted = True
        reason = None

    verifier = Verifier.__new__(Verifier)
    verifier.telemetry = _Broken()
    # Must not raise.
    verifier._emit(_Admission(), target="mcp://x/y", privileged=False)
