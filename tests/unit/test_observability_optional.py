"""The layer is a no-op when the OpenTelemetry extra is absent.

``opentelemetry`` is an optional extra. A deployment that never enables telemetry must not need
it installed, which means **nothing in ``app.observability`` may import it at module scope** —
and that is an easy invariant to break by accident, because the natural way to write
``context.py`` or ``spans.py`` is with a top-level import.

It broke exactly once during implementation: ``context.py`` imported
``opentelemetry.trace.propagation.tracecontext`` at module scope, and because
``app/observability/__init__.py`` imports ``context`` eagerly, importing *anything* in the
package pulled the SDK in. The suite only caught it when the extra was uninstalled.

Rather than depend on someone remembering to run the suite with the extra removed, these tests
block the import in a subprocess. ``tracing.py`` is the one deliberate exception: it subclasses
SDK types, so it cannot be written lazily — and ``__init__`` imports it only inside
``_build_pipeline``, which never runs while telemetry is disabled.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

# Installed into sys.meta_path so any `import opentelemetry...` raises, simulating a deployment
# that never installed the extra.
BLOCKER = """
import sys

class _Blocker:
    def find_module(self, name, path=None):
        return self.find_spec(name, path)
    def find_spec(self, name, path=None, target=None):
        if name == "opentelemetry" or name.startswith("opentelemetry."):
            raise ImportError(f"blocked for test: {name}")
        return None

sys.meta_path.insert(0, _Blocker())
"""


def _run(body: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", BLOCKER + textwrap.dedent(body)],
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_package_imports_without_opentelemetry() -> None:
    result = _run(
        """
        import app.observability as obs
        from app.observability import config, context, ids, spans, surface
        print("IMPORTED")
        """
    )
    assert "IMPORTED" in result.stdout, result.stderr


def test_setup_reports_sdk_missing_and_does_not_raise() -> None:
    result = _run(
        """
        from app.observability import setup
        from app.observability.config import DISABLED_SDK_MISSING, ObservabilityConfig
        cfg = ObservabilityConfig.resolve(
            enabled=True, key="k" * 32, identity_disclosure=False,
            allow_sample_ratio=1.0, service_name="control_plane",
        )
        resolved = setup(resolved=cfg, install_globally=False)
        assert resolved.state == DISABLED_SDK_MISSING, resolved.state
        assert not resolved.enabled
        print("DEGRADED_CLEANLY")
        """
    )
    assert "DEGRADED_CLEANLY" in result.stdout, result.stderr


def test_the_pure_primitives_still_work_without_the_sdk() -> None:
    """Pseudonyms and derived trace ids are standard-library only, so they keep working — which
    is what lets their unit tests run in a deployment without the extra."""
    result = _run(
        """
        from app.observability.ids import pseudonym, session_trace_id
        assert len(pseudonym("agent", "agent://x", b"k" * 32)) == 32
        assert session_trace_id("s-1", b"k" * 32) > 0
        print("PRIMITIVES_OK")
        """
    )
    assert "PRIMITIVES_OK" in result.stdout, result.stderr


def test_the_control_plane_app_still_builds_without_the_sdk() -> None:
    """The end-to-end claim: a deployment that never installs the extra still serves."""
    result = _run(
        """
        from app.main import create_app
        app = create_app()
        assert app.title
        print("APP_BUILDS")
        """
    )
    assert "APP_BUILDS" in result.stdout, result.stderr


def test_tracer_is_a_noop_without_the_sdk() -> None:
    """Call sites use `with tracer().start_as_current_span(...)` unconditionally, so the no-op
    must support the context-manager protocol rather than being None."""
    result = _run(
        """
        from app.observability import tracer
        with tracer().start_as_current_span("authz.decide") as span:
            span.set_attribute("authz.hop", 1)
            assert not span.is_recording()
        print("NOOP_TRACER_OK")
        """
    )
    assert "NOOP_TRACER_OK" in result.stdout, result.stderr
