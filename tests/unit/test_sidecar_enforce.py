"""Path resolution in the sidecar's enforcement core.

These live at unit level because the httpx test transport resolves dot segments
client-side, so an integration test cannot present most of the shapes uvicorn will.
"""

from __future__ import annotations

import pytest
from starlette.responses import JSONResponse

from app.sidecar.config import SidecarConfig, Upstream
from app.sidecar.enforce import _has_traversal, _resolve_call


def _config() -> SidecarConfig:
    return SidecarConfig(
        pdp_url="http://pdp",
        upstream_map={
            "/kb": Upstream("http://upstream:9000", "mcp://kb.internal/search", "kb.public")
        },
    ).validate()


@pytest.mark.parametrize(
    "path",
    [
        "/kb/../admin",
        "/kb/../../etc/passwd",
        "/kb/a/../../../root",
        "/kb/./search",
        "/kb/a/./../../secret",
        "/kb\\windows",
    ],
)
def test_paths_that_escape_their_prefix_are_refused(path: str) -> None:
    """Each of these matches the `/kb` prefix, so each would be authorized against the
    `/kb` target — and then delivered somewhere else once the URL is resolved."""
    assert _has_traversal(path) is True

    outcome = _resolve_call(_config(), path, {})

    assert isinstance(outcome, JSONResponse), f"{path!r} resolved to a forwardable target"
    assert outcome.status_code == 403


@pytest.mark.parametrize("path", ["/kb", "/kb/", "/kb/search", "/kb/a..b", "/kb/...", "/kb/a.b"])
def test_ordinary_paths_still_resolve(path: str) -> None:
    """Dots inside a segment are just characters. Only whole `.` / `..` segments escape."""
    assert _has_traversal(path) is False

    outcome = _resolve_call(_config(), path, {})

    assert not isinstance(outcome, JSONResponse), f"{path!r} was wrongly refused"
    prefix, upstream, target, data_class = outcome
    assert prefix == "/kb"
    assert target == "mcp://kb.internal/search"


# ---------------------------------------------------------------------------------------
# The reserved telemetry namespace
#
# `/__agentic/metrics` and `/__agentic/status` are mounted ahead of the catch-all proxy
# route. `upstream_map` prefixes are integrator-chosen, so a mapping that covered the same
# paths would silently take one of the two away — either the PEP becomes unmonitorable, or
# the proxy route stops working. Both are bad enough to refuse at config load.
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "prefix",
    [
        "/__agentic",
        "/__agentic/",
        "/__agentic/metrics",
        "/__agentic/status",
        "/__agentic/anything",
        "/",  # a catch-all would shadow the reserved namespace too
    ],
)
def test_an_upstream_prefix_that_would_shadow_the_telemetry_routes_is_refused(
    prefix: str,
) -> None:
    from app.sidecar.config import SidecarConfig, SidecarConfigError, Upstream

    with pytest.raises(SidecarConfigError, match="reserved"):
        SidecarConfig(
            pdp_url="http://pdp.test",
            upstream_map={prefix: Upstream(url="http://upstream.test")},
        ).validate()


@pytest.mark.parametrize("prefix", ["/kb", "/__agenticx", "/agentic", "/metrics", "/status"])
def test_ordinary_prefixes_are_unaffected(prefix: str) -> None:
    """Including `/metrics` and `/status`: those are exactly why the PEP's own routes live
    under a reserved namespace instead of at the obvious paths."""
    from app.sidecar.config import SidecarConfig, Upstream

    config = SidecarConfig(
        pdp_url="http://pdp.test",
        upstream_map={prefix: Upstream(url="http://upstream.test")},
    ).validate()
    assert prefix in config.upstream_map


def test_telemetry_without_a_key_is_refused_at_startup() -> None:
    """A sidecar that came up exporting unkeyed identity references would be worse than one
    that refuses to start, for the same reason the rest of this config is strict."""
    from app.sidecar.config import SidecarConfig, SidecarConfigError, Upstream

    with pytest.raises(SidecarConfigError, match="telemetry_key"):
        SidecarConfig(
            pdp_url="http://pdp.test",
            upstream_map={"/kb": Upstream(url="http://upstream.test")},
            telemetry_enabled=True,
        ).validate()
