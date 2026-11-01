"""End-to-end fixtures: one embedded control plane per test, and real tool servers on it.

Everything in ``tests/e2e`` drives a feature the way a customer reaches it: the SDK client,
the enforcement points' own ASGI apps, the resource-side verifier, the CLIs' entry points.
Nothing here imports a service, repository or route from inside the control plane.

It runs on the embedded control plane, so it needs no PostgreSQL, Redis or network, and the
root conftest's database fixtures are shadowed out.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import pytest_asyncio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from agentic_auth.embedded import BASE_URL, EmbeddedControlPlane
from tests.fixtures.discovery.server import RESOURCES

pytestmark = pytest.mark.e2e

#: Where the embedded control plane answers. Enforcement points are configured with it as
#: their `pdp_url`, exactly as a deployment configures its own control plane's URL.
CONTROL_PLANE = BASE_URL


@pytest_asyncio.fixture(autouse=True)
async def _clean() -> AsyncIterator[None]:
    """Shadows the root conftest's PostgreSQL cleanup; every instance here owns its store."""
    yield


@pytest_asyncio.fixture
async def cp() -> AsyncIterator[EmbeddedControlPlane]:
    async with EmbeddedControlPlane.open(capabilities=RESOURCES) as instance:
        yield instance


@dataclass
class ToolServer:
    """A tool host that records what reached it. Mounted at ``https://{host}`` on the
    instance's in-process network, so an enforcement point can forward to it."""

    host: str
    received: list[dict[str, Any]] = field(default_factory=list)

    def app(self) -> Starlette:
        async def handle(request: Request) -> JSONResponse:
            body = await request.body()
            self.received.append(
                {
                    "path": request.url.path,
                    "method": request.method,
                    "authorization": request.headers.get("authorization"),
                    "body": body.decode() if body else "",
                }
            )
            return JSONResponse({"ok": True, "path": request.url.path})

        return Starlette(
            routes=[Route("/{path:path}", handle, methods=["GET", "POST", "PUT", "DELETE"])]
        )


@pytest.fixture
def tool_server(cp: EmbeddedControlPlane):
    """``tool_server("kb.internal")`` mounts a recording tool server and returns it."""

    def _mount(host: str) -> ToolServer:
        server = ToolServer(host)
        cp.mount(host, server.app())
        return server

    return _mount


def asgi_client(app: Any, base_url: str = "http://pep.test") -> httpx.AsyncClient:
    """A client that talks to an enforcement point's ASGI app directly, as an agent's
    egress would talk to the process listening on its port."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base_url)


TELEMETRY_KEY = "e2e-telemetry-key-0123456789abcdef"


@pytest.fixture
def telemetry() -> Iterator[SimpleNamespace]:
    """Turn on OpenTelemetry with in-memory exporters, as `AGENTIC_AUTH_TELEMETRY_*` would.

    Telemetry is process-wide, so it is torn down after the test whatever happens.
    """
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from agentic_auth import observability
    from agentic_auth.observability.config import ObservabilityConfig

    exporter = InMemorySpanExporter()
    observability._reset_for_tests()
    config = ObservabilityConfig.resolve(
        enabled=True,
        key=TELEMETRY_KEY,
        identity_disclosure=False,
        allow_sample_ratio=1.0,
        service_name="control_plane",
    )
    # install_globally=False: OpenTelemetry refuses a second global provider in one process.
    observability.setup(
        resolved=config,
        install_globally=False,
        exporter=exporter,
        synchronous_export=True,
    )
    try:
        yield SimpleNamespace(
            spans=lambda: list(exporter.get_finished_spans()),
            named=lambda name: [s for s in exporter.get_finished_spans() if s.name == name],
        )
    finally:
        observability._reset_for_tests()
        logging.getLogger("agentic_auth").handlers.clear()
