"""FastAPI application factory for the control plane."""

from __future__ import annotations

from agentic_auth._extras import require_extra

require_extra(
    "agentic_auth.main",
    "server",
    "fastapi",
    "sqlalchemy",
    "pydantic_settings",
    "redis",
    "multipart",
)

import contextlib
import logging
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text
from starlette.types import ASGIApp, Receive, Scope, Send

from agentic_auth import observability
from agentic_auth.api.errors import register_error_handlers
from agentic_auth.api.v1 import (
    agents,
    audit,
    authorize,
    consent,
    decisions,
    enrollment,
    identity,
    jwks,
    manifests,
    scopes,
    token,
    transaction,
)
from agentic_auth.config import get_settings
from agentic_auth.db import get_engine, get_sessionmaker
from agentic_auth.observability import logs, surface
from agentic_auth.redis import get_redis
from agentic_auth.runtime import Runtime, use_runtime
from agentic_auth.services.anchors import AnchorCache
from agentic_auth.services.metrics import exposition_registry, get_metrics
from agentic_auth.services.revocation import RevocationService

logger = logging.getLogger(__name__)


@contextlib.asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Rebuild the revoked-agents set from the database, so a flushed Redis can never make
    the control plane more permissive than the table."""
    try:
        async with get_sessionmaker()() as session:
            await RevocationService(AnchorCache(get_redis())).rebuild(session, get_redis())
    except Exception:  # pragma: no cover - startup without a database (docs builds, tests)
        logger.warning("could not rebuild the revoked-agents set at startup")

    # Telemetry. Off by default; `setup` never raises, so a missing
    # collector, a missing OTel extra or a missing telemetry key cannot stop the control plane
    # from serving. Deliberately the opposite posture to the audit log above.
    logs.configure()
    observability.setup(service_name=surface.COMPONENT_CONTROL_PLANE, metrics=get_metrics())
    get_metrics().telemetry_identity_disclosure.set(
        1 if observability.config().identity_disclosure else 0
    )
    try:
        yield
    finally:
        # force_flush happens here and nowhere else: it is the one call that can block, so it
        # never touches a request path.
        observability.shutdown()


class _RuntimeMiddleware:
    """Runs every request of an embedded app inside its own runtime (agentic_auth/runtime.py),
    so the process-wide accessors hand that instance its own database, Redis and keys."""

    def __init__(self, app: ASGIApp, runtime: Runtime) -> None:
        self.app = app
        self.runtime = runtime

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        with use_runtime(self.runtime):
            await self.app(scope, receive, send)


def create_app(runtime: Runtime | None = None) -> FastAPI:
    """The control plane. ``runtime`` is for the embedded control plane only: the app then
    serves that instance and skips the server's startup, which the instance runs itself."""
    app = FastAPI(
        title="Agentic Authorization SDK — Control Plane",
        version="0.1.0",
        lifespan=_lifespan if runtime is None else None,
    )
    if runtime is not None:
        app.add_middleware(_RuntimeMiddleware, runtime=runtime)
    register_error_handlers(app)
    app.include_router(agents.router)
    app.include_router(manifests.router)
    app.include_router(scopes.router)
    app.include_router(consent.router)
    app.include_router(authorize.router)
    app.include_router(token.router)
    app.include_router(transaction.router)
    app.include_router(enrollment.router)
    app.include_router(identity.router)
    app.include_router(decisions.router)
    app.include_router(audit.router)
    app.include_router(jwks.router)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/readyz", tags=["ops"])
    async def readyz() -> dict:
        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        await get_redis().ping()
        return {"status": "ready"}

    if get_settings().metrics_enabled:

        @app.get("/metrics", tags=["ops"], include_in_schema=False)
        async def metrics() -> Response:
            """Prometheus text exposition. Internal network only — labels carry no agent,
            user, session or target identities. The registry is
            resolved per request, so a multi-process collector sees every worker."""
            return Response(generate_latest(exposition_registry()), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()
