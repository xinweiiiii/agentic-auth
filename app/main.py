"""FastAPI application factory for the control plane."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from app import observability
from app.api.errors import register_error_handlers
from app.api.v1 import (
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
from app.config import get_settings
from app.db import get_engine, get_sessionmaker
from app.observability import logs, surface
from app.redis import get_redis
from app.services.anchors import AnchorCache
from app.services.metrics import exposition_registry, get_metrics
from app.services.revocation import RevocationService

logger = logging.getLogger(__name__)


@contextlib.asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Rebuild the revoked-agents set from the database, so a flushed Redis can never make
    the control plane more permissive than the table (Phase 4, research.md R12)."""
    try:
        async with get_sessionmaker()() as session:
            await RevocationService(AnchorCache(get_redis())).rebuild(session, get_redis())
    except Exception:  # pragma: no cover - startup without a database (docs builds, tests)
        logger.warning("could not rebuild the revoked-agents set at startup")

    # Telemetry (Phase 6, spec 007). Off by default; `setup` never raises, so a missing
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
        # never touches a request path (research.md R9).
        observability.shutdown()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Agentic Authorization SDK — Control Plane", version="0.1.0", lifespan=_lifespan
    )
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
            user, session or target identities (contracts/metrics.md). The registry is
            resolved per request, so a multi-process collector sees every worker."""
            return Response(generate_latest(exposition_registry()), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()
