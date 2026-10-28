"""Shared test fixtures: real DB with per-test truncate, fake discovery, async client.

**The Phase 6 no-regression gate.** The observability
layer is additive and observational by construction, so the strongest evidence it stayed that way
is the set of suites that did *not* have to change. These must keep passing untouched:

    tests/integration/test_audit_before_dispatch.py   no allow dispatches without a record
    tests/integration/test_observe_mode.py            observe mode decides, records, does not block
    tests/integration/test_fail_closed.py             PDP unavailability blocks
    tests/unit/test_pdp_matrix.py                     decision semantics
    tests/unit/test_pdp_taint_matrix.py               taint semantics

and these two are **additive only** — new cases may be appended, no existing case may change:

    tests/integration/test_metrics.py                 the published metric surface
    tests/unit/test_verify_imports.py                 the verifier's pyjwt-only dependency floor

If a change needs to edit an existing case in any of the above, something observational has become
behavioural. Treat that as a design question, not a test to fix.

Baseline at the start of Phase 6: 936 passed, 1 skipped.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

os.environ.setdefault(
    "AGENTIC_AUTH_DATABASE_URL",
    "postgresql+asyncpg://app:app@localhost:5432/agentic_auth",
)
os.environ["AGENTIC_AUTH_ADMIN_TOKEN"] = "test-admin-token"
os.environ["AGENTIC_AUTH_REDIS_URL"] = "redis://localhost:6379/15"

from app.config import get_settings  # noqa: E402
from app.models import Base  # noqa: E402

get_settings.cache_clear()

ADMIN_TOKEN = "test-admin-token"
_TABLES = (
    "agents, manifests, compiled_policies, reconciliation_reports, sessions, audit_decisions, "
    "trust_anchors, transaction_tokens, step_up_grants, sandbox_runs"
)


@pytest_asyncio.fixture(scope="session")
async def _engine() -> AsyncIterator:
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture(scope="session")
def _sessionmaker(_engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(_engine, expire_on_commit=False, autoflush=False)


@pytest_asyncio.fixture(scope="session")
async def writer_engine(_engine) -> AsyncIterator:
    """An engine connected as the least-privileged runtime role (research.md R5).

    Creates ``agentic_auth_writer`` and a login member ``agentic_auth_app`` if absent, and
    applies the same grants migration 0003 does, so append-only can be tested as the
    credentials the service actually runs with — not only as the table owner.
    """
    from sqlalchemy.engine import make_url

    from app.models.audit_decision import WRITER_GRANTS_SQL, WRITER_ROLE_SQL
    from app.models.step_up_grant import WRITER_GRANTS_SQL_0005
    from app.models.transaction_token import WRITER_GRANTS_SQL_0004

    async with _engine.begin() as conn:
        await conn.execute(text(WRITER_ROLE_SQL))
        await conn.execute(
            text(
                "DO $$ BEGIN "
                "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agentic_auth_app') THEN "
                "CREATE ROLE agentic_auth_app LOGIN PASSWORD 'app' IN ROLE agentic_auth_writer; "
                "END IF; END $$"
            )
        )
        for statement in (*WRITER_GRANTS_SQL, *WRITER_GRANTS_SQL_0004, *WRITER_GRANTS_SQL_0005):
            await conn.execute(text(statement))

    url = make_url(get_settings().database_url).set(username="agentic_auth_app", password="app")
    engine = create_async_engine(url, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest.fixture
def flags(monkeypatch):
    """Flip the three Phase 4 controls for one test: ``flags(identity_required=True)``.

    Settings are cached process-wide, so the fixture patches the cached instance and
    restores it afterwards through monkeypatch.
    """
    settings = get_settings()

    def _set(**values):
        for name, value in values.items():
            assert hasattr(settings, name), name
            monkeypatch.setattr(settings, name, value)
        return settings

    return _set


@pytest.fixture
def metrics_registry(monkeypatch):
    """A fresh, isolated metrics set for one test."""
    from prometheus_client import CollectorRegistry

    from app.services import metrics

    current = metrics.build_control_plane_metrics(CollectorRegistry())
    monkeypatch.setattr(metrics, "_current", current)
    return current


@pytest_asyncio.fixture(scope="session")
async def redis_client() -> AsyncIterator:
    from redis.asyncio import from_url

    client = from_url(get_settings().redis_url, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture(autouse=True)
async def _clean(_engine, redis_client) -> AsyncIterator[None]:
    yield
    async with _engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {_TABLES} RESTART IDENTITY CASCADE"))
    await redis_client.flushdb()


@pytest_asyncio.fixture
async def db_session(_sessionmaker) -> AsyncIterator[AsyncSession]:
    async with _sessionmaker() as session:
        yield session


@pytest.fixture
def fake_discovery_app():
    from tests.fixtures.discovery.server import fake_discovery_app

    return fake_discovery_app


@pytest_asyncio.fixture
async def discovery_client(fake_discovery_app) -> AsyncIterator:
    from app.services.discovery import DiscoveryClient

    http = httpx.AsyncClient(transport=ASGITransport(app=fake_discovery_app))
    try:
        yield DiscoveryClient(client=http)
    finally:
        await http.aclose()


@pytest_asyncio.fixture
async def client(_sessionmaker, redis_client, discovery_client) -> AsyncIterator[httpx.AsyncClient]:
    from app.api import service_deps
    from app.db import get_session
    from app.main import create_app
    from app.services.dag_compiler import DagCompiler
    from app.services.manifest_service import ManifestService
    from app.services.reconciler import ReconcilerService

    app = create_app()

    async def _get_session() -> AsyncIterator[AsyncSession]:
        async with _sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def _get_service() -> AsyncIterator[ManifestService]:
        yield ManifestService(
            discovery=discovery_client,
            reconciler=ReconcilerService(),
            compiler=DagCompiler(),
        )

    app.dependency_overrides[get_session] = _get_session
    app.dependency_overrides[service_deps.get_manifest_service] = _get_service
    app.dependency_overrides[service_deps.get_redis_dep] = lambda: redis_client

    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def fake_idp(flags) -> AsyncIterator:
    """The fake human IdP, wired into the control plane's settings for one test.

    The principal binder fetches the JWKS through an httpx transport routed to this ASGI
    app, so no port is opened. Yields the ``FakeIdp`` so a test can mint assertions or take
    the provider down.
    """
    from app.services import principal as principal_module
    from tests.fixtures.idp.server import AUDIENCE, ISSUER, JWKS_URL, build_idp

    app, state = build_idp()
    flags(
        principal_idp_issuer=ISSUER,
        principal_idp_jwks_url=JWKS_URL,
        principal_idp_audience=AUDIENCE,
        principal_binding_claim="agent",
    )
    http = httpx.AsyncClient(transport=ASGITransport(app=app))
    previous = principal_module.jwks_http_client
    principal_module.jwks_http_client = lambda: http
    try:
        yield state
    finally:
        principal_module.jwks_http_client = previous
        await http.aclose()


@pytest.fixture
def principal_assertion_for(fake_idp):
    """``principal_assertion_for("support-agent")`` -> an ID token binding alice to it."""

    def _mint(agent_name: str | None, **kwargs) -> str:
        agent = f"agent://{agent_name}" if agent_name else None
        return fake_idp.mint_id_token(agent=agent, **kwargs)

    return _mint


@pytest_asyncio.fixture
async def resource_stack(client, redis_client, flags):
    """A protected resource guarded by ``app.verify``, bootstrapped from the in-process
    control plane over an httpx transport that can be CUT after bootstrap (SC-008).

    ``build(agents=[...], identity_required=True)`` returns ``(resource_client, recorder,
    verifier)``. The verifier's anchors poll through the same cuttable transport.
    """
    from app.verify import HttpAnchors, HttpJwks, InMemoryReplay, Verifier
    from tests.fixtures.resource.server import build_resource

    class _Cuttable(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.inner = ASGITransport(app=client._transport.app)
            self.cut = False
            self.requests = 0

        async def handle_async_request(self, request):
            if self.cut:
                raise httpx.ConnectError("control plane unreachable (cut)")
            self.requests += 1
            return await self.inner.handle_async_request(request)

    transport = _Cuttable()
    http = httpx.AsyncClient(transport=transport, base_url="http://test")
    verifiers: list = []
    clients: list[httpx.AsyncClient] = []

    async def _build(*, agents: list[str], identity_required: bool = True, freshness: int = 30):
        # A READ-ONLY token, not the admin token: the verifier must need no more than that.
        flags(audit_read_token="resource-reader")
        anchors = HttpAnchors(
            base_url="http://test",
            token="resource-reader",
            agents=agents,
            freshness_seconds=freshness,
            client=http,
        )
        verifier = Verifier(
            issuer_jwks=HttpJwks("http://test/.well-known/jwks.json", client=http),
            anchors=anchors,
            replay=InMemoryReplay(),
            identity_required=identity_required,
            freshness_seconds=freshness,
        )
        await verifier.bootstrap()
        await verifier.close()  # tests drive refresh() explicitly; no background task
        verifiers.append(verifier)
        app, recorder = build_resource(verifier)
        c = httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://resource")
        clients.append(c)
        return c, recorder, verifier

    async def _build_guarded(
        *,
        agents: list[str],
        identity_required: bool = True,
        freshness: int = 30,
        max_body_bytes: int = 1_048_576,
    ):
        """Phase 5: the same verifier, behind ``RequireAgenticAuth`` middleware instead of
        a hand-rolled ``admit()`` call per route."""
        from tests.fixtures.resource_guarded.server import build_guarded_resource

        _, _, verifier = await _build(
            agents=agents, identity_required=identity_required, freshness=freshness
        )
        app, recorder = build_guarded_resource(verifier, max_body_bytes=max_body_bytes)
        c = httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://guarded")
        clients.append(c)
        return c, recorder, verifier

    from types import SimpleNamespace

    yield SimpleNamespace(build=_build, build_guarded=_build_guarded, transport=transport)
    for v in verifiers:
        await v.close()
    for c in clients:
        await c.aclose()
    await http.aclose()


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest_asyncio.fixture
async def register_chain(client, admin_headers):
    """Register the 4-agent delegation chain and return its compiled scope versions.

    Registered leaf-first so each downstream reference resolves at compile time; a
    forward reference would land in ``unresolved_downstream`` instead of ``edges``.
    """
    from tests.fixtures.chains import CHAIN_AGENTS, chain_docs

    async def _register(*, include_kb_edge: bool = True) -> dict[str, int]:
        docs = chain_docs(include_kb_edge=include_kb_edge)
        versions: dict[str, int] = {}
        for name in reversed(CHAIN_AGENTS):
            r = await client.post(
                "/v1/agents",
                headers=admin_headers,
                json={"name": name, "manifest": docs[name]},
            )
            assert r.status_code == 201, (name, r.status_code, r.text)
            versions[name] = r.json()["manifest_version"]
        return versions

    return _register


@pytest_asyncio.fixture
async def consent(client, admin_headers):
    """Consent to a scope and return the parsed response body."""

    async def _consent(scope: str = "orchestrator", user_sub: str = "user:alice", **kwargs):
        r = await client.post(
            "/v1/consent",
            headers=admin_headers,
            json={"scope": scope, "user_sub": user_sub, **kwargs},
        )
        assert r.status_code == 201, (r.status_code, r.text)
        return r.json()

    return _consent


@pytest_asyncio.fixture
async def sidecar_stack(client, redis_client):
    """A sidecar wired to the in-process control plane and a recording upstream.

    Both the PDP and the upstream are ASGI apps behind one httpx client, so the whole
    hop runs in-process with no ports. ``pdp_url`` is a sentinel host that the mounting
    transport routes to the control-plane app.
    """
    import httpx
    from httpx import ASGITransport

    from app.sidecar.app import build_app
    from app.sidecar.config import SidecarConfig, Upstream
    from tests.fixtures.upstream.server import build_upstream

    upstream_app, recorder = build_upstream()

    class _Router(httpx.AsyncBaseTransport):
        """Routes control-plane calls to the FastAPI app and everything else upstream."""

        def __init__(self) -> None:
            self.pdp = ASGITransport(app=client._transport.app)
            self.upstream = ASGITransport(app=upstream_app)
            self.pdp_down = False
            self.upstream_down = False
            # Phase 4: take only the transaction mint down, leaving decide + exchange up.
            self.transaction_down = False

        async def handle_async_request(self, request):
            if request.url.host == "pdp.test":
                if self.pdp_down:
                    raise httpx.ConnectError("PDP is down")
                if self.transaction_down and request.url.path == "/v1/token/transaction":
                    raise httpx.ConnectError("transaction service is down")
                return await self.pdp.handle_async_request(request)
            if self.upstream_down:
                raise httpx.ConnectError("upstream is down")
            return await self.upstream.handle_async_request(request)

    router = _Router()

    default_map = {
        "/kb": Upstream(
            url="http://upstream.test",
            target="mcp://kb.internal/search",
            data_class="kb.public",
        ),
        "/delegate": Upstream(
            url="http://upstream.test",
            target="agent://kb-search",
            data_class="kb.internal",
        ),
        "/bare": Upstream(url="http://upstream.test"),
    }

    def _build(**overrides):
        upstream_map = overrides.pop("upstream_map", default_map)
        config = SidecarConfig(
            pdp_url="http://pdp.test", upstream_map=upstream_map, **overrides
        ).validate()
        http = httpx.AsyncClient(transport=router)
        return build_app(config, client=http)

    clients: list[httpx.AsyncClient] = []

    async def _sidecar_client(**overrides) -> httpx.AsyncClient:
        c = httpx.AsyncClient(
            transport=ASGITransport(app=_build(**overrides)), base_url="http://sidecar"
        )
        clients.append(c)
        return c

    # SimpleNamespace, not a class body: `recorder = recorder` in a class body binds
    # the class-level name and cannot see the enclosing scope.
    from types import SimpleNamespace

    yield SimpleNamespace(recorder=recorder, router=router, client=_sidecar_client)
    for c in clients:
        await c.aclose()


@pytest_asyncio.fixture
async def gateway_stack(client, redis_client):
    """A shared gateway wired to the in-process control plane and a recording upstream.

    Mirrors ``sidecar_stack`` deliberately: the two fixtures differ only where the two
    deployments differ, so a divergence in the tests reflects a divergence in the code
    rather than in the harness.

    ``instances=2`` builds a second app over the SAME Postgres and Redis, for the
    multi-instance tests. No sticky routing is configured anywhere — if a test only
    passes with hops pinned to one instance, that is a correctness bug (research.md R3).
    """
    import httpx
    from app.gateway.app import build_app
    from app.gateway.config import GatewayConfig
    from app.gateway.metrics import build_gateway_metrics
    from httpx import ASGITransport
    from prometheus_client import CollectorRegistry

    from app.sidecar.config import Upstream
    from tests.fixtures.upstream.server import build_upstream

    upstream_app, recorder = build_upstream()

    class _Router(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.pdp = ASGITransport(app=client._transport.app)
            self.upstream = ASGITransport(app=upstream_app)
            self.pdp_down = False
            self.upstream_down = False
            self.transaction_down = False
            # Seconds of artificial delay on every control-plane call, for the
            # decision-deadline test.
            self.pdp_delay = 0.0

        async def handle_async_request(self, request):
            if request.url.host == "pdp.test":
                if self.pdp_down:
                    raise httpx.ConnectError("PDP is down")
                if self.pdp_delay:
                    import anyio

                    await anyio.sleep(self.pdp_delay)
                if self.transaction_down and request.url.path == "/v1/token/transaction":
                    raise httpx.ConnectError("transaction service is down")
                return await self.pdp.handle_async_request(request)
            if self.upstream_down:
                raise httpx.ConnectError("upstream is down")
            return await self.upstream.handle_async_request(request)

    router = _Router()

    default_table = {
        (None, "/kb"): Upstream(
            url="http://upstream.test",
            target="mcp://kb.internal/search",
            data_class="kb.public",
        ),
        (None, "/delegate"): Upstream(
            url="http://upstream.test",
            target="agent://kb-search",
            data_class="kb.internal",
        ),
        (None, "/bare"): Upstream(url="http://upstream.test"),
    }

    registry = CollectorRegistry()
    metrics = build_gateway_metrics(registry)

    def _build(**overrides):
        route_table = overrides.pop("route_table", default_table)
        config = GatewayConfig(
            pdp_url="http://pdp.test", route_table=route_table, **overrides
        ).validate()
        http = httpx.AsyncClient(transport=router)
        return build_app(config, client=http, registry=registry, metrics=metrics)

    clients: list[httpx.AsyncClient] = []

    async def _gateway_client(**overrides) -> httpx.AsyncClient:
        c = httpx.AsyncClient(
            transport=ASGITransport(app=_build(**overrides)), base_url="http://gateway"
        )
        clients.append(c)
        return c

    async def _instances(count: int = 2, **overrides) -> list[httpx.AsyncClient]:
        """Several independent gateway apps over one Postgres and one Redis."""
        return [await _gateway_client(**overrides) for _ in range(count)]

    from types import SimpleNamespace

    yield SimpleNamespace(
        recorder=recorder,
        router=router,
        client=_gateway_client,
        instances=_instances,
        registry=registry,
        metrics=metrics,
    )
    for c in clients:
        await c.aclose()


# ---------------------------------------------------------------------------------------
# Telemetry capture (spec 007). ASGITransport does not run lifespan, so `observability.setup`
# is never called by the `client` fixture — these fixtures do it explicitly, with an in-memory
# exporter in place of OTLP, and reset the module's global state afterwards so one test's
# provider cannot leak into the next.
# ---------------------------------------------------------------------------------------

TELEMETRY_TEST_KEY = "0" * 64


@pytest.fixture
def telemetry(metrics_registry):
    """Enable telemetry for one test and capture what it emits.

    Returns an object with ``spans()`` (every exported span, in end order), ``logs()`` and
    ``metrics``. Pass ``identity_disclosure=True`` or ``allow_sample_ratio=`` to exercise those
    settings.
    """
    import logging
    from types import SimpleNamespace

    from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
    from opentelemetry.sdk._logs.export import InMemoryLogExporter, SimpleLogRecordProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from app import observability
    from app.observability.config import ObservabilityConfig

    span_exporter = InMemorySpanExporter()
    log_exporter = InMemoryLogExporter()
    handlers: list[logging.Handler] = []

    def _enable(**overrides):
        observability._reset_for_tests()
        cfg = ObservabilityConfig.resolve(
            enabled=overrides.pop("enabled", True),
            key=overrides.pop("key", TELEMETRY_TEST_KEY),
            identity_disclosure=overrides.pop("identity_disclosure", False),
            allow_sample_ratio=overrides.pop("allow_sample_ratio", 1.0),
            service_name="control_plane",
        )
        assert not overrides, f"unknown overrides: {sorted(overrides)}"
        # `synchronous_export` swaps the batching processor for a simple one, so a test sees a
        # span the moment it ends with no flush. The RefusalPreservingFilter still wraps it, so
        # the sampling behaviour under test is the real one.
        # install_globally=False: OTel refuses a second set_tracer_provider in one process
        # ("Overriding of current TracerProvider is not allowed"), which would leave every test
        # after the first pointing at a stale global. `observability.tracer()` reads the module's
        # own provider, so the global is not needed.
        observability.setup(
            resolved=cfg,
            install_globally=False,
            metrics=metrics_registry,
            exporter=span_exporter,
            synchronous_export=True,
        )
        provider = LoggerProvider()
        provider.add_log_record_processor(SimpleLogRecordProcessor(log_exporter))
        handler = LoggingHandler(logger_provider=provider)
        logging.getLogger().addHandler(handler)
        handlers.append(handler)
        return cfg

    def _spans():
        return list(span_exporter.get_finished_spans())

    def _logs():
        return list(log_exporter.get_finished_logs())

    def _named(name: str):
        return [s for s in _spans() if s.name == name]

    yield SimpleNamespace(
        enable=_enable,
        spans=_spans,
        logs=_logs,
        named=_named,
        metrics=metrics_registry,
        key=TELEMETRY_TEST_KEY.encode(),
    )

    for h in handlers:
        logging.getLogger().removeHandler(h)
    from app import observability as _obs

    _obs._reset_for_tests()
