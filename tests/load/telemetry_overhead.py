"""What the telemetry layer costs.

    python -m tests.load.telemetry_overhead --iterations 400

The budget bounds the **telemetry layer's own share** of per-hop decision latency at 5% of p95. It
is measured as an A/B delta — the same workload with ``AGENTIC_AUTH_TELEMETRY_ENABLED`` false
then true — because a single absolute number says nothing: a p95 of 4 ms could be a fast
guardrail with slow telemetry or the reverse.

Two measurements, because one alone is not honest:

**A. The synchronous cost of emitting a decision span**, in isolation and at high iteration
count — resolving the parent context, building and validating the attributes, starting and
ending the span. This is the only part of the layer that runs on a request thread; export is
asynchronous and separately bounded (see
``test_telemetry_fail_open.py::test_a_slow_sink_does_not_add_unbounded_latency``).

**B. The end-to-end delta** across ``POST /v1/authorize`` with telemetry off then on.

B is reported but **not** used as the verdict. Per-hop latency is dominated by Postgres and
Redis round trips — tens of milliseconds against the layer's tens of microseconds — so the
delta sits far below the run-to-run noise floor and routinely comes out *negative*. A negative
"improvement" is the signal that the measurement is noise, not a result, so the verdict comes
from A expressed as a share of the measured per-hop p95.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time
import uuid

TARGET = "mcp://kb.internal/search"
DATA_CLASS = "kb.public"
USER = "user:alice"


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    k = (len(ordered) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


class _NullExporter:
    """Accepts and discards. Keeps the measurement about the synchronous path rather than
    about whatever collector happens to be reachable."""

    def export(self, spans):  # noqa: ANN001, ANN202
        from opentelemetry.sdk.trace.export import SpanExportResult

        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


async def _measure(enabled: bool, iterations: int) -> list[float]:
    """Time `iterations` authorize calls, with telemetry on or off."""
    import os

    os.environ.setdefault(
        "AGENTIC_AUTH_DATABASE_URL", "postgresql+asyncpg://app:app@localhost:5432/agentic_auth"
    )
    os.environ["AGENTIC_AUTH_ADMIN_TOKEN"] = "test-admin-token"
    os.environ["AGENTIC_AUTH_REDIS_URL"] = "redis://localhost:6379/15"

    import httpx
    from httpx import ASGITransport
    from prometheus_client import CollectorRegistry
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    from app import observability
    from app.api import service_deps
    from app.config import get_settings
    from app.db import get_session
    from app.main import create_app
    from app.models import Base
    from app.observability.config import ObservabilityConfig
    from app.services import metrics as metrics_module
    from app.services.dag_compiler import DagCompiler
    from app.services.manifest_service import ManifestService
    from app.services.reconciler import ReconcilerService
    from tests.fixtures.chains import CHAIN_AGENTS, chain_docs

    get_settings.cache_clear()
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)

    from redis.asyncio import from_url

    from app.services.discovery import DiscoveryClient
    from tests.fixtures.discovery.server import fake_discovery_app

    redis = from_url(get_settings().redis_url, decode_responses=True)
    discovery_http = httpx.AsyncClient(transport=ASGITransport(app=fake_discovery_app))
    discovery = DiscoveryClient(client=discovery_http)

    app = create_app()

    async def _get_session():
        async with sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def _get_service():
        yield ManifestService(
            discovery=discovery, reconciler=ReconcilerService(), compiler=DagCompiler()
        )

    app.dependency_overrides[get_session] = _get_session
    app.dependency_overrides[service_deps.get_manifest_service] = _get_service
    app.dependency_overrides[service_deps.get_redis_dep] = lambda: redis

    registry = metrics_module.build_control_plane_metrics(CollectorRegistry())
    metrics_module._current = registry

    observability._reset_for_tests()
    if enabled:
        observability.setup(
            resolved=ObservabilityConfig.resolve(
                enabled=True,
                key="0" * 64,
                identity_disclosure=False,
                allow_sample_ratio=1.0,
                service_name="control_plane",
            ),
            install_globally=False,
            metrics=registry,
            exporter=_NullExporter(),
        )

    samples: list[float] = []
    try:
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://bench"
        ) as client:
            admin = {"Authorization": "Bearer test-admin-token"}
            # Leaf-first, so each downstream reference resolves at compile time.
            docs = chain_docs()
            for name in reversed(CHAIN_AGENTS):
                r = await client.post(
                    "/v1/agents", headers=admin, json={"name": name, "manifest": docs[name]}
                )
                assert r.status_code == 201, (name, r.status_code, r.text[:300])

            for _ in range(iterations):
                r = await client.post(
                    "/v1/consent",
                    headers=admin,
                    json={"user_sub": USER, "scope": "orchestrator"},
                )
                session = r.json()
                started = time.perf_counter()
                resp = await client.post(
                    "/v1/authorize",
                    headers={"Authorization": f"Bearer {session['root_grant']}"},
                    json={
                        "session_id": session["session_id"],
                        "caller": USER,
                        "target": TARGET,
                        "data_class": DATA_CLASS,
                        "guarantee": "full",
                    },
                )
                samples.append(time.perf_counter() - started)
                assert resp.status_code == 200, resp.text
    finally:
        observability._reset_for_tests()
        await discovery_http.aclose()
        await redis.aclose()
        await engine.dispose()
    return samples


def _measure_span_emission(iterations: int) -> list[float]:
    """Measurement A: the synchronous span-emission path, with nothing else in the way."""
    from prometheus_client import CollectorRegistry

    from app import observability
    from app.observability import surface
    from app.observability.config import ObservabilityConfig
    from app.services.metrics import build_control_plane_metrics

    registry = build_control_plane_metrics(CollectorRegistry())
    config = ObservabilityConfig.resolve(
        enabled=True,
        key="0" * 64,
        identity_disclosure=False,
        allow_sample_ratio=1.0,
        service_name="control_plane",
    )
    observability._reset_for_tests()
    observability.setup(
        resolved=config,
        install_globally=False,
        metrics=registry,
        exporter=_NullExporter(),
    )
    tracer = observability.tracer()
    act_chain = [{"sub": USER}, {"agent": "agent://orchestrator"}]
    samples: list[float] = []
    try:
        for i in range(iterations):
            session_id = str(uuid.UUID(int=i))
            started = time.perf_counter()
            parent = observability.extract_parent(
                {}, session_id=session_id, key=config.key, metrics=registry
            )
            attributes = observability.decision_attributes(
                config,
                action_id=session_id,
                session_id=session_id,
                hop=2,
                outcome="deny",
                deny_reason="EDGE_NOT_IN_DAG",
                recoverable=False,
                enforced=True,
                target_kind="tool",
                data_class="kb.public",
                privileged=False,
                taint="trusted_internal",
                policy_version=1,
                acting_agent="agent://kb-search",
                act_chain=act_chain,
                taint_source=None,
            )
            with tracer.start_as_current_span(
                surface.SPAN_DECIDE,
                context=parent,
                attributes=attributes,
                record_exception=False,
            ):
                pass
            samples.append(time.perf_counter() - started)
    finally:
        observability._reset_for_tests()
    return samples


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=400, help="authorize calls per arm (B)")
    parser.add_argument("--emissions", type=int, default=20_000, help="span emissions (A)")
    parser.add_argument("--budget", type=float, default=5.0, help="max overhead, percent of p95")
    args = parser.parse_args(argv)

    def row(label: str, s: list[float]) -> None:
        print(
            f"  {label:22} p50={percentile(s, 0.50) * 1000:8.4f}ms  "
            f"p95={percentile(s, 0.95) * 1000:8.4f}ms  "
            f"mean={statistics.mean(s) * 1000:8.4f}ms"
        )

    # ---- A: the synchronous cost, which is what the budget bounds -------------------------
    print(f"A. span emission, {args.emissions:,} iterations\n")
    emission = _measure_span_emission(args.emissions)
    row("span emission", emission)
    emit_p95 = percentile(emission, 0.95)

    # ---- B: end to end, reported for context only -------------------------------------
    print(f"\nB. POST /v1/authorize, {args.iterations} calls per arm\n")
    off = asyncio.run(_measure(enabled=False, iterations=args.iterations))
    on = asyncio.run(_measure(enabled=True, iterations=args.iterations))
    row("telemetry off", off)
    row("telemetry on", on)

    p95_off = percentile(off, 0.95)
    delta = percentile(on, 0.95) - p95_off
    e2e_pct = (delta / p95_off * 100) if p95_off else 0.0

    share = (emit_p95 / p95_off * 100) if p95_off else 0.0

    print()
    print(f"  per-hop p95 (telemetry off):  {p95_off * 1000:8.4f}ms")
    print(f"  span emission p95:            {emit_p95 * 1000:8.4f}ms")
    print(f"  telemetry share of per-hop:   {share:8.4f}%   <- the verdict")
    print(f"  budget:                       {args.budget:8.1f}%")
    print()
    print(f"  end-to-end p95 delta:         {delta * 1000:+8.4f}ms ({e2e_pct:+.2f}%)")
    if delta < 0:
        print(
            "    (negative, i.e. below the noise floor: per-hop latency is dominated by\n"
            "     Postgres and Redis round trips, so B cannot resolve a cost this small.\n"
            "     Reported for context; the verdict comes from A.)"
        )
    print()
    if share <= args.budget:
        print(f"PASS: the telemetry layer's share is {share:.4f}% of per-hop p95.")
        return 0
    print(f"FAIL: {share:.4f}% exceeds the {args.budget:.1f}% budget.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
