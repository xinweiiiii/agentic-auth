"""The shared gateway — one choke point, the same decision core (FR-001..FR-006).

A reverse proxy, like the sidecar: the agent's tool base URL points here. Unlike the
sidecar, one instance serves many agents, so three things differ and **only** three:

1. **The route table is shared and agent-keyed.** Resolution happens in
   :mod:`agentic_auth.gateway.resolve` and the result is handed to ``enforce()``.
2. **Identity is relayed, never minted.** A gateway holding every agent's signing key
   would be the one component able to impersonate them all — precisely what the
   identity/authorization split exists to prevent (research.md R2).
3. **There is a decision deadline.** Past it the call is refused, not retried: a slow
   decision is no decision (FR-003).

Everything else — the decision, the narrowing, the transaction mint, the fail-closed
rules, the observe-mode behaviour, the deny envelope — is ``agentic_auth.sidecar.enforce.enforce()``
called unmodified. That is what makes the conformance suite able to prove parity rather
than merely assert it.

Horizontal scaling needs no new coordination: hop depth is derived from the verified act
chain in the token, the single-use guard is ``spent:{action_id}`` in Redis, the decision
cache is Redis, and the session row is immutable. Nothing here is per-process
(research.md R3).
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import AsyncIterator
from dataclasses import asdict

import anyio
import httpx
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from agentic_auth.boundary.guarantee import Guarantee
from agentic_auth.gateway.config import GatewayConfig
from agentic_auth.gateway.metrics import GatewayMetrics, build_gateway_metrics
from agentic_auth.gateway.resolve import agent_name, agent_of, resolve
from agentic_auth.services.edge_trace import EdgeRecorder
from agentic_auth.sidecar.app import _SKIP_REQUEST_HEADERS, _SKIP_RESPONSE_HEADERS
from agentic_auth.sidecar.enforce import Allow, Blocked, Observed, enforce

logger = logging.getLogger(__name__)

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

IDENTITY_HEADER = "agent-identity"
ACTOR_TOKEN_HEADER = "actor-token"

HEALTH_PATHS = ("/v1/gateway/healthz", "/v1/gateway/routes", "/metrics")


def _unavailable(message: str, reason: str = "PDP_UNAVAILABLE") -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "error": {
                "code": "gateway_unavailable",
                "message": message,
                "details": {"reason": reason, "recoverable": False},
            }
        },
    )


def build_app(
    config: GatewayConfig,
    client: httpx.AsyncClient | None = None,
    *,
    registry: CollectorRegistry | None = None,
    metrics: GatewayMetrics | None = None,
) -> Starlette:
    owned = client is None
    http = client or httpx.AsyncClient()
    recorder = EdgeRecorder(config.trace_path, "sidecar") if config.trace_path else None
    gauge = metrics or build_gateway_metrics(registry)

    async def proxy(request: Request) -> Response:
        started = time.perf_counter()
        path = request.url.path

        async def read_body(cap: int) -> bytes | None:
            """Buffer up to ``cap`` bytes; ``None`` past it. Privileged calls only."""
            chunks: list[bytes] = []
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > cap:
                    return None
                chunks.append(chunk)
            return b"".join(chunks)

        # -- resolve the route, from the token's agent and the shared table -------
        authorization = request.headers.get("authorization", "")
        token = (
            authorization.removeprefix("Bearer ").strip()
            if authorization.startswith("Bearer ")
            else ""
        )
        agent = agent_name(agent_of(token)) if token else None
        resolved = resolve(config, agent=agent, path=path, headers=request.headers)
        if isinstance(resolved, JSONResponse):
            gauge.route_misses.inc()

        # -- relay identity; never mint it (research.md R2) ----------------------
        actor_token = request.headers.get(ACTOR_TOKEN_HEADER)
        identity_assertion = request.headers.get(IDENTITY_HEADER)
        gauge.identity_relayed.labels(present=str(bool(identity_assertion)).lower()).inc()

        # The deadline bounds the WHOLE decision — decide, exchange and, for a privileged
        # target, mint — not each HTTP call inside it. Three calls each finishing just
        # inside a per-call timeout would still blow an operator's budget. `fail_after`
        # is also the only bound that holds against an in-process transport, where
        # `httpx` timeouts do not apply at all.
        try:
            with anyio.fail_after(config.control_plane_timeout_seconds):
                outcome = await enforce(
                    http,
                    config,
                    path=path,
                    headers=request.headers,
                    body_reader=read_body,
                    identity=None,  # a gateway holds no key
                    actor_token=actor_token,
                    resolved=resolved,
                )
        except TimeoutError:
            # Refuse, never retry: a slow decision is no decision (FR-003). Retrying
            # would turn a control-plane stall into an unbounded wait for every agent
            # this gateway serves.
            gauge.deadline_exceeded.inc()
            gauge.decisions.labels(outcome="blocked_infra", reason="PDP_UNAVAILABLE").inc()
            logger.warning("decision exceeded %sms for %s", config.decision_deadline_ms, path)
            return _unavailable(f"decision exceeded the {config.decision_deadline_ms}ms deadline")

        if recorder is not None:
            recorder.record(**asdict(outcome.attribution))
        gauge.decisions.labels(
            outcome=outcome.attribution.outcome, reason=outcome.attribution.reason or ""
        ).inc()

        if isinstance(outcome, Blocked):
            return outcome.response

        if isinstance(outcome, Observed):
            forwarded_token = token
            upstream, prefix = outcome.upstream, outcome.prefix
        elif isinstance(outcome, Allow):
            forwarded_token, upstream, prefix = outcome.token, outcome.upstream, outcome.prefix
        else:  # pragma: no cover - the union is closed; a new member must be handled
            logger.error("unhandled enforcement outcome %r — blocking", type(outcome).__name__)
            return _unavailable("unhandled enforcement outcome")

        suffix = path[len(prefix.rstrip("/")) :] or "/"
        url = httpx.URL(f"{upstream.url}{suffix}", query=request.url.query.encode())

        headers = {
            k: v for k, v in request.headers.items() if k.lower() not in _SKIP_REQUEST_HEADERS
        }
        headers["authorization"] = f"Bearer {forwarded_token}"
        content: object = request.stream()
        if isinstance(outcome, Allow):
            if outcome.transaction_token is not None:
                headers["txn-token"] = outcome.transaction_token
            # Relayed through untouched: the agent signed it, not us.
            if identity_assertion is not None:
                headers[IDENTITY_HEADER] = identity_assertion
            if outcome.body is not None:
                content = outcome.body

        upstream_request = http.build_request(
            request.method,
            url,
            headers=headers,
            content=content,  # type: ignore[arg-type]
            timeout=httpx.Timeout(config.request_timeout_seconds),
        )
        try:
            response = await http.send(upstream_request, stream=True)
        except Exception as exc:
            logger.warning("upstream %s unreachable: %s", url, exc)
            return JSONResponse(
                status_code=502,
                content={
                    "error": {
                        "code": "upstream_unreachable",
                        "message": f"upstream did not respond: {exc}",
                    }
                },
            )

        async def body() -> AsyncIterator[bytes]:
            try:
                async for chunk in response.aiter_raw():
                    yield chunk
            finally:
                await response.aclose()
                gauge.upstream_latency.observe(time.perf_counter() - started)

        return StreamingResponse(
            body(),
            status_code=response.status_code,
            headers={
                k: v for k, v in response.headers.items() if k.lower() not in _SKIP_RESPONSE_HEADERS
            },
        )

    async def healthz(_request: Request) -> JSONResponse:
        """Liveness AND enforcement readiness.

        A gateway that is up but cannot reach the control plane reports 503, never 200.
        Reporting healthy while unable to enforce is the failure the sidecar's strict
        startup exists to prevent, and centrally it would take every agent with it.
        """
        reachable = False
        try:
            probe = await http.get(
                f"{config.pdp_url}/healthz",
                timeout=httpx.Timeout(config.control_plane_timeout_seconds),
            )
            reachable = probe.status_code == 200
        except Exception as exc:  # noqa: BLE001 - any failure means "cannot enforce"
            logger.warning("control plane probe failed: %s", exc)

        routes = len(config.route_table)
        ok = reachable and routes > 0
        return JSONResponse(
            status_code=200 if ok else 503,
            content={
                "status": "ok" if ok else "degraded",
                "control_plane": "reachable" if reachable else "unreachable",
                "routes": routes,
                "guarantee_level": config.guarantee_level,
            },
        )

    async def routes_view(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "routes": [
                    {
                        "prefix": prefix,
                        "agent": route_agent,
                        "url": upstream.url,
                        "target": upstream.target,
                        "data_class": upstream.data_class,
                    }
                    for (route_agent, prefix), upstream in sorted(
                        config.route_table.items(), key=lambda kv: (kv[0][1], kv[0][0] or "")
                    )
                ]
            }
        )

    async def metrics_view(_request: Request) -> Response:
        return Response(
            generate_latest(registry) if registry is not None else generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        yield
        if owned:
            await http.aclose()

    return Starlette(
        routes=[
            Route("/v1/gateway/healthz", healthz, methods=["GET"]),
            Route("/v1/gateway/routes", routes_view, methods=["GET"]),
            Route("/metrics", metrics_view, methods=["GET"]),
            # Last: every other path is a proxied tool call.
            Route("/{path:path}", proxy, methods=METHODS),
        ],
        lifespan=lifespan,
    )


def guarantee_for(config: GatewayConfig, *, identity_verified: bool) -> Guarantee:
    """What this gateway may honestly report (FR-016, research.md R2).

    ``full`` requires that every hop was decided *and* the presenting agent was
    identified. A gateway cannot identify an agent itself — it holds no key — so it may
    only claim ``full`` when identity enforcement is off (nothing to prove) or the agent
    supplied headers that verified. Otherwise it reports its configured level, which an
    operator sets to whatever the deployment actually achieves.
    """
    if identity_verified:
        return Guarantee.FULL
    return Guarantee(config.guarantee_level)


__all__ = ["build_app", "guarantee_for"]
