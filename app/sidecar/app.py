"""The sidecar reverse proxy.

A reverse proxy rather than a forward/CONNECT proxy: no TLS interception, no CA to trust
in the agent runtime, no root privileges. The agent's tool base URL points here.

Bodies stream in both directions so a large tool payload never buffers in memory.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import time
from collections.abc import AsyncIterator
from dataclasses import asdict

import httpx
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from app import observability
from app.observability import pep as pep_telemetry
from app.observability import surface
from app.services.edge_trace import EdgeRecorder
from app.services.metrics import build_pep_metrics
from app.sidecar.config import RESERVED_PATH_PREFIX, SidecarConfig
from app.sidecar.enforce import Allow, Blocked, Observed, enforce
from app.sidecar.identity import load_identity

logger = logging.getLogger(__name__)

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

# This enforcement point's own version, reported as a label on agentic_auth_pep_info.
PEP_VERSION = "0.1.0"

# Hop-by-hop headers must not be relayed (RFC 9110 §7.6.1); Host and Content-Length are
# recomputed by the client for the upstream request.
_SKIP_REQUEST_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
}
_SKIP_RESPONSE_HEADERS = {
    "content-length",
    "content-encoding",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
}


def _upstream_digest(config: SidecarConfig) -> str:
    """A stable digest of the upstream map, for comparing two PEPs that should match."""
    payload = json.dumps(
        {
            prefix: [u.url, u.target, u.data_class]
            for prefix, u in sorted(config.upstream_map.items())
        },
        sort_keys=True,
    )
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()[:16]


def build_app(config: SidecarConfig, client: httpx.AsyncClient | None = None) -> Starlette:
    # One pooled client for the whole process. A per-request client would spend the
    # entire per-hop latency budget on connection setup alone.
    owned = client is None
    http = client or httpx.AsyncClient()
    # Passive: one event per call, written after the outcome is fixed. A recorder failure is
    # counted into the events file, never raised here (app/services/edge_trace.py).
    recorder = EdgeRecorder(config.trace_path, "sidecar") if config.trace_path else None
    # Phase 4: with a key configured, every exchange carries an actor_token and every
    # forwarded call an Agent-Identity assertion. Loaded once; a bad key fails startup.
    identity = load_identity(config)

    # -- telemetry -------------------------------------------------
    # One registry per process, served at GET /__agentic/metrics. Before this, nothing here
    # emitted anything: a sidecar that had been silently forwarding every call looked exactly
    # like a healthy one.
    metrics = build_pep_metrics()
    mode = surface.PEP_MODE_OBSERVING if config.observe_mode else surface.PEP_MODE_ENFORCING
    metrics.up.set(1)
    metrics.info.labels(mode=mode, version=PEP_VERSION).set(1)
    telemetry = observability.setup(
        service_name=surface.COMPONENT_PEP,
        resolved=observability.ObservabilityConfig.resolve(
            enabled=config.telemetry_enabled,
            key=config.telemetry_key,
            identity_disclosure=config.telemetry_identity_disclosure,
            allow_sample_ratio=config.telemetry_allow_sample_ratio,
            service_name=surface.COMPONENT_PEP,
        ),
        metrics=metrics,
    )
    metrics.telemetry_identity_disclosure.set(1 if telemetry.identity_disclosure else 0)
    started_at = time.monotonic()
    # Derived from the last real control-plane call, not from a probe: a probe adds a request
    # the dispatch path does not need and can report healthy while real calls fail.
    pdp_state: dict[str, float | None] = {"last_success": None}

    async def proxy(request: Request) -> StreamingResponse | JSONResponse:
        path = request.url.path

        async def read_body(cap: int) -> bytes | None:
            """Buffer up to ``cap`` bytes; ``None`` past it. Only called for privileged calls."""
            chunks: list[bytes] = []
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > cap:
                    return None
                chunks.append(chunk)
            return b"".join(chunks)

        timer = pep_telemetry.StageTimer(metrics)
        session_hint = request.headers.get("x-agentic-session")
        parent = observability.extract_parent(
            request.headers,
            session_id=session_hint,
            key=telemetry.key,
            metrics=metrics,
        )
        outcome = await enforce(
            http,
            config,
            path=path,
            headers=request.headers,
            body_reader=read_body,
            identity=identity,
            timer=timer,
        )
        if recorder is not None:
            recorder.record(**asdict(outcome.attribution))

        # One mapping for all ~20 of enforce()'s return paths, because every one of them
        # already produces an EdgeAttribution. The alternative — a counter increment at each
        # return — would have missed one eventually.
        classification = pep_telemetry.classify(
            outcome.attribution.outcome, outcome.attribution.reason
        )
        pep_telemetry.record(metrics, classification)
        _emit_forward_span(
            parent=parent,
            method=request.method,
            classification=classification,
            session_id=session_hint,
        )
        # Only a call that actually reached the decision endpoint says anything about whether
        # it is reachable. A refusal before dispatch — an unauthorized bearer, an unmapped
        # path — never contacted it, and counting those as success made `/status` report the
        # control plane healthy while it was in fact dead.
        if "decide" in timer.stages and classification.block_cause != "pdp_unreachable":
            pdp_state["last_success"] = time.monotonic()

        if isinstance(outcome, Blocked):
            timer.finish()
            return outcome.response

        if isinstance(outcome, Observed):
            # Denied, but the operator asked to watch rather than block. The ORIGINAL
            # token goes upstream — no exchange happened for a denied hop.
            token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
            upstream, prefix = outcome.upstream, outcome.prefix
        elif isinstance(outcome, Allow):
            token, upstream, prefix = outcome.token, outcome.upstream, outcome.prefix
        else:  # pragma: no cover - the union is closed; a new member must be handled
            logger.error("unhandled enforcement outcome %r — blocking", type(outcome).__name__)
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "code": "policy_denied",
                        "message": "unhandled enforcement outcome",
                        "details": {"reason": "PDP_UNAVAILABLE", "recoverable": False},
                    }
                },
            )

        suffix = path[len(prefix.rstrip("/")) :] or "/"
        url = httpx.URL(f"{upstream.url}{suffix}", query=request.url.query.encode())

        headers = {
            k: v for k, v in request.headers.items() if k.lower() not in _SKIP_REQUEST_HEADERS
        }
        # The narrowed token replaces the presented one. The presented token is never
        # forwarded unchanged on an allowed hop.
        headers["authorization"] = f"Bearer {token}"
        # `traceparent` is not a hop-by-hop header and is deliberately absent from
        # `_SKIP_REQUEST_HEADERS`, so a caller-supplied one already passes through untouched.
        # This adds one when the caller sent none, so the upstream lands in the same trace
        # either way. Do not "tidy" traceparent into the skip list.
        observability.inject(headers)
        content: object = request.stream()
        if isinstance(outcome, Allow):
            if outcome.transaction_token is not None:
                headers["txn-token"] = outcome.transaction_token
            if outcome.identity_assertion is not None:
                headers["agent-identity"] = outcome.identity_assertion
            if outcome.body is not None:
                # Buffered to bind it; forward exactly those bytes.
                content = outcome.body

        upstream_request = http.build_request(
            request.method,
            url,
            headers=headers,
            content=content,  # type: ignore[arg-type]
            timeout=httpx.Timeout(config.request_timeout_seconds),
        )
        upstream_started = time.perf_counter()
        try:
            response = await http.send(upstream_request, stream=True)
        except Exception as exc:
            timer.finish()
            logger.warning(
                "upstream unreachable",
                extra={"authz.component": "pep", "error.type": type(exc).__name__},
            )
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
                # The upstream stage ends when its body is fully relayed, so overhead is
                # measured against the whole call rather than against the headers only.
                timer._record("upstream", time.perf_counter() - upstream_started)
                timer.finish()

        return StreamingResponse(
            body(),
            status_code=response.status_code,
            headers={
                k: v for k, v in response.headers.items() if k.lower() not in _SKIP_RESPONSE_HEADERS
            },
        )

    async def pep_metrics(_request: Request) -> Response:
        """This enforcement point's own Prometheus exposition.

        Served on the existing listener — no new port. A PEP that is not scraped is not
        observable, and no amount of instrumentation inside it changes that: see
        https://authzai.dev/how-to/observe-the-guardrail for the deployment
        obligation this route creates.
        """
        return Response(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST)

    async def pep_status(_request: Request) -> JSONResponse:
        """Mode, liveness and dependency health, for an operator or a readiness probe.

        ``upstream_map_digest`` is a digest rather than the map itself: upstream URLs carry
        internal hostnames, and two PEPs that are supposed to be configured identically are
        compared by digest anyway.
        """
        last = pdp_state["last_success"]
        return JSONResponse(
            {
                "mode": mode,
                "uptime_seconds": round(time.monotonic() - started_at, 3),
                "upstreams": len(config.upstream_map),
                "upstream_map_digest": _upstream_digest(config),
                "pdp": {
                    "reachable": last is not None,
                    "last_success_seconds_ago": (
                        None if last is None else round(time.monotonic() - last, 3)
                    ),
                },
                "telemetry": {
                    "enabled": telemetry.enabled,
                    "state": telemetry.state,
                    "identity_disclosure": telemetry.identity_disclosure,
                },
                "version": PEP_VERSION,
            }
        )

    def _emit_forward_span(
        *,
        parent: object,
        method: str,
        classification: pep_telemetry.Classification,
        session_id: str | None,
    ) -> None:
        """``pep.forward`` — the enforcement point's view of one proxied call.

        The stage children (`pep.decide` and friends) are not emitted as separate spans: the
        same boundaries are already in the stage histograms, and a span per stage would triple
        the volume for a number an operator reads off a dashboard anyway.
        """
        if not telemetry.enabled:
            return
        attributes = observability.pep_attributes(
            telemetry,
            mode=mode,
            outcome=classification.outcome,
            block_cause=classification.block_cause,
            session_id=session_id,
            http_method=method,
        )
        with observability.tracer().start_as_current_span(
            surface.SPAN_PEP_FORWARD,
            context=parent,
            attributes=attributes,
            record_exception=False,
        ):
            pass

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        yield
        observability.shutdown()
        metrics.up.set(0)
        if owned:  # only close what we created; an injected client is the caller's
            await http.aclose()

    return Starlette(
        routes=[
            # Before the catch-all, and under a prefix `validate()` refuses to let an
            # upstream mapping shadow.
            Route(f"{RESERVED_PATH_PREFIX}/metrics", pep_metrics, methods=["GET"]),
            Route(f"{RESERVED_PATH_PREFIX}/status", pep_status, methods=["GET"]),
            Route("/{path:path}", proxy, methods=METHODS),
        ],
        lifespan=lifespan,
    )
