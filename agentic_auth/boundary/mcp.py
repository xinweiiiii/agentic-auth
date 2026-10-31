"""The connector proxy — governing an agent whose code you cannot touch (FR-010..FR-012).

**Use this when you own the agent's tool configuration but not its code.** Repoint that
configuration here and the agent keeps calling what it thinks are its tools; every call
now gets a policy decision and a narrowed authority on the way through, and the agent
never knows.

Two deliberate limits on how much protocol this module implements (research.md R8):

- **The upstream server's own authorization handshake is passed through untouched.** We
  add a policy layer; we are not an MCP implementation. That protocol's auth model is
  still hardening, so anything we wrote here would be depreciating from the day it
  shipped.
- **No MCP SDK dependency.** The envelope this needs to understand is a handful of JSON
  fields, and a dependency whose release cadence tracks a moving spec is a liability on
  a fail-closed path.

Per method:

===============  =====================================================================
``tools/call``   ``target = mcp://<host>/<tool>``, then ``enforce()`` — the same
                 decision core as the sidecar and the gateway.
``tools/list``   Relayed, and the result filtered to what the pinned policy declares.
everything else  Relayed unchanged.
===============  =====================================================================

Refusals come back as JSON-RPC errors, carrying the same ``reason``/``recoverable`` pair
every other enforcement point returns, so an SDK-aware caller branches identically.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import asdict
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from agentic_auth.boundary.guarantee import Guarantee
from agentic_auth.gateway.config import GatewayConfig
from agentic_auth.gateway.resolve import agent_name, agent_of
from agentic_auth.services.edge_trace import EdgeRecorder
from agentic_auth.sidecar.config import Upstream
from agentic_auth.sidecar.enforce import Allow, Blocked, Observed, enforce

logger = logging.getLogger(__name__)

# A connector proxy sees only what goes through the agent's tool configuration. A call
# made by any other route is invisible to it, which is exactly why this is not `full`.
GUARANTEE = Guarantee.CONNECTOR

# JSON-RPC error codes. -32003 is in the implementation-defined server range and is what
# this proxy uses for "policy refused"; -32603 is the standard internal-error code and
# means "a dependency failed", which an agent should treat as retryable and a policy
# refusal as not.
POLICY_REFUSED = -32003
INFRASTRUCTURE = -32603
INVALID_REQUEST = -32600

TOOLS_CALL = "tools/call"
TOOLS_LIST = "tools/list"


def _error(request_id: object, code: int, message: str, **data: object) -> JSONResponse:
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message, "data": data or None},
        }
    )


def _tool_target(upstream: Upstream, tool_name: str) -> str:
    """The policy target for a tool call.

    Derived from the *upstream* host and the tool the agent named, never from a header:
    the whole point of this rung is that the agent is not cooperating, so nothing it
    sends may choose which policy target its call is checked against.
    """
    host = httpx.URL(upstream.url).host
    return f"mcp://{host}/{tool_name}"


def build_app(
    config: GatewayConfig,
    client: httpx.AsyncClient | None = None,
    *,
    declared_tools: frozenset[str] | None = None,
) -> Starlette:
    """An MCP-shaped reverse proxy in front of one upstream server.

    ``declared_tools`` is what the session's pinned policy declares for the calling
    agent, used to filter ``tools/list``. Passed in rather than loaded here because this
    module must not acquire a database dependency — it deploys next to an agent, not next
    to the control plane.
    """
    owned = client is None
    http = client or httpx.AsyncClient()
    recorder = EdgeRecorder(config.trace_path, "sidecar") if config.trace_path else None

    async def rpc(request: Request) -> Response:
        raw = await request.body()
        try:
            envelope = json.loads(raw or b"{}")
        except ValueError as exc:
            # A malformed envelope is refused, not relayed. Forwarding something we
            # could not parse would mean forwarding a call we did not decide on.
            return _error(None, INVALID_REQUEST, f"malformed JSON-RPC envelope: {exc}")
        if not isinstance(envelope, dict):
            return _error(None, INVALID_REQUEST, "JSON-RPC envelope must be an object")

        request_id = envelope.get("id")
        method = envelope.get("method")
        token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        agent = agent_name(agent_of(token)) if token else None

        match = config.resolve(agent, request.url.path)
        if match is None:
            return _error(
                request_id, POLICY_REFUSED, f"no upstream mapped for {request.url.path!r}"
            )
        prefix, upstream = match

        if method == TOOLS_CALL:
            return await _tools_call(
                request, envelope, request_id, prefix, upstream, token, http, recorder, config
            )

        relayed = await _relay(request, raw, upstream, http, config)
        if method == TOOLS_LIST and declared_tools is not None:
            return _filtered_listing(relayed, upstream, declared_tools)
        return relayed

    async def _tools_call(
        request: Request,
        envelope: dict[str, Any],
        request_id: Any,
        prefix: str,
        upstream: Any,
        token: str,
        http: httpx.AsyncClient,
        recorder: Any,
        config: Any,
    ) -> Response:
        params = envelope.get("params") or {}
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            return _error(request_id, INVALID_REQUEST, "tools/call needs a tool name")

        target = _tool_target(upstream, tool_name)
        data_class = upstream.data_class or request.headers.get("x-agentic-data-class")
        if not data_class:
            # Guessing a data class would be inventing consent. Same rule as everywhere.
            return _error(
                request_id,
                POLICY_REFUSED,
                f"no data class configured for {target!r}",
                reason="UPSTREAM_TARGET_UNRESOLVED",
                recoverable=False,
            )

        arguments = params.get("arguments")
        body = json.dumps(arguments if isinstance(arguments, dict) else {}).encode()

        async def body_reader(cap: int) -> bytes | None:
            return None if len(body) > cap else body

        outcome = await enforce(
            http,
            config,
            path=request.url.path,
            headers=request.headers,
            body_reader=body_reader,
            identity=None,
            actor_token=request.headers.get("actor-token"),
            resolved=(prefix, upstream, target, data_class),
        )
        if recorder is not None:
            recorder.record(**asdict(outcome.attribution))

        if isinstance(outcome, Blocked):
            return _jsonrpc_refusal(request_id, outcome)

        forwarded = token if isinstance(outcome, Observed) else outcome.token
        headers = {
            "authorization": f"Bearer {forwarded}",
            "content-type": "application/json",
            "accept": request.headers.get("accept", "application/json"),
        }
        if isinstance(outcome, Allow):
            if outcome.transaction_token is not None:
                headers["txn-token"] = outcome.transaction_token
            if outcome.identity_assertion is not None:
                headers["agent-identity"] = outcome.identity_assertion

        # The narrowed token, the transaction token and the upstream's own credentials
        # go OUT; none of them is ever returned to the agent (FR-011).
        try:
            upstream_response = await http.post(
                f"{upstream.url}{request.url.path[len(prefix.rstrip('/')) :] or '/'}",
                headers=headers,
                content=await request.body(),
                timeout=httpx.Timeout(config.request_timeout_seconds),
            )
        except Exception as exc:
            logger.warning("upstream %s unreachable: %s", upstream.url, exc)
            return _error(
                request_id,
                INFRASTRUCTURE,
                f"upstream did not respond: {exc}",
                reason="UPSTREAM_UNREACHABLE",
                recoverable=False,
            )
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type", "application/json"),
        )

    async def _relay(
        request: Request, raw: bytes, upstream: Any, http: httpx.AsyncClient, config: Any
    ) -> Response:
        try:
            response = await http.post(
                f"{upstream.url}{request.url.path}",
                headers={
                    k: v
                    for k, v in request.headers.items()
                    if k.lower() not in {"host", "content-length"}
                },
                content=raw,
                timeout=httpx.Timeout(config.request_timeout_seconds),
            )
        except Exception as exc:
            return _error(None, INFRASTRUCTURE, f"upstream did not respond: {exc}")
        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type", "application/json"),
        )

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        yield
        if owned:
            await http.aclose()

    return Starlette(routes=[Route("/{path:path}", rpc, methods=["POST"])], lifespan=lifespan)


def _jsonrpc_refusal(request_id: object, outcome: Blocked) -> JSONResponse:
    """A refusal in the shape the agent already handles (FR-011).

    The distinction between a policy refusal and an infrastructure failure is preserved,
    because they send an operator to different places: one is a rule, the other is an
    outage.
    """
    try:
        body = json.loads(bytes(outcome.response.body))
        error = body.get("error", {})
        details = error.get("details") or {}
        message = error.get("message") or "denied by policy"
    except (ValueError, KeyError, TypeError):
        details, message = {}, "denied by policy"

    infrastructure = outcome.attribution.outcome == "blocked_infra"
    return _error(
        request_id,
        INFRASTRUCTURE if infrastructure else POLICY_REFUSED,
        message,
        reason=details.get("reason") or outcome.attribution.reason,
        recoverable=bool(details.get("recoverable", False)),
        target=outcome.attribution.target,
        guarantee_level=GUARANTEE.value,
    )


def _filtered_listing(response: Response, upstream: Upstream, declared: frozenset[str]) -> Response:
    """Offer only the tools the pinned manifest declares (FR-012, research.md R9).

    Filtering is defence in depth over an enforced rule, not the rule itself — a direct
    ``tools/call`` to an unlisted tool is still refused. What it removes is a whole class
    of wasted work, where an agent sees a tool, plans around it, calls it, and is refused
    three steps later.
    """
    try:
        body = json.loads(bytes(response.body))
        tools = body["result"]["tools"]
    except (ValueError, KeyError, TypeError, AttributeError):
        return response  # not a listing we understand; relay untouched

    host = httpx.URL(upstream.url).host
    kept = [t for t in tools if f"mcp://{host}/{t.get('name')}" in declared]
    removed = len(tools) - len(kept)
    if removed:
        logger.info("filtered %d undeclared tool(s) from a listing", removed)
    body["result"]["tools"] = kept
    return JSONResponse(body, status_code=response.status_code)


__all__ = ["GUARANTEE", "INFRASTRUCTURE", "POLICY_REFUSED", "build_app"]
