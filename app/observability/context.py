"""Inbound trace context, treated as untrusted input.

A caller-supplied ``traceparent`` arrives from an agent process we may not control. Three rules,
all enforced here so no call site has to remember them:

1. **`tracecontext` only.** The SDK default is ``tracecontext,baggage``, and
   ``W3CBaggagePropagator`` would extract arbitrary attacker-controlled key/value data on the way
   in and **re-inject it into every outbound call**. An agent could use it to smuggle unbounded
   content through our telemetry, or to spoof fields a backend treats as trustworthy. We
   instantiate the trace-context propagator directly rather than reading ``OTEL_PROPAGATORS``, so
   an integrator who enables baggage for their own services cannot enable it on ours.
2. **`tracestate` is discarded.** Neither read nor propagated.
3. **Nothing inbound reaches a decision.** No value here is read by the authorization path, and
   none is written to an audit row, a deny reason, or a metric label.

What a caller *can* do is claim any trace id, and so make its spans appear inside another trace.
That is a correlation nuisance, not a security bypass, and it has one consequence worth stating
plainly:

    **A trace id is never evidence.** The audit record, keyed by ``action_id``, is the evidence.
    The span is a handle that points at it.

``traceparent`` is fixed-length by the W3C format, so with baggage and tracestate dropped there
is no unbounded-input vector left.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from app.observability.ids import session_parent_context

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Mapping

    from opentelemetry.context import Context

logger = logging.getLogger(__name__)

TRACEPARENT = "traceparent"

# Reject causes, matching surface.TRACE_CONTEXT_REJECT_CAUSES.
CAUSE_MALFORMED = "malformed"
CAUSE_ABSENT = "absent"
CAUSE_BAGGAGE_DROPPED = "baggage_dropped"


@lru_cache(maxsize=1)
def _propagator() -> Any:
    """Deliberately not the global propagator — see rule 1 above — and deliberately built
    lazily: the OpenTelemetry API is an optional extra, so nothing in this package may import
    it at module scope. The gate (the suite passing with the extra uninstalled) is what
    enforces that."""
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

    return TraceContextTextMapPropagator()


# Headers a caller may send that we refuse to honour or forward.
_REFUSED_HEADERS = ("baggage", "tracestate")


def _record(metrics: object | None, cause: str) -> None:
    """Count a rejection, if a registry was supplied. Never raises: a missing or half-built
    metrics object must not break a request."""
    if metrics is None:
        return
    try:
        metrics.trace_context_rejected.labels(cause=cause).inc()  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - defensive
        logger.debug("could not record a trace-context rejection", exc_info=False)


def extract_parent(
    headers: Mapping[str, str],
    *,
    session_id: str | None,
    key: bytes,
    metrics: object | None = None,
) -> Context | None:
    """Resolve the parent context for a span, from the caller's headers or from the session.

    Returns ``None`` when there is neither usable inbound context nor a session id, which leaves
    the SDK to start a fresh random root — correct for a call that belongs to no session.

    ``propagate.extract`` returns a context with no valid span context when ``traceparent`` is
    malformed, rather than raising, so the fallback would be silent. We detect it deliberately
    and count it: a deployment cannot otherwise tell cooperative callers from broken ones.
    """
    # Rule 1/2: note and drop anything we refuse to honour, before looking at traceparent, so
    # the drop is counted even when the caller also sent a perfectly good traceparent.
    for refused in _REFUSED_HEADERS:
        if refused in headers or refused.title() in headers:
            _record(metrics, CAUSE_BAGGAGE_DROPPED)
            break

    raw = headers.get(TRACEPARENT) or headers.get("Traceparent")
    if raw:
        # Only traceparent is passed to the propagator. tracestate is not forwarded even though
        # the W3C propagator would accept it, so a caller cannot seed vendor state.
        from opentelemetry import trace as trace_api

        context = _propagator().extract({TRACEPARENT: raw})
        span_context = trace_api.get_current_span(context).get_span_context()
        if span_context.is_valid:
            return context
        _record(metrics, CAUSE_MALFORMED)
    else:
        _record(metrics, CAUSE_ABSENT)

    if session_id and key:
        # One chain, one trace, with no cooperation from the caller and no channel between the
        # control plane and the PEP.
        return session_parent_context(session_id, key)
    return None


def inject(headers: dict[str, str]) -> dict[str, str]:
    """Add ``traceparent`` for an outbound call the SDK controls.

    Only trace context goes out — no baggage, no tracestate. The sidecar's **upstream** leg needs
    no help: ``traceparent`` is not a hop-by-hop header and is deliberately absent from
    ``_SKIP_REQUEST_HEADERS`` in ``app/sidecar/app.py``, so it already passes through.
    """
    _propagator().inject(headers)
    return headers
