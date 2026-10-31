"""Keyed identity pseudonyms and session-derived trace roots.

Two primitives, one secret (``AGENTIC_AUTH_TELEMETRY_KEY``):

- ``pseudonym()`` replaces an agent name or act chain in a trace or log with a stable,
  non-reversible reference.
- ``session_trace_id()`` / ``session_parent_context()`` give every decision in one session the
  same trace, even when no caller supplies a ``traceparent`` and even across processes that
  share no context.

**Why the key, and not a plain hash.** Agent names are a small, enumerable space
(``agent://router``, ``agent://billing-writer``, ...). An unkeyed SHA-256 of one is recovered by
brute force in seconds by anyone holding the telemetry and a guess at the naming convention. A
MAC with a secret the telemetry backend does not hold defeats that. The same key makes a trace
id something other than a plaintext session handle in a third-party backend.

**Why no custom ``IdGenerator``**:
OTel's ``IdGenerator.generate_trace_id(self)`` takes no arguments, so a generator cannot see the
session id without process-global or contextvar state. Building a synthetic non-recording
*remote parent* from the derived id is deterministic per request, needs no global state, and
makes the trace id arrive from the parent context — so the SDK never generates one for these
spans and R4's ``is_trace_id_random`` caveat does not arise.

This module imports only the standard library plus the OTel **API** (not the SDK) for the
context helper, so the pure functions remain testable without the ``otel`` extra installed.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from opentelemetry.context import Context

# 128 bits. Long enough that collisions are negligible at the design scale (1,000 agents x
# 100,000 sessions), short enough to keep span attributes readable.
PSEUDONYM_HEX_LEN = 32

_TRACE_ID_BYTES = 16
_SPAN_ID_BYTES = 8

# Domain prefixes. Separate namespaces so a target URI and an agent name with the same text
# never produce the same pseudonym.
KIND_AGENT = "agent"
KIND_CHAIN = "chain"
KIND_TARGET = "target"
KIND_SESSION = "session"
KIND_SPAN = "span"


def _frame(kind: str, value: str) -> str:
    """Length-prefix the domain so the encoding is injective.

    A bare ``f"{kind}:{value}"`` is ambiguous: ``("agent", "x:y")`` and ``("agent:x", "y")`` both
    frame to ``"agent:x:y"``. Not exploitable while every ``kind`` is an internal constant, but an
    encoding that *cannot* collide costs one integer and removes the need to reason about it.
    """
    return f"{len(kind)}:{kind}:{value}"


def _mac(key: bytes, label: str) -> bytes:
    if not key:
        # Reaching here means a caller bypassed ObservabilityConfig's refusal to enable without
        # a key. Raising beats falling back to an unkeyed digest, which would look like it
        # worked while being trivially reversible.
        raise ValueError("a telemetry key is required; refusing to derive an unkeyed value")
    return hmac.new(key, label.encode("utf-8"), hashlib.sha256).digest()


def pseudonym(kind: str, value: str, key: bytes) -> str:
    """A stable, non-reversible reference to ``value`` within one deployment.

    Stable: same key and input always give the same answer, in every process, forever — which is
    what lets an operator group a deployment's telemetry by agent without learning which agent.
    Non-reversible: not without the key.

    Rotating the key re-pseudonymises everything and breaks historical grouping. That is the
    documented cost of one secret serving both primitives here.
    """
    return _mac(key, _frame(kind, value)).hex()[:PSEUDONYM_HEX_LEN]


def session_trace_id(session_id: str, key: bytes) -> int:
    """The 128-bit trace id every span in ``session_id`` belongs to, absent inbound context.

    Derived, not generated, so two processes agree without a channel between them.
    """
    digest = _mac(key, _frame(KIND_SESSION, session_id))
    trace_id = int.from_bytes(digest[:_TRACE_ID_BYTES], "big")
    # 0 is INVALID_TRACE_ID and would be dropped by the SDK. Astronomically unlikely from a MAC,
    # but a silent drop is a bad failure mode, so it is handled rather than assumed away.
    return trace_id or 1


def session_root_span_id(session_id: str, key: bytes) -> int:
    """The 64-bit id of the synthetic parent. Derived from its own domain rather than from the
    trace id's low bytes, so neither leaks the other."""
    digest = _mac(key, _frame(KIND_SPAN, session_id))
    span_id = int.from_bytes(digest[:_SPAN_ID_BYTES], "big")
    return span_id or 1


def session_parent_context(session_id: str, key: bytes) -> Context:
    """A ``Context`` whose current span is a synthetic, non-recording remote parent for this
    session.

    Used as the parent when a caller sends no usable ``traceparent``. The parent itself is never
    exported — it is a correlation handle, and ``is_remote=True`` says honestly that it did not
    originate here. ``TraceFlags.SAMPLED`` is set because a child that inherited an unsampled
    parent would be dropped, which must never happen to a refusal.
    """
    from opentelemetry import trace as trace_api

    span_context = trace_api.SpanContext(
        trace_id=session_trace_id(session_id, key),
        span_id=session_root_span_id(session_id, key),
        is_remote=True,
        trace_flags=trace_api.TraceFlags(trace_api.TraceFlags.SAMPLED),
    )
    return trace_api.set_span_in_context(trace_api.NonRecordingSpan(span_context))
