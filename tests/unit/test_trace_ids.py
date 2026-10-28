"""Session-derived trace roots (spec 007 FR-010, contracts/trace-context.md §3).

The control plane and the sidecar are separate processes with no shared context. When no caller
supplies a `traceparent`, both must land their spans in the SAME trace — so the root is derived
from a value both already hold, the session id, and nothing is passed between them.

**Deviation from research.md R4, which specified a custom `IdGenerator`.** OTel's
`IdGenerator.generate_trace_id(self)` takes no arguments, so a generator cannot see the session
id without process-global or contextvar state. A synthetic non-recording *remote parent* built
from the derived id achieves the same determinism per request, with no global state, and makes
the trace id come from the parent context — so the SDK never generates one for these spans and
the `is_trace_id_random` caveat in R4 does not arise at all.
"""

from __future__ import annotations

import pytest

# Only the OTel *API* is needed here (SpanContext/NonRecordingSpan), not the SDK — but the API
# is still part of the optional extra, so skip rather than fail when it is absent (FR-029).
pytest.importorskip("opentelemetry.trace", reason="requires the 'otel' extra")

from opentelemetry import trace as trace_api  # noqa: E402

from app.observability.ids import session_parent_context, session_trace_id  # noqa: E402

KEY = b"0123456789abcdef0123456789abcdef"
OTHER_KEY = b"fedcba9876543210fedcba9876543210"
SESSION = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"


# -- the derivation ------------------------------------------------------------------------


def test_trace_id_is_the_keyed_hmac_of_the_session() -> None:
    import hashlib
    import hmac

    framed = f"7:session:{SESSION}"  # length-prefixed domain, see ids._frame
    expected = int.from_bytes(hmac.new(KEY, framed.encode(), hashlib.sha256).digest()[:16], "big")
    assert session_trace_id(SESSION, KEY) == expected


def test_trace_id_is_128_bits() -> None:
    assert 0 < session_trace_id(SESSION, KEY) < 2**128


def test_trace_id_is_never_invalid() -> None:
    """INVALID_TRACE_ID (0) would be silently dropped by the SDK."""
    for i in range(2000):
        assert session_trace_id(f"session-{i}", KEY) != trace_api.INVALID_TRACE_ID


def test_different_keys_give_different_roots() -> None:
    """So a trace id is not a reversible handle to a session id in a third-party backend."""
    assert session_trace_id(SESSION, KEY) != session_trace_id(SESSION, OTHER_KEY)


def test_empty_key_is_refused() -> None:
    with pytest.raises(ValueError, match="telemetry key"):
        session_trace_id(SESSION, b"")


# -- two independent processes agree (the whole point) -------------------------------------


def test_two_independently_built_contexts_share_one_trace() -> None:
    """Simulates the control plane and the sidecar: same session, same key, nothing shared."""
    control_plane = session_parent_context(SESSION, KEY)
    sidecar = session_parent_context(SESSION, KEY)

    a = trace_api.get_current_span(control_plane).get_span_context()
    b = trace_api.get_current_span(sidecar).get_span_context()

    assert a.trace_id == b.trace_id
    assert a.span_id == b.span_id, "the synthetic parent must also be stable, or children differ"


def test_different_sessions_are_different_traces() -> None:
    other = "11111111-2222-4333-8444-555555555555"
    a = trace_api.get_current_span(session_parent_context(SESSION, KEY)).get_span_context()
    b = trace_api.get_current_span(session_parent_context(other, KEY)).get_span_context()
    assert a.trace_id != b.trace_id


# -- the synthetic parent's properties ----------------------------------------------------


def test_parent_is_remote_and_sampled_and_non_recording() -> None:
    ctx = session_parent_context(SESSION, KEY)
    span = trace_api.get_current_span(ctx)
    sc = span.get_span_context()

    assert sc.is_remote, "marks the parent as not originating in this process"
    assert sc.trace_flags.sampled, "else children inherit a dropped decision"
    assert not span.is_recording(), "it is a correlation handle, never exported itself"
    assert sc.is_valid


def test_parent_span_id_is_never_invalid() -> None:
    for i in range(2000):
        sc = trace_api.get_current_span(session_parent_context(f"s{i}", KEY)).get_span_context()
        assert sc.span_id != trace_api.INVALID_SPAN_ID


def test_trace_and_span_ids_are_independently_derived() -> None:
    """A span id that reused the trace id's low bytes would make the two correlated, which is
    needlessly surprising and would leak one from the other."""
    sc = trace_api.get_current_span(session_parent_context(SESSION, KEY)).get_span_context()
    assert sc.span_id != sc.trace_id & (2**64 - 1)
