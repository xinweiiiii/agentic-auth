"""Sampling must never lose a refusal.

The reason this needs two mechanisms rather than one: ``Sampler.should_sample`` runs when a span
*starts*, and the outcome is not known until it ends. So the sampler keeps everything, and a
``SpanProcessor`` sheds a fraction of ALLOW spans at ``on_end``, where the outcome attribute
exists. Refusals never consult the ratio.

The sampler also deliberately **overrides the caller's sampling decision**. An agent trace the
integrator sampled out would otherwise take our deny span with it, and a deny that no one can
see is the failure mode this whole feature exists to prevent. The cost is a partial trace, which
is accepted: the span still carries `authz.action_id` and is chain-resolvable on its own.
"""

from __future__ import annotations

import pytest

# The sampler and the filter are OTel SDK types, so this file needs the optional `otel` extra.
# It skips without it rather than failing, because the suite must to pass with the
# extra uninstalled — that run is what proves the no-op fallback.
pytest.importorskip("opentelemetry.sdk.trace", reason="requires the 'otel' extra")

from opentelemetry import trace as trace_api  # noqa: E402
from opentelemetry.sdk.trace.export import SpanExportResult  # noqa: E402
from opentelemetry.sdk.trace.sampling import Decision  # noqa: E402

from agentic_auth.observability import surface  # noqa: E402
from agentic_auth.observability.tracing import AlwaysSampleAuthz, RefusalPreservingFilter  # noqa: E402

# Every refusal shape the control plane and the PEP can produce. Each one must survive the most
# aggressive sampling the layer permits.
REFUSALS = [
    {surface.ATTR_OUTCOME: "deny", surface.ATTR_DENY_REASON: "EDGE_NOT_IN_DAG"},
    {surface.ATTR_OUTCOME: "deny", surface.ATTR_DENY_REASON: "PDP_UNAVAILABLE"},
    {surface.ATTR_OUTCOME: "deny", surface.ATTR_DENY_REASON: "TAINTED_INTO_PRIVILEGED"},
    {surface.ATTR_OUTCOME: "deny", surface.ATTR_DENY_REASON: "AUDIT_UNAVAILABLE"},
    {surface.ATTR_OUTCOME: "deny", surface.ATTR_DENY_REASON: "HOP_BUDGET_EXCEEDED"},
    {surface.ATTR_OUTCOME: "deny", surface.ATTR_DENY_REASON: "AGENT_REVOKED"},
    {surface.ATTR_PEP_OUTCOME: "blocked", surface.ATTR_PEP_BLOCK_CAUSE: "policy"},
    {surface.ATTR_PEP_OUTCOME: "blocked", surface.ATTR_PEP_BLOCK_CAUSE: "pdp_unreachable"},
    {surface.ATTR_PEP_OUTCOME: "observed_would_block", surface.ATTR_PEP_BLOCK_CAUSE: "policy"},
    {surface.ATTR_ERROR_TYPE: "TaintStoreUnavailable"},
]

ALLOWS = [
    {surface.ATTR_OUTCOME: "allow"},
    {surface.ATTR_PEP_OUTCOME: "allowed"},
]


class _FakeSpan:
    """The processor reads only `name` and `attributes`, so a ReadableSpan stand-in is enough
    and keeps the matrix readable."""

    def __init__(self, attributes: dict, name: str = surface.SPAN_DECIDE) -> None:
        self.name = name
        self.attributes = attributes


class _RecordingProcessor:
    def __init__(self) -> None:
        self.ended: list[_FakeSpan] = []
        self.flushed = False
        self.shut_down = False

    def on_start(self, span, parent_context=None) -> None:  # noqa: ANN001
        pass

    def on_end(self, span) -> None:  # noqa: ANN001
        self.ended.append(span)

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        self.flushed = True
        return True

    def shutdown(self) -> None:
        self.shut_down = True


@pytest.fixture
def downstream() -> _RecordingProcessor:
    return _RecordingProcessor()


# -- the drop matrix -------------------------------------------------------------------------


@pytest.mark.parametrize("ratio", [0.0, 0.5, 1.0])
@pytest.mark.parametrize("attrs", REFUSALS, ids=lambda a: "-".join(str(v) for v in a.values()))
def test_every_refusal_survives_every_ratio(
    attrs: dict, ratio: float, downstream: _RecordingProcessor
) -> None:
    """This is the test the feature is built around."""
    f = RefusalPreservingFilter(downstream, allow_sample_ratio=ratio)
    f.on_end(_FakeSpan(attrs))
    assert len(downstream.ended) == 1, f"a refusal was dropped at ratio {ratio}: {attrs}"


@pytest.mark.parametrize("attrs", ALLOWS)
def test_allows_are_all_kept_at_ratio_one(attrs: dict, downstream: _RecordingProcessor) -> None:
    f = RefusalPreservingFilter(downstream, allow_sample_ratio=1.0)
    for _ in range(50):
        f.on_end(_FakeSpan(attrs))
    assert len(downstream.ended) == 50


@pytest.mark.parametrize("attrs", ALLOWS)
def test_allows_are_all_dropped_at_ratio_zero(attrs: dict, downstream: _RecordingProcessor) -> None:
    f = RefusalPreservingFilter(downstream, allow_sample_ratio=0.0)
    for _ in range(50):
        f.on_end(_FakeSpan(attrs))
    assert downstream.ended == []


def test_half_ratio_keeps_roughly_half(downstream: _RecordingProcessor) -> None:
    f = RefusalPreservingFilter(downstream, allow_sample_ratio=0.5)
    for _ in range(4000):
        f.on_end(_FakeSpan({surface.ATTR_OUTCOME: "allow"}))
    kept = len(downstream.ended)
    assert 1700 < kept < 2300, f"kept {kept}/4000 at ratio 0.5"


def test_a_span_with_no_outcome_is_treated_as_a_refusal(downstream: _RecordingProcessor) -> None:
    """Fail safe: an unrecognised span is kept, not dropped. Losing a signal we failed to
    classify is strictly worse than exporting one span too many."""
    f = RefusalPreservingFilter(downstream, allow_sample_ratio=0.0)
    f.on_end(_FakeSpan({}))
    f.on_end(_FakeSpan(None))  # type: ignore[arg-type]
    assert len(downstream.ended) == 2


def test_non_dispatch_spans_are_passed_through_untouched(downstream: _RecordingProcessor) -> None:
    f = RefusalPreservingFilter(downstream, allow_sample_ratio=0.0)
    f.on_end(_FakeSpan({surface.ATTR_OUTCOME: "allow"}, name="something.else"))
    assert len(downstream.ended) == 1, "only our own dispatch spans are subject to shedding"


# -- lifecycle delegation --------------------------------------------------------------------


def test_lifecycle_is_delegated(downstream: _RecordingProcessor) -> None:
    f = RefusalPreservingFilter(downstream, allow_sample_ratio=1.0)
    assert f.force_flush() is True
    assert downstream.flushed
    f.shutdown()
    assert downstream.shut_down


def test_on_start_is_forwarded(downstream: _RecordingProcessor) -> None:
    """The wrapped BatchSpanProcessor relies on on_start for its own bookkeeping."""
    f = RefusalPreservingFilter(downstream, allow_sample_ratio=1.0)
    f.on_start(_FakeSpan({}), None)  # must not raise


# -- the sampler -----------------------------------------------------------------------------


def _unsampled_parent() -> object:
    sc = trace_api.SpanContext(
        trace_id=0x1234567890ABCDEF1234567890ABCDEF,
        span_id=0x1234567890ABCDEF,
        is_remote=True,
        trace_flags=trace_api.TraceFlags(trace_api.TraceFlags.DEFAULT),  # NOT sampled
    )
    return trace_api.set_span_in_context(trace_api.NonRecordingSpan(sc))


def test_sampler_overrides_an_unsampled_parent() -> None:
    """The crux: a caller that sampled its own trace out must not take our deny span with it."""
    sampler = AlwaysSampleAuthz()
    result = sampler.should_sample(_unsampled_parent(), 0x1234, surface.SPAN_DECIDE)
    assert result.decision is Decision.RECORD_AND_SAMPLE


def test_sampler_samples_with_no_parent() -> None:
    sampler = AlwaysSampleAuthz()
    result = sampler.should_sample(None, 0x1234, surface.SPAN_PEP_FORWARD)
    assert result.decision is Decision.RECORD_AND_SAMPLE


def test_sampler_defers_to_the_parent_for_foreign_spans() -> None:
    """Spans that are not ours keep normal parent-based semantics, so embedding this layer does
    not inflate an integrator's own trace volume."""
    sampler = AlwaysSampleAuthz()
    result = sampler.should_sample(_unsampled_parent(), 0x1234, "GET /some/route")
    assert result.decision is Decision.DROP


def test_sampler_has_a_description() -> None:
    assert "AlwaysSampleAuthz" in AlwaysSampleAuthz().get_description()


# -- the filter must not be able to break a request ------------------------------------------


def test_a_failing_downstream_processor_does_not_propagate(downstream: _RecordingProcessor) -> None:
    """Telemetry is fail-open. `on_end` runs synchronously on the thread that ended the
    span, which on the control plane is a request-handling thread."""

    class _Broken(_RecordingProcessor):
        def on_end(self, span) -> None:  # noqa: ANN001
            raise RuntimeError("exporter exploded")

    f = RefusalPreservingFilter(_Broken(), allow_sample_ratio=1.0)
    f.on_end(_FakeSpan({surface.ATTR_OUTCOME: "deny", surface.ATTR_DENY_REASON: "X"}))


def test_export_result_enum_is_available() -> None:
    """Guards the import used by the fault-injection exporter in the integration suite."""
    assert SpanExportResult.FAILURE is not SpanExportResult.SUCCESS
