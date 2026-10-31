"""The tracer provider, the sampler, and the refusal-preserving filter.

**Why sampling takes two mechanisms instead of one.** Every refusal must survive
the most aggressive sampling the layer permits, but ``Sampler.should_sample`` runs when a span
*starts* — before the outcome exists. So the work is split:

- ``AlwaysSampleAuthz`` keeps every span in our instrumentation scope at start, **ignoring the
  parent's sampling decision**. An agent trace the integrator sampled out would otherwise take
  our deny span with it. Spans that are not ours keep ordinary parent-based semantics, so
  embedding this layer does not inflate an integrator's own trace volume.
- ``RefusalPreservingFilter`` sheds a fraction of ALLOW spans at ``on_end``, where the outcome
  attribute exists. Refusals never consult the ratio.

The accepted consequence of overriding the parent is a **partial trace**: our span is exported,
its parent is not. That is fine — the span carries ``authz.action_id`` and resolves to the
verified delegation chain on its own. Losing the refusal would not be fine.

Everything here is best-effort. ``on_end`` runs synchronously on the thread that ended the span,
which on the control plane is a request-handling thread, so it does an attribute lookup and a
comparison and swallows any downstream failure.
"""

from __future__ import annotations

import logging
import random
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor
from opentelemetry.sdk.trace.sampling import (
    ALWAYS_ON,
    Decision,
    ParentBased,
    Sampler,
    SamplingResult,
)

from agentic_auth.observability import surface

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Sequence

    from opentelemetry.context import Context
    from opentelemetry.trace import Link, SpanKind
    from opentelemetry.trace.span import TraceState
    from opentelemetry.util.types import Attributes

logger = logging.getLogger(__name__)


class AlwaysSampleAuthz(Sampler):
    """Sample every authorization span, whatever the caller decided; defer otherwise.

    Decision volume is one span per hop — bounded by authorizations, not by tokens or requests —
    so always-on is affordable. ``RefusalPreservingFilter`` is what actually controls volume.
    """

    def __init__(self) -> None:
        self._delegate = ParentBased(root=ALWAYS_ON)

    def should_sample(
        self,
        parent_context: Context | None,
        trace_id: int,
        name: str,
        kind: SpanKind | None = None,
        attributes: Attributes = None,
        links: Sequence[Link] | None = None,
        trace_state: TraceState | None = None,
    ) -> SamplingResult:
        if name in surface.SPAN_NAMES:
            # Carry the parent's trace state through rather than dropping it: the SDK docs
            # recommend propagating it from the parent span context in a custom sampler.
            return SamplingResult(Decision.RECORD_AND_SAMPLE, attributes, trace_state)
        return self._delegate.should_sample(
            parent_context, trace_id, name, kind, attributes, links, trace_state
        )

    def get_description(self) -> str:
        return "AlwaysSampleAuthz{authz spans always sampled, others ParentBased(ALWAYS_ON)}"


class RefusalPreservingFilter(SpanProcessor):
    """Shed allow spans; never shed a refusal.

    Wraps the real exporting processor (normally a ``BatchSpanProcessor``) rather than exporting
    itself, so batching, the bounded queue and the background export thread are all still the
    SDK's.
    """

    def __init__(
        self,
        downstream: SpanProcessor,
        allow_sample_ratio: float = 1.0,
        on_drop: Callable[[], None] | None = None,
    ) -> None:
        self._downstream = downstream
        self._ratio = min(1.0, max(0.0, allow_sample_ratio))
        self._on_drop = on_drop

    # -- classification --------------------------------------------------------------------

    @staticmethod
    def _is_refusal(attributes: Any) -> bool:
        """Anything that is not an unambiguous allow is treated as a refusal.

        Fail safe, deliberately: losing a signal we failed to classify is strictly worse than
        exporting one span too many. A span with no attributes, or with attributes we do not
        recognise, is kept.
        """
        if not attributes:
            return True
        outcome = attributes.get(surface.ATTR_OUTCOME)
        pep_outcome = attributes.get(surface.ATTR_PEP_OUTCOME)
        if outcome is None and pep_outcome is None:
            return True
        if outcome is not None and outcome != "allow":
            return True
        if pep_outcome is not None and pep_outcome != "allowed":
            return True
        # An error on an otherwise-allowed call still needs a human.
        return attributes.get(surface.ATTR_ERROR_TYPE) is not None

    def _keep(self, span: ReadableSpan) -> bool:
        if span.name not in surface.DISPATCH_PATH_SPANS:
            return True
        if self._is_refusal(span.attributes):
            return True
        if self._ratio >= 1.0:
            return True
        if self._ratio <= 0.0:
            return False
        return random.random() < self._ratio

    # -- SpanProcessor ---------------------------------------------------------------------

    def on_start(self, span: Any, parent_context: Context | None = None) -> None:
        try:
            self._downstream.on_start(span, parent_context)
        except Exception:  # pragma: no cover - defensive; telemetry is never fatal
            logger.debug("span processor on_start failed", exc_info=False)

    def on_end(self, span: ReadableSpan) -> None:
        try:
            if self._keep(span):
                self._downstream.on_end(span)
            elif self._on_drop is not None:
                # A sampling drop is telemetry loss and is counted as such.
                self._on_drop()
        except Exception:  # pragma: no cover - defensive; telemetry is never fatal
            # Swallowed on purpose. This runs on the thread that ended the span, which is a
            # request-handling thread: a raise here would turn a telemetry fault into a failed
            # authorization, which telemetry must never do.
            logger.debug("span processor on_end failed", exc_info=False)

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        try:
            return bool(self._downstream.force_flush(timeout_millis))
        except Exception:  # pragma: no cover - defensive
            return False

    def shutdown(self) -> None:
        try:
            self._downstream.shutdown()
        except Exception:  # pragma: no cover - defensive
            logger.debug("span processor shutdown failed", exc_info=False)
