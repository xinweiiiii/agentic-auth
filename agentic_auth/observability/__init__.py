"""The observability layer's public surface.

Four functions, and every one of them is safe to call when telemetry is off, when the
OpenTelemetry SDK is not installed, and when the collector is unreachable:

    setup(...)    -> configure this process. Idempotent. Never raises.
    tracer()      -> a tracer; a no-op tracer when disabled.
    config()      -> the resolved ObservabilityConfig, for attribute builders and /status.
    shutdown()    -> flush and stop. Called at process exit, never on a request path.

**Fail-open, by construction**. Telemetry is the opposite posture to audit:
``api/v1/authorize.py`` refuses to return an allow for a decision it could not record, while a
dead collector here changes nothing. Any exception during setup disables telemetry and leaves the
component running — a guardrail that refused to start because a collector was down would be an
availability regression caused by an observability feature.

**This module never calls ``set_tracer_provider()`` for a process it does not own.** That
function is process-global and warns-and-ignores on a second call, so a library that calls it
either hijacks the host's pipeline or silently emits nothing. The control plane and the sidecar
own their processes and opt in explicitly via ``install_globally=True``; the verifier library
never does.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, Any

from agentic_auth.observability.config import (
    DISABLED,
    ObservabilityConfig,
    from_settings,
    sdk_available,
)
from agentic_auth.observability.context import extract_parent, inject
from agentic_auth.observability.spans import (
    decision_attributes,
    exchange_attributes,
    mint_attributes,
    pep_attributes,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from opentelemetry.trace import Tracer

logger = logging.getLogger(__name__)

__all__ = [
    "ObservabilityConfig",
    "OtelSink",
    "config",
    "decision_attributes",
    "exchange_attributes",
    "extract_parent",
    "inject",
    "mint_attributes",
    "pep_attributes",
    "setup",
    "shutdown",
    "tracer",
]

INSTRUMENTATION_SCOPE = "agentic-auth"

_config: ObservabilityConfig = DISABLED
_provider: Any = None
_logging_handler: Any = None


def config() -> ObservabilityConfig:
    return _config


def setup(
    *,
    service_name: str = "control_plane",
    resolved: ObservabilityConfig | None = None,
    install_globally: bool = True,
    metrics: Any = None,
    exporter: Any = None,
    synchronous_export: bool = False,
) -> ObservabilityConfig:
    """Configure telemetry for this process. Idempotent, and never raises.

    ``resolved`` lets the sidecar pass its own configuration instead of the control plane's
    settings. ``metrics`` is a registry whose ``telemetry_dropped`` counter the export pipeline
    feeds, so telemetry loss reports itself. ``exporter`` overrides the OTLP exporter —
    the tests pass an in-memory one, and the fault-injection suite passes a failing one.
    ``synchronous_export`` swaps the batching processor for a simple one, so a test sees a span
    the moment it ends instead of having to flush.
    """
    global _config, _provider, _logging_handler

    if _provider is not None:
        return _config

    try:
        _config = resolved if resolved is not None else from_settings(service_name)
    except Exception:
        logger.warning("could not resolve telemetry configuration; telemetry is off")
        _config = DISABLED
        return _config

    _config.log_state_once()
    if not _config.enabled:
        return _config

    try:
        _provider, _logging_handler = _build_pipeline(
            _config, install_globally, metrics, exporter, synchronous_export
        )
    except Exception:
        # Deliberately broad. Any failure here — a missing exporter extra, a malformed
        # endpoint, a provider that cannot start — must leave the process serving.
        logger.warning("telemetry setup failed; continuing without it", exc_info=False)
        _config = ObservabilityConfig(
            enabled=False,
            key=_config.key,
            identity_disclosure=False,
            allow_sample_ratio=_config.allow_sample_ratio,
            service_name=_config.service_name,
            state="setup_failed",
        )
        _provider = None
    return _config


def _build_pipeline(
    cfg: ObservabilityConfig,
    install_globally: bool,
    metrics: Any,
    exporter: Any = None,
    synchronous_export: bool = False,
) -> tuple[Any, Any]:
    """Build the tracer provider and the logging bridge. Imported lazily: these are the optional
    ``otel`` extra, and nothing above may import them at module scope."""
    from opentelemetry import trace as trace_api
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor

    from agentic_auth.observability.tracing import AlwaysSampleAuthz, RefusalPreservingFilter

    resource = Resource.create({"service.name": f"agentic-auth-{cfg.service_name}"})
    provider = TracerProvider(sampler=AlwaysSampleAuthz(), resource=resource)

    exporter = exporter if exporter is not None else _span_exporter()
    if exporter is not None:
        # BatchSpanProcessor is the bounded queue and the background export thread. Giving it a
        # meter_provider is what makes its own dropped/queued counts observable, rather than us
        # counting them by hand.
        batch = (
            SimpleSpanProcessor(exporter)
            if synchronous_export
            else BatchSpanProcessor(exporter, meter_provider=_meter_provider(metrics))
        )
        provider.add_span_processor(
            RefusalPreservingFilter(
                batch,
                allow_sample_ratio=cfg.allow_sample_ratio,
                on_drop=_drop_recorder(metrics),
            )
        )

    if install_globally:
        trace_api.set_tracer_provider(provider)

    return provider, _install_log_bridge(cfg)


def _drop_recorder(metrics: Any) -> Any:
    """Feed ``agentic_auth_telemetry_dropped`` from the sampling filter.

    Sampling drops and queue-overflow drops are both telemetry loss, and the design requires the
    loss to report itself. ``None`` when there is no registry to write to.
    """
    if metrics is None:
        return None

    def _record() -> None:
        with contextlib.suppress(Exception):  # pragma: no cover - never fatal
            metrics.telemetry_dropped.labels(signal="span").inc()

    return _record


def _span_exporter() -> Any:
    """The OTLP/HTTP span exporter, or ``None`` when no endpoint is configured.

    Endpoint, headers, timeout and protocol all come from the standard ``OTEL_EXPORTER_OTLP_*``
    variables, read by the exporter itself. We define no names of our own, which is what makes
    the "configuration only" promise true for an integrator who already sets them.
    """
    import os

    if not (
        os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    ):
        # No endpoint: traces are recorded in-process but not shipped. The local surfaces
        # (/metrics, JSON logs on stdout) remain fully functional, and this is not an error.
        return None
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    return OTLPSpanExporter()


def _meter_provider(metrics: Any) -> Any:
    """BatchSpanProcessor's self-instrumentation target.

    ``None`` means the SDK uses the global meter provider, which is a no-op unless the integrator
    configured one. We do not install an OTel meter provider: metrics stay on
    ``prometheus-client``, and ``agentic_auth_telemetry_dropped`` is incremented
    from the drop path instead.
    """
    return None


def _install_log_bridge(cfg: ObservabilityConfig) -> Any:
    """Attach OTel's ``LoggingHandler`` to the root logger when an endpoint is configured.

    The handler exports every non-reserved ``LogRecord`` attribute, so ``extra=`` arrives as
    structured attributes with no adapter, and it attaches ``trace_id``/``span_id`` from the
    active context automatically.
    """
    import os

    if not (
        os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or os.environ.get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
    ):
        return None

    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.resources import Resource

    provider = LoggerProvider(
        resource=Resource.create({"service.name": f"agentic-auth-{cfg.service_name}"})
    )
    provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
    handler = LoggingHandler(logger_provider=provider)
    logging.getLogger().addHandler(handler)
    return handler


class _NoOpSpan:
    """A span that does nothing, implemented without OpenTelemetry.

    OTel's own ``NoOpTracer`` would be the obvious choice, but importing it requires the
    optional extra — the very thing that may be missing. So call sites can use
    ``with tracer().start_as_current_span(...)`` unconditionally, in every configuration,
    including a deployment that never installed the extra.
    """

    __slots__ = ()

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_attributes(self, attributes: Any) -> None:
        pass

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        pass

    def add_event(self, *args: Any, **kwargs: Any) -> None:
        pass

    def record_exception(self, *args: Any, **kwargs: Any) -> None:
        pass

    def update_name(self, name: str) -> None:
        pass

    def is_recording(self) -> bool:
        return False

    def end(self, end_time: int | None = None) -> None:
        pass


class _NoOpTracer:
    """Mirrors the slice of the OTel ``Tracer`` protocol this layer uses."""

    __slots__ = ()

    @contextlib.contextmanager
    def start_as_current_span(self, name: str, *args: Any, **kwargs: Any) -> Any:
        yield _NoOpSpan()

    def start_span(self, name: str, *args: Any, **kwargs: Any) -> _NoOpSpan:
        return _NoOpSpan()


_NO_OP_TRACER = _NoOpTracer()


def tracer() -> Tracer:
    """A tracer for this layer's spans. A no-op when telemetry is off, so call sites need no
    conditionals — ``with tracer().start_as_current_span(...)`` is always valid."""
    if _provider is not None:
        return _provider.get_tracer(INSTRUMENTATION_SCOPE)
    return _NO_OP_TRACER  # type: ignore[return-value]


class OtelSink:
    """An OTel-backed :class:`agentic_auth.verify.TelemetrySink`, constructed by the integrator.

    Lives here rather than in ``agentic_auth/verify/`` because the verifier must stay importable
    with only ``pyjwt[crypto]``. The provider is passed in, never discovered and
    never installed: ``set_tracer_provider`` is process-global, so a library that calls it in a
    host it does not own either hijacks the host's pipeline or silently emits nothing.

        from opentelemetry import trace
        from agentic_auth.observability import OtelSink
        from agentic_auth.verify import Verifier

        verifier = Verifier(..., telemetry=OtelSink(trace.get_tracer_provider()))

    Attributes are passed through as given: the verifier runs in the integrator's process, so
    it is their disclosure policy that applies, not ours.
    """

    __slots__ = ("_tracer",)

    def __init__(self, tracer_provider: Any, scope: str = INSTRUMENTATION_SCOPE) -> None:
        self._tracer = tracer_provider.get_tracer(scope)

    def span(self, name: str, attributes: Any) -> None:
        clean = {k: v for k, v in dict(attributes).items() if v is not None}
        with self._tracer.start_as_current_span(name, attributes=clean, record_exception=False):
            pass

    def event(self, name: str, attributes: Any) -> None:
        from opentelemetry import trace as trace_api

        clean = {k: v for k, v in dict(attributes).items() if v is not None}
        trace_api.get_current_span().add_event(name, attributes=clean)


def shutdown(timeout_millis: int = 5000) -> None:
    """Flush and stop. Called at process exit only.

    ``force_flush`` is the one place telemetry can block, which is why it is never called on a
    request path.
    """
    global _provider, _logging_handler
    provider, _provider = _provider, None
    handler, _logging_handler = _logging_handler, None

    if handler is not None:
        with contextlib.suppress(Exception):  # pragma: no cover - defensive
            logging.getLogger().removeHandler(handler)
    if provider is not None:
        try:
            provider.force_flush(timeout_millis)
            provider.shutdown()
        except Exception:  # pragma: no cover - defensive
            logger.debug("telemetry shutdown failed", exc_info=False)


def _reset_for_tests() -> None:
    """Tear down module state between tests. Not part of the public surface."""
    global _config
    shutdown(timeout_millis=100)
    _config = DISABLED
    sdk_available.cache_clear()
