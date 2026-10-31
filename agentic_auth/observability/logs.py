"""Structured logs: a JSON formatter for stdout, and correlation fields via ``extra=``.

**No new logging library.** Two properties of OTel's ``LoggingHandler`` make the standard
library sufficient:

- It exports every non-reserved attribute of the ``LogRecord``, so ``extra={...}`` arrives at
  the backend as structured attributes with no adapter in between.
- It builds the exported record with ``context=get_current()``, so ``trace_id`` and ``span_id``
  are attached from the active span automatically — trace linkage needs no code at the
  call sites.

It also maps Python levels to OTel severities (``WARNING``→``WARN``, ``CRITICAL``→``FATAL``),
which is what alerting needs: an expected policy deny at ``INFO`` and an unreachable control plane
at ``WARNING`` arrive distinguishable, with no custom mapping from us.

**What this module deliberately does not do** is record exceptions. ``logger.exception(...)``
sets ``exc_info``, and ``LoggingHandler`` then exports ``exception.message`` (as
``str(value.args[0])``) and ``exception.stacktrace`` (the full formatted traceback). A traceback
through token verification can carry a token fragment, so dispatch-path call sites log
``error.type`` and a static message instead. :func:`scrub_exception_fields` is the backstop that
strips those keys if one slips through.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agentic_auth.observability import surface

# Attributes the logging module puts on every record. Anything outside this set came from an
# `extra=`, which is what we want to export.
_RESERVED = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

# Never exported, even if something sets them. The SDK adds the first three itself when
# `exc_info` is present.
FORBIDDEN_LOG_FIELDS = frozenset(
    {"exception.message", "exception.stacktrace", "exception.type", "exc_info", "exc_text"}
)


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with the correlation fields hoisted to the top level.

    Used for stdout. When an OTLP sink is configured the same records also go through
    ``LoggingHandler``, so a deployment with no collector still gets machine-parsable logs on
    stdout — "the local surfaces remain fully functional".
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        for key, value in vars(record).items():
            if key in _RESERVED or key in FORBIDDEN_LOG_FIELDS or key.startswith("_"):
                continue
            payload[key] = value if _jsonable(value) else str(value)

        span = _active_span_ids()
        if span is not None:
            payload["trace_id"], payload["span_id"] = span
        return json.dumps(payload, default=str, sort_keys=True)


def _jsonable(value: Any) -> bool:
    return isinstance(value, str | int | float | bool | type(None) | list | dict)


def _active_span_ids() -> tuple[str, str] | None:
    """The active trace and span ids, or ``None``.

    Imported lazily and failure-tolerantly: this must work in a process that never installed
    the optional OpenTelemetry extra.
    """
    try:
        from opentelemetry import trace as trace_api
    except ImportError:
        return None
    try:
        ctx = trace_api.get_current_span().get_span_context()
    except Exception:  # pragma: no cover - defensive
        return None
    if not ctx.is_valid:
        return None
    return format(ctx.trace_id, "032x"), format(ctx.span_id, "016x")


def fields(
    component: str,
    *,
    session_id: Any = None,
    action_id: Any = None,
    hop: int | None = None,
    error_type: str | None = None,
) -> dict[str, Any]:
    """Build the ``extra=`` mapping for a dispatch-path log record.

    Only the fields in ``surface.LOG_FIELDS`` are produced, so a log record cannot acquire a
    key the telemetry surface does not declare. Identifiers go here rather than into the
    message, so the messages stay static and group.
    """
    out: dict[str, Any] = {surface.LOG_COMPONENT: component}
    if session_id is not None:
        out[surface.ATTR_SESSION_ID] = str(session_id)
    if action_id is not None:
        out[surface.ATTR_ACTION_ID] = str(action_id)
    if hop is not None:
        out[surface.ATTR_HOP] = hop
    if error_type is not None:
        out[surface.ATTR_ERROR_TYPE] = error_type
    return out


def scrub_exception_fields(record: logging.LogRecord) -> logging.LogRecord:
    """Drop ``exc_info`` so no stack trace is exported. The backstop for the no-secrets rule,
    not the primary control — the primary control is that dispatch-path sites do not call
    ``logger.exception`` at all."""
    record.exc_info = None
    record.exc_text = None
    return record


class DispatchPathFilter(logging.Filter):
    """Strips exception payloads from records emitted by the dispatch-path loggers.

    Installed on the handlers rather than the loggers, so a library logger that happens to be
    a child of one of these names is covered too.
    """

    LOGGERS = (
        "agentic_auth.api.v1.authorize",
        "agentic_auth.api.v1.token",
        "agentic_auth.api.v1.transaction",
        "agentic_auth.services.audit",
        "agentic_auth.services.transactions",
        "agentic_auth.sidecar.enforce",
        "agentic_auth.sidecar.app",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        if record.exc_info and record.name.startswith(self.LOGGERS):
            scrub_exception_fields(record)
        return True


def configure(stream_handler: logging.Handler | None = None) -> logging.Handler:
    """Install JSON formatting and the exception filter on the root logger.

    Idempotent: calling it twice does not stack handlers, because a process that is configured
    twice (an app factory invoked per test, say) should not emit every line twice.
    """
    root = logging.getLogger()
    for existing in root.handlers:
        if getattr(existing, "_agentic_auth_json", False):
            return existing

    handler = stream_handler or logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(DispatchPathFilter())
    handler._agentic_auth_json = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    return handler
