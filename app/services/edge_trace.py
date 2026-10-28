"""Recording observed edges, and aggregating them into a trace.

**Recording is passive and cannot change enforcement.** The sidecar and SDK call
:meth:`EdgeRecorder.record` *after* an outcome is fixed, and ``record`` never raises: a write
that fails is counted, and the count is written into the events file on the next success,
so lost evidence surfaces as ``recorder_errors`` — which makes ``drift check`` refuse to
report a pass — instead of silently shrinking the trace.

**Lines are appended atomically.** One ``os.write`` of one line under 4 KiB, on a descriptor
opened ``O_APPEND``, so several recorders sharing a file on a local filesystem never
interleave partial lines. Networked filesystems are not supported for shared event files.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from app.schemas.edge_trace import (
    EVALUATED_OUTCOMES,
    EdgeEvent,
    EdgeOutcomes,
    EdgeTrace,
    ObservedEdge,
    RecorderErrorLine,
    Source,
    TraceRun,
    Unattributed,
    kind_of,
)

logger = logging.getLogger(__name__)

TRACE_PATH_ENV = "AGENTIC_AUTH_TRACE_PATH"
MAX_LINE_BYTES = 4096


class EdgeRecorder:
    def __init__(self, path: str | os.PathLike[str], source: Source) -> None:
        self._path = os.fspath(path)
        self._source: Source = source
        self._lost = 0
        self._lock = threading.Lock()

    @property
    def path(self) -> str:
        return self._path

    @property
    def lost(self) -> int:
        """Events not yet accounted for in the file."""
        return self._lost

    def record(
        self,
        *,
        acting_agent: str | None,
        target: str | None,
        outcome: str,
        reason: str | None,
    ) -> None:
        try:
            event = EdgeEvent(
                ts=datetime.now(UTC),
                source=self._source,
                acting_agent=acting_agent,
                target=target,
                kind=kind_of(target),
                outcome=outcome,
                reason=reason,
            )
        except (ValidationError, ValueError):
            # An event this recorder cannot express faithfully is a lost event, never a
            # guessed one.
            self._note_loss("event did not fit the edge-event schema")
            return
        self._append(event.model_dump_json())

    def _note_loss(self, why: str) -> None:
        with self._lock:
            self._lost += 1
        logger.error("edge recorder %s lost an event: %s", self._path, why)

    def _append(self, line: str) -> None:
        data = (line + "\n").encode("utf-8")
        if len(data) > MAX_LINE_BYTES:
            self._note_loss("event line exceeds 4 KiB")
            return
        with self._lock:
            try:
                fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            except OSError as exc:
                self._lost += 1
                logger.error("edge recorder cannot open %s: %s", self._path, type(exc).__name__)
                return
            try:
                if self._lost:
                    lost_line = RecorderErrorLine(
                        ts=datetime.now(UTC), source=self._source, recorder_error=self._lost
                    ).model_dump_json()
                    os.write(fd, (lost_line + "\n").encode("utf-8"))
                    self._lost = 0
                if os.write(fd, data) != len(data):
                    self._lost += 1
            except OSError as exc:
                self._lost += 1
                logger.error("edge recorder cannot write %s: %s", self._path, type(exc).__name__)
            finally:
                os.close(fd)


def recorder_from_env(source: Source) -> EdgeRecorder | None:
    path = os.environ.get(TRACE_PATH_ENV)
    return EdgeRecorder(path, source) if path else None


def aggregate(
    event_files: Sequence[Path],
    *,
    started_at: datetime,
    finished_at: datetime,
    command: list[str] | None,
    exit_code: int | None,
) -> EdgeTrace:
    """Deduplicate recorded events into one trace. Anything unreadable counts against it."""
    buckets: dict[tuple[str, str], Counter[str]] = {}
    unattributed: Counter[str] = Counter()
    recorder_errors = 0
    events_total = 0

    for event_file in event_files:
        if not event_file.is_file():
            continue
        for raw in event_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except ValueError:
                recorder_errors += 1  # includes a line truncated by a killed process
                continue

            if isinstance(obj, dict) and "recorder_error" in obj:
                try:
                    recorder_errors += RecorderErrorLine.model_validate(obj).recorder_error
                except ValidationError:
                    recorder_errors += 1
                continue

            try:
                event = EdgeEvent.model_validate(obj)
            except ValidationError:
                recorder_errors += 1
                continue

            events_total += 1
            if event.acting_agent and event.target and event.outcome in EVALUATED_OUTCOMES:
                buckets.setdefault((event.acting_agent, event.target), Counter())[
                    event.outcome
                ] += 1
            else:
                unattributed[event.reason or event.outcome.upper()] += 1

    edges = [
        ObservedEdge(
            from_=caller,
            to=target,
            kind=kind_of(target) or "tool",
            count=sum(outcomes.values()),
            outcomes=EdgeOutcomes(
                allow=outcomes["allow"], deny=outcomes["deny"], observed=outcomes["observed"]
            ),
        )
        for (caller, target), outcomes in sorted(buckets.items())
    ]
    return EdgeTrace(
        run=TraceRun(
            started_at=started_at,
            finished_at=finished_at,
            command=command,
            event_files=[str(f) for f in event_files],
            exit_code=exit_code,
        ),
        edges=edges,
        unattributed=Unattributed(
            count=sum(unattributed.values()), by_reason=dict(sorted(unattributed.items()))
        ),
        recorder_errors=recorder_errors,
        events_total=events_total,
    )
