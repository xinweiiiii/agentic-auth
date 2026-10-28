"""The CI gate, callable from code.

``agentic-auth drift record`` and ``drift check`` are the command-line form of exactly
this: aggregate the edge events an enforcement point recorded into one trace, then ask
whether every observed edge was declared. These functions exist so a pipeline — or a
notebook — can run the same gate in-process and branch on the report instead of parsing
stdout.

Both run from files only. No discovery, no reconciliation, no control plane, no
credentials: the question is only "was every observed edge declared", and CI should be
able to answer it offline.

Never a pass without evidence. Invalid or missing inputs, lost events, and a run that
observed nothing at all are each a distinct ``error`` in the report, and
:func:`check_drift` reports those as a failure rather than a pass.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from app.schemas.edge_trace import DriftReport, EdgeTrace
from app.services.drift import run_check
from app.services.edge_trace import TRACE_PATH_ENV, EdgeRecorder, aggregate

# What CI exits with. `drift check` uses the same two codes.
PASS_EXIT = 0
FAIL_EXIT = 1


def trace_recorder(path: str | os.PathLike[str]) -> EdgeRecorder:
    """An edge recorder writing to ``path``, for an enforcement point the SDK does not own.

    An ``AgenticAuthClient`` built with ``trace_path=`` (or with
    ``AGENTIC_AUTH_TRACE_PATH`` set, which is how ``drift record`` wires a child process)
    already records one event per ``authorize``. Use this only to record edges taken by
    something else — a hand-rolled call path, or a test harness standing in for one.
    """
    return EdgeRecorder(path, "sdk")


def trace_env(path: str | os.PathLike[str]) -> dict[str, str]:
    """The environment a child process needs to record into ``path``.

    ``{**os.environ, **trace_env(p)}`` is what ``drift record`` passes to the command it
    wraps, so every SDK client and sidecar inside it records to one file.
    """
    return {TRACE_PATH_ENV: os.fspath(path)}


def aggregate_trace(
    event_files: Sequence[str | os.PathLike[str]],
    *,
    out: str | os.PathLike[str] | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    command: list[str] | None = None,
    exit_code: int | None = None,
) -> EdgeTrace:
    """Deduplicate recorded events into one trace — the ``drift record`` half of the gate.

    ``recorder_errors`` counts evidence that was lost (an unparseable line, a killed
    process, a write that failed). A non-zero count is why :func:`check_drift` refuses to
    report a pass: a shrunken trace would otherwise look like a clean run.
    """
    now = datetime.now(UTC)
    trace = aggregate(
        [Path(os.fspath(f)) for f in event_files],
        started_at=started_at or now,
        finished_at=finished_at or now,
        command=command,
        exit_code=exit_code,
    )
    if out is not None:
        Path(os.fspath(out)).write_text(trace.model_dump_json(indent=2), encoding="utf-8")
    return trace


def check_drift(
    manifest_dirs: Sequence[str | os.PathLike[str]],
    trace: str | os.PathLike[str],
    *,
    generated_at: datetime | None = None,
) -> DriftReport:
    """Observed edges versus declared manifests — the ``drift check`` half of the gate.

    The verdict for every edge comes from the same function the runtime PDP calls, over an
    index built by the same compiler, so a pipeline and production cannot disagree about
    what the manifests declare.
    """
    return run_check(
        [Path(os.fspath(d)) for d in manifest_dirs],
        Path(os.fspath(trace)),
        generated_at=generated_at,
    )


def exit_code_for(report: DriftReport) -> int:
    """``0`` only for a clean, evidenced pass: no undeclared edges and no errors."""
    return PASS_EXIT if report.result == "pass" else FAIL_EXIT


__all__ = [
    "FAIL_EXIT",
    "PASS_EXIT",
    "aggregate_trace",
    "check_drift",
    "exit_code_for",
    "trace_env",
    "trace_recorder",
]
