"""``agentic-auth drift record|check`` — see https://authzai.dev/reference/cli/drift.

``record`` runs a test command with edge recording switched on and aggregates what the
sidecar and SDK observed. ``check`` compares a trace with local manifests, offline, and
exits 0 (pass), 1 (drift), or 2 (could not run) — never 0 without evidence.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import typer
from prometheus_client import write_to_textfile

from app.cli.drift_render import render_github, render_json, render_text
from app.schemas.edge_trace import DriftReport
from app.services.drift import run_check
from app.services.edge_trace import TRACE_PATH_ENV, aggregate
from app.services.metrics import build_drift_metrics

drift_app = typer.Typer(help="Record observed agent edges and check them against manifests")

EXIT_PASS = 0
EXIT_DRIFT = 1
EXIT_ERROR = 2
EXIT_FOR_RESULT = {"pass": EXIT_PASS, "drift": EXIT_DRIFT, "error": EXIT_ERROR}
FORMATS = ("text", "json", "github")
VERDICTS = ("UNDECLARED_TOOL", "UNDECLARED_DELEGATION", "UNKNOWN_AGENT")


def _fail(message: str) -> typer.Exit:
    typer.echo(f"agentic-auth drift: {message}", err=True)
    return typer.Exit(EXIT_ERROR)


@drift_app.command(
    "record",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def record(
    ctx: typer.Context,
    out: Path = typer.Option(..., "--out", help="Where to write the aggregated edge trace"),
    events: Path | None = typer.Option(
        None, "--events", help="Events file to aggregate (required when no command is given)"
    ),
) -> None:
    """Run COMMAND (after --) with edge recording on, then aggregate. Exits with COMMAND's code."""
    command = list(ctx.args)
    if not out.parent.is_dir():
        raise _fail(f"cannot write {out}: directory {out.parent} does not exist")

    started_at = datetime.now(UTC)
    temporary: Path | None = None
    exit_code: int | None = None

    if command:
        if events is not None and events.is_file() and events.stat().st_size > 0:
            raise _fail(f"refusing to mix runs: {events} already contains events")
        if events is None:
            fd, name = tempfile.mkstemp(prefix="agentic-auth-events-", suffix=".jsonl")
            os.close(fd)
            temporary = events_path = Path(name)
        else:
            events_path = events
            events_path.touch()
        os.chmod(events_path, 0o600)

        env = {**os.environ, TRACE_PATH_ENV: str(events_path.resolve())}
        try:
            exit_code = subprocess.run(command, env=env, check=False).returncode  # noqa: S603
        except OSError as exc:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            raise _fail(f"cannot run {command[0]!r}: {type(exc).__name__}") from exc
    else:
        if events is None:
            raise _fail("--events is required when no command is given")
        if not events.is_file():
            raise _fail(f"no events file at {events}")
        events_path = events

    try:
        trace = aggregate(
            [events_path],
            started_at=started_at,
            finished_at=datetime.now(UTC),
            command=command or None,
            exit_code=exit_code,
        )
        out.write_text(trace.model_dump_json(by_alias=True, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise _fail(f"cannot write {out}: {type(exc).__name__}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    typer.echo(
        f"agentic-auth drift record: {len(trace.edges)} edges from {trace.events_total} events "
        f"({trace.unattributed.count} unattributed, {trace.recorder_errors} recorder errors) "
        f"-> {out}",
        err=True,
    )
    raise typer.Exit(exit_code if command and exit_code is not None else EXIT_PASS)


def write_drift_metrics(report: DriftReport, path: Path) -> None:
    """One run's drift metrics, written atomically for the node-exporter textfile collector
    (contracts/metrics.md). Labels carry verdicts and results — never agent names."""
    metrics = build_drift_metrics()
    metrics.checks.labels(result=report.result).inc()
    for verdict in VERDICTS:
        metrics.undeclared_edges.labels(verdict=verdict).set(
            sum(1 for edge in report.undeclared if edge.verdict == verdict)
        )
    metrics.observed_edges.set(report.summary.edges_observed)
    metrics.unattributed_calls.set(report.summary.unattributed_calls)
    write_to_textfile(str(path), metrics.registry)


@drift_app.command("check")
def check(
    manifest: list[Path] = typer.Option(
        ..., "--manifest", help="Manifest directory (repeatable); the union is the declared set"
    ),
    trace: Path = typer.Option(..., "--trace", help="Edge trace from `drift record`"),
    output_format: str = typer.Option("text", "--format", help="text | json | github"),
    report: Path | None = typer.Option(None, "--report", help="Also write the JSON report here"),
    metrics_out: Path | None = typer.Option(
        None, "--metrics-out", help="Write drift metrics to this .prom textfile"
    ),
    deterministic: bool = typer.Option(
        False, "--deterministic", help="Omit the wall-clock timestamp, for golden files"
    ),
) -> None:
    """Compare observed edges with declared manifests. Exit 0 pass, 1 drift, 2 could not run."""
    if output_format not in FORMATS:
        raise _fail(f"--format must be one of {', '.join(FORMATS)}, got {output_format!r}")
    if metrics_out is not None and metrics_out.suffix != ".prom":
        raise _fail("--metrics-out must end in .prom for the node-exporter textfile collector")

    result = run_check(manifest, trace, generated_at=None if deterministic else datetime.now(UTC))

    try:
        if report is not None:
            report.write_text(render_json(result) + "\n", encoding="utf-8")
        if metrics_out is not None:
            write_drift_metrics(result, metrics_out)
    except OSError as exc:
        raise _fail(f"cannot write output: {type(exc).__name__}") from exc

    if output_format == "json":
        typer.echo(render_json(result))
    elif output_format == "github":
        text, annotations = render_github(result, os.environ.get("GITHUB_STEP_SUMMARY"))
        typer.echo(text)
        for annotation in annotations:
            typer.echo(annotation)
    else:
        typer.echo(render_text(result))
    raise typer.Exit(EXIT_FOR_RESULT[result.result])
