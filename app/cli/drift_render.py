"""Rendering a drift report — text for humans, JSON for machines, and GitHub for pull requests.

Output is deterministic for identical inputs: undeclared edges are already sorted
by the check, JSON keys are sorted, and the one wall-clock field is dropped under
``--deterministic``.

The GitHub rendering is the text output plus two things a reviewer sees without opening a
log: a Markdown table appended to the job's step summary, and one workflow annotation per
undeclared edge, anchored on the manifest that would have to change.
"""

from __future__ import annotations

import json

from app.schemas.edge_trace import DriftReport

VERDICT_TITLES = {
    "UNDECLARED_TOOL": "Undeclared tool edge",
    "UNDECLARED_DELEGATION": "Undeclared delegation edge",
    "UNKNOWN_AGENT": "Unknown agent",
}
RESULT_BADGES = {"pass": "✅", "drift": "❌", "error": "⚠️"}


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def render_json(report: DriftReport) -> str:
    data = report.model_dump(mode="json", by_alias=True)
    if data["inputs"].get("generated_at") is None:
        data["inputs"].pop("generated_at", None)
    return json.dumps(data, sort_keys=True, indent=2)


def render_text(report: DriftReport) -> str:
    summary = report.summary
    lines: list[str] = []

    if report.result == "error":
        lines.append("agentic-auth drift check: ERROR, the check could not run")
        lines.append("")
        for error in report.errors:
            suffix = f" ({error.path})" if error.path else ""
            lines.append(f"  {error.code}: {error.message}{suffix}")
    elif report.result == "drift":
        undeclared = _plural(summary.edges_undeclared, "undeclared edge")
        observed = _plural(summary.edges_observed, "edge")
        lines.append(
            f"agentic-auth drift check: DRIFT, {undeclared} "
            f"({observed} observed, {summary.edges_declared} declared)"
        )
        lines.append("")
        for edge in report.undeclared:
            lines.append(
                f"  {edge.verdict}  {edge.from_} -> {edge.to}   ({_plural(edge.count, 'call')})"
            )
            lines.append(f"    runtime would deny: {edge.runtime_reason}")
            lines.append(f"    declared in: {edge.manifest_path or '(no manifest for this agent)'}")
            lines.append(f"    fix: {edge.hint}")
    else:
        lines.append(
            f"agentic-auth drift check: PASS, {_plural(summary.edges_observed, 'edge')} observed, "
            "all declared"
        )

    if report.warnings:
        lines.append("")
        lines.extend(f"warning: {warning.code}: {warning.message}" for warning in report.warnings)
    return "\n".join(lines)


# -- GitHub ----------------------------------------------------------------------------


def _escape_data(text: str) -> str:
    """Workflow-command message escaping."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    """Workflow-command property escaping: data escaping, plus the separators."""
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_annotations(report: DriftReport) -> list[str]:
    if report.result == "error":
        return [
            "::error title=Drift check could not run::"
            + _escape_data(f"{error.code}: {error.message}")
            for error in report.errors
        ]

    annotations = []
    for edge in report.undeclared:
        message = (
            f"{edge.from_} -> {edge.to} ({_plural(edge.count, 'call')}). "
            f"Runtime would deny with {edge.runtime_reason}."
        )
        location = f"file={_escape_property(edge.manifest_path)}," if edge.manifest_path else ""
        title = _escape_property(VERDICT_TITLES[edge.verdict])
        annotations.append(f"::error {location}title={title}::{_escape_data(message)}")
    return annotations


def render_step_summary(report: DriftReport) -> str:
    summary = report.summary
    lines = [
        f"## {RESULT_BADGES[report.result]} agentic-auth drift check: {report.result.upper()}",
        "",
        "| Edges observed | Declared | Undeclared | Calls | Unattributed calls |",
        "|---|---|---|---|---|",
        f"| {summary.edges_observed} | {summary.edges_declared} | {summary.edges_undeclared} "
        f"| {summary.calls_observed} | {summary.unattributed_calls} |",
    ]
    if report.undeclared:
        lines += [
            "",
            "### Undeclared edges",
            "",
            "| Verdict | From | To | Calls | Runtime reason | Manifest |",
            "|---|---|---|---|---|---|",
        ]
        lines += [
            f"| {_cell(edge.verdict)} | `{_cell(edge.from_)}` | `{_cell(edge.to)}` | {edge.count} "
            f"| {_cell(edge.runtime_reason)} | {_cell(edge.manifest_path or '—')} |"
            for edge in report.undeclared
        ]
    if report.errors:
        lines += ["", "### The check could not run", ""]
        lines += [f"- **{_cell(e.code)}**: {_cell(e.message)}" for e in report.errors]
    if report.warnings:
        lines += ["", "### Warnings", ""]
        lines += [f"- **{_cell(w.code)}**: {_cell(w.message)}" for w in report.warnings]
    return "\n".join(lines) + "\n"


def render_github(report: DriftReport, summary_path: str | None) -> tuple[str, list[str]]:
    """``(text, annotations)``. Appends the Markdown summary to ``summary_path`` when set."""
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(render_step_summary(report))
    return render_text(report), render_annotations(report)
