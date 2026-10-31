"""GitHub rendering: the step summary and one annotation per undeclared edge."""

from __future__ import annotations

from typer.testing import CliRunner

from agentic_auth.cli import app
from agentic_auth.cli.drift_render import (
    render_annotations,
    render_github,
    render_step_summary,
    render_text,
)
from agentic_auth.schemas.edge_trace import (
    DriftError,
    DriftInputs,
    DriftReport,
    DriftSummary,
    DriftWarning,
    UndeclaredEdge,
)

INPUTS = DriftInputs(
    manifest_dirs=["manifests"], trace="t.json", manifests_loaded=3, skipped_files=[]
)


def undeclared(
    verdict: str = "UNDECLARED_TOOL",
    *,
    caller: str = "support-agent",
    target: str = "mcp://accounts.internal/terminate_account",
    manifest_path: str | None = "manifests/support-agent.yaml",
    count: int = 3,
) -> UndeclaredEdge:
    return UndeclaredEdge(
        from_=caller,
        to=target,
        kind="delegation" if target.startswith("agent://") else "tool",
        count=count,
        verdict=verdict,  # type: ignore[arg-type]
        runtime_reason="EDGE_NOT_IN_DAG" if verdict == "UNDECLARED_DELEGATION" else "OUT_OF_SCOPE",
        manifest_path=manifest_path,
        hint="fix it",
    )


def report(result: str, edges=(), errors=(), warnings=()) -> DriftReport:
    return DriftReport(
        result=result,  # type: ignore[arg-type]
        summary=DriftSummary(
            edges_observed=3,
            edges_declared=3 - len(edges),
            edges_undeclared=len(edges),
            calls_observed=5,
            unattributed_calls=1,
        ),
        undeclared=list(edges),
        errors=list(errors),
        warnings=list(warnings),
        inputs=INPUTS,
    )


# -- annotations --------------------------------------------------------------------


def test_an_undeclared_tool_is_annotated_on_its_manifest() -> None:
    assert render_annotations(report("drift", [undeclared()])) == [
        "::error file=manifests/support-agent.yaml,title=Undeclared tool edge::"
        "support-agent -> mcp://accounts.internal/terminate_account (3 calls). "
        "Runtime would deny with OUT_OF_SCOPE."
    ]


def test_an_undeclared_delegation_has_its_own_title() -> None:
    [line] = render_annotations(
        report(
            "drift",
            [
                undeclared(
                    "UNDECLARED_DELEGATION",
                    caller="balance-agent",
                    target="agent://fraud-agent",
                    count=1,
                )
            ],
        )
    )
    assert "title=Undeclared delegation edge::" in line
    assert "(1 call). Runtime would deny with EDGE_NOT_IN_DAG." in line


def test_an_unknown_agent_has_no_file_to_anchor_on() -> None:
    [line] = render_annotations(
        report("drift", [undeclared("UNKNOWN_AGENT", caller="ghost", manifest_path=None)])
    )
    assert line.startswith("::error title=Unknown agent::")
    assert "file=" not in line


def test_a_check_that_could_not_run_says_why() -> None:
    errors = [DriftError(code="NO_EDGES_OBSERVED", message="nothing was recorded")]
    assert render_annotations(report("error", errors=errors)) == [
        "::error title=Drift check could not run::NO_EDGES_OBSERVED: nothing was recorded"
    ]


def test_workflow_command_characters_are_escaped() -> None:
    [line] = render_annotations(report("drift", [undeclared(manifest_path="odd,dir/100%:x.yaml")]))
    assert "file=odd%2Cdir/100%25%3Ax.yaml," in line

    errors = [DriftError(code="MANIFEST_INVALID", message="line one\nline two 50%")]
    [error_line] = render_annotations(report("error", errors=errors))
    assert error_line.endswith("MANIFEST_INVALID: line one%0Aline two 50%25")


def test_a_pass_emits_no_annotations() -> None:
    assert render_annotations(report("pass")) == []


# -- step summary ------------------------------------------------------------------


def test_the_step_summary_tables_each_undeclared_edge() -> None:
    summary = render_step_summary(
        report(
            "drift",
            [undeclared()],
            warnings=[DriftWarning(code="UNATTRIBUTED_CALLS", message="1 call")],
        )
    )

    assert summary.startswith("## ❌ agentic-auth drift check: DRIFT")
    assert "| 3 | 2 | 1 | 5 | 1 |" in summary
    assert (
        "| UNDECLARED_TOOL | `support-agent` | `mcp://accounts.internal/terminate_account` | 3 "
        "| OUT_OF_SCOPE | manifests/support-agent.yaml |"
    ) in summary
    assert "**UNATTRIBUTED_CALLS**" in summary


def test_render_github_appends_to_the_summary_file_and_returns_the_text(tmp_path) -> None:
    summary_file = tmp_path / "summary.md"
    summary_file.write_text("earlier step\n")
    drifted = report("drift", [undeclared()])

    text, annotations = render_github(drifted, str(summary_file))

    assert text == render_text(drifted)
    assert len(annotations) == 1
    content = summary_file.read_text()
    assert content.startswith("earlier step\n")  # appended, never overwritten
    assert "agentic-auth drift check: DRIFT" in content


def test_render_github_without_a_summary_file_still_renders() -> None:
    text, annotations = render_github(report("pass"), None)
    assert "PASS" in text
    assert annotations == []


def test_the_cli_github_format_prints_text_then_annotations(tmp_path, monkeypatch) -> None:
    import yaml

    from tests.fixtures.bank import bank_docs
    from tests.unit.test_drift_cli import DRIFT_EDGES, write_manifests, write_trace

    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    manifests = write_manifests(tmp_path / "manifests", bank_docs())
    assert yaml  # manifests are YAML on disk

    result = CliRunner().invoke(
        app,
        [
            "drift",
            "check",
            "--manifest",
            str(manifests),
            "--trace",
            str(write_trace(tmp_path / "t.json", DRIFT_EDGES)),
            "--format",
            "github",
        ],
    )

    assert result.exit_code == 1
    lines = result.stdout.splitlines()
    assert lines[0].startswith("agentic-auth drift check: DRIFT")
    assert lines[-1].startswith(
        f"::error file={manifests / 'support-agent.yaml'},title=Undeclared tool edge::"
    )
    assert "Undeclared edges" in summary_file.read_text()
