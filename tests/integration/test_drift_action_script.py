"""The composite action's shell, executed.

`action.yml` is the one deliverable whose behaviour normally cannot be observed without
opening a pull request: the workflow in `.github/workflows/drift-check-fixture.yml` proves it
on GitHub, but only after a change is already pushed. These tests extract the step scripts
verbatim and run them, so a broken `$GITHUB_OUTPUT` capture, a swallowed error, or a mangled
heredoc fails here instead of on someone's PR.

They assert the action's contract: outputs, exit codes, and the two things a reviewer
actually sees — the step summary and one annotation per undeclared edge.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
ACTION = REPO / "actions" / "drift-check" / "action.yml"
FIXTURE = REPO / "examples" / "drift-fixture"
MANIFESTS = FIXTURE / "manifests"
WIDENED = FIXTURE / "manifests-widened"
MALFORMED = FIXTURE / "malformed.edge-trace.json"

DRIFTED_EDGES = [
    ("bank-assistant", "agent://balance-agent", "delegation"),
    ("balance-agent", "agent://support-agent", "delegation"),
    ("support-agent", "mcp://accounts.internal/terminate_account", "tool"),
]


def step_script(name_fragment: str) -> str:
    steps = yaml.safe_load(ACTION.read_text())["runs"]["steps"]
    for step in steps:
        if name_fragment in (step.get("name") or ""):
            return step["run"]
    raise AssertionError(f"no step named like {name_fragment!r} in {ACTION}")


def write_trace(path: Path, edges=DRIFTED_EDGES) -> Path:
    """A trace of the PRD scenario, in the shape `drift record` produces."""
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run": {
                    "started_at": "2026-09-13T10:00:00Z",
                    "finished_at": "2026-09-13T10:00:01Z",
                    "command": None,
                    "event_files": [],
                    "exit_code": 0,
                },
                "edges": [
                    {
                        "from": caller,
                        "to": target,
                        "kind": kind,
                        "count": 1,
                        "outcomes": {"allow": 0, "deny": 0, "observed": 1},
                    }
                    for caller, target, kind in edges
                ],
                "unattributed": {"count": 0, "by_reason": {}},
                "recorder_errors": 0,
                "events_total": len(edges),
            }
        )
    )
    return path


class ActionRun:
    def __init__(self, tmp_path: Path, completed: subprocess.CompletedProcess[str]) -> None:
        self.exit_code = completed.returncode
        self.stdout = completed.stdout
        self.outputs = dict(
            line.split("=", 1)
            for line in (tmp_path / "output").read_text().splitlines()
            if "=" in line
        )
        self.summary = (tmp_path / "summary").read_text()

    @property
    def annotations(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.startswith("::")]


def run_check_step(
    tmp_path: Path, *, manifests, trace: Path, fail_on_drift: str = "true"
) -> ActionRun:
    """Run the action's check step the way the runner does: inputs only through the env."""
    if isinstance(manifests, Path | str):
        manifests = [manifests]
    (tmp_path / "output").write_text("")
    (tmp_path / "summary").write_text("")

    env = {
        **os.environ,
        # The action installs the CLI; here it is already on PATH from the venv running pytest.
        "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
        "MANIFESTS": "\n".join(str(m) for m in manifests),
        "TRACE": str(trace),
        "REPORT_PATH": str(tmp_path / "report.json"),
        "FAIL_ON_DRIFT": fail_on_drift,
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
    }
    completed = subprocess.run(
        ["bash", "-c", step_script("Check observed edges")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return ActionRun(tmp_path, completed)


pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="the action runs on bash")


# -- results the PR check reports ------------------------------------------------------


def test_an_undeclared_edge_fails_the_check_and_sets_the_outputs(tmp_path) -> None:
    run = run_check_step(tmp_path, manifests=MANIFESTS, trace=write_trace(tmp_path / "t.json"))

    assert run.exit_code == 1
    assert run.outputs["result"] == "drift"
    assert run.outputs["undeclared-count"] == "1"
    assert run.outputs["report-path"] == str(tmp_path / "report.json")
    assert json.loads((tmp_path / "report.json").read_text())["result"] == "drift"


def test_widening_the_manifest_passes(tmp_path) -> None:
    run = run_check_step(tmp_path, manifests=WIDENED, trace=write_trace(tmp_path / "t.json"))

    assert run.exit_code == 0
    assert run.outputs == {
        "result": "pass",
        "undeclared-count": "0",
        "report-path": str(tmp_path / "report.json"),
    }


def test_several_manifest_directories_are_split_on_newlines(tmp_path) -> None:
    """The `manifests` input is newline-separated, and YAML block scalars leave indentation
    behind easily — an unstripped path finds no manifests and the check would wrongly error.

    The agents are split across two directories (the widened fixture redeclares all three, so
    pairing it with `manifests/` is a real duplicate, not a split).
    """
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    for name in ("bank-assistant.yaml", "balance-agent.yaml"):
        shutil.copy(MANIFESTS / name, first / name)
    shutil.copy(WIDENED / "support-agent.yaml", second / "support-agent.yaml")

    run = run_check_step(
        tmp_path,
        # A leading-space path, a blank line, and a clean one — all three must be handled.
        manifests=[f"  {first}  ", "", str(second)],
        trace=write_trace(tmp_path / "t.json"),
    )

    assert run.exit_code == 0, run.stdout  # the widened support-agent declares terminate_account
    assert run.outputs["result"] == "pass"
    assert json.loads((tmp_path / "report.json").read_text())["inputs"]["manifests_loaded"] == 3


# -- a check that could not run is never a pass -----------------------------------------


@pytest.mark.parametrize(
    ("trace_name", "make"),
    [
        ("malformed", lambda tmp: MALFORMED),
        ("missing", lambda tmp: tmp / "absent.json"),
        ("no edges", lambda tmp: write_trace(tmp / "empty.json", [])),
    ],
)
def test_a_check_that_could_not_run_exits_two(tmp_path, trace_name, make) -> None:
    run = run_check_step(tmp_path, manifests=MANIFESTS, trace=make(tmp_path))

    assert run.exit_code == 2, f"{trace_name}: {run.stdout}"
    assert run.outputs["result"] == "error"
    assert run.outputs["undeclared-count"] == "0"


def test_fail_on_drift_false_reports_drift_without_failing(tmp_path) -> None:
    run = run_check_step(
        tmp_path, manifests=MANIFESTS, trace=write_trace(tmp_path / "t.json"), fail_on_drift="false"
    )

    assert run.exit_code == 0
    assert run.outputs["result"] == "drift"  # reported, just not fatal
    assert run.outputs["undeclared-count"] == "1"


def test_fail_on_drift_false_still_fails_a_check_that_could_not_run(tmp_path) -> None:
    """The escape hatch is for drift, not for a broken check — otherwise setting it once
    would silently disable the whole thing."""
    run = run_check_step(
        tmp_path, manifests=MANIFESTS, trace=tmp_path / "absent.json", fail_on_drift="false"
    )

    assert run.exit_code == 2
    assert run.outputs["result"] == "error"


def test_a_stale_report_from_a_previous_run_is_not_reused(tmp_path) -> None:
    (tmp_path / "report.json").write_text(json.dumps({"result": "pass", "undeclared": []}))

    run = run_check_step(tmp_path, manifests=MANIFESTS, trace=tmp_path / "absent.json")

    assert run.exit_code == 2
    assert run.outputs["result"] == "error"  # not the stale "pass"


# -- what a reviewer actually sees -------------------------------------------------------


def test_the_step_summary_and_annotation_name_the_offending_edge(tmp_path) -> None:
    run = run_check_step(tmp_path, manifests=MANIFESTS, trace=write_trace(tmp_path / "t.json"))

    assert "agentic-auth drift check: DRIFT" in run.summary
    assert "| UNDECLARED_TOOL | `support-agent` |" in run.summary
    assert "mcp://accounts.internal/terminate_account" in run.summary

    [annotation] = run.annotations
    assert annotation.startswith(f"::error file={MANIFESTS / 'support-agent.yaml'},")
    assert "title=Undeclared tool edge::" in annotation
    assert "Runtime would deny with OUT_OF_SCOPE." in annotation


def test_the_summary_is_appended_never_overwritten(tmp_path) -> None:
    (tmp_path / "summary").write_text("## an earlier step\n")
    env_summary = tmp_path / "summary"

    run_check_step(tmp_path, manifests=WIDENED, trace=write_trace(tmp_path / "t.json"))

    # run_check_step resets the file, so write it again and re-run to observe appending.
    env_summary.write_text("## an earlier step\n")
    script = step_script("Check observed edges")
    subprocess.run(
        ["bash", "-c", script],
        env={
            **os.environ,
            "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
            "MANIFESTS": str(WIDENED),
            "TRACE": str(tmp_path / "t.json"),
            "REPORT_PATH": str(tmp_path / "report.json"),
            "FAIL_ON_DRIFT": "true",
            "GITHUB_OUTPUT": str(tmp_path / "output"),
            "GITHUB_STEP_SUMMARY": str(env_summary),
        },
        capture_output=True,
        text=True,
        check=False,
    )

    content = env_summary.read_text()
    assert content.startswith("## an earlier step\n")
    assert "agentic-auth drift check: PASS" in content


# -- the install step's two branches ------------------------------------------------------


def test_a_local_action_without_a_package_input_refuses_clearly(tmp_path) -> None:
    """`GITHUB_ACTION_REPOSITORY` is empty for `uses: ./actions/drift-check`, so there is no
    ref to install from. Say so, rather than failing later inside pip."""
    completed = subprocess.run(
        ["bash", "-c", step_script("Install agentic-auth")],
        env={**os.environ, "PACKAGE": "", "GITHUB_ACTION_REPOSITORY": "", "GITHUB_ACTION_REF": ""},
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 2
    assert "set the 'package' input" in completed.stdout
