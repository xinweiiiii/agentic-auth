"""``agentic-auth drift record|check`` — exit codes, every could-not-run cause, formats (T041)."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from app.cli import app
from app.schemas.edge_trace import EdgeOutcomes, EdgeTrace, ObservedEdge, TraceRun, Unattributed
from app.services.edge_trace import EdgeRecorder
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    bank_docs,
)
from tests.fixtures.chains import manifest_doc

runner = CliRunner()
NOW = datetime(2026, 9, 13, 10, 0, tzinfo=UTC)

CLEAN_EDGES = [
    (BANK_ASSISTANT, f"agent://{BALANCE_AGENT}", 1),
    (BALANCE_AGENT, f"agent://{SUPPORT_AGENT}", 1),
    (SUPPORT_AGENT, KB_SEARCH_TOOL, 1),
]
DRIFT_EDGES = [*CLEAN_EDGES[:2], (SUPPORT_AGENT, TERMINATE_ACCOUNT, 3)]


def write_manifests(directory: Path, docs: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, doc in docs.items():
        (directory / f"{name}.yaml").write_text(yaml.safe_dump(doc))
    return directory


def write_trace(path: Path, edges=CLEAN_EDGES, *, recorder_errors: int = 0) -> Path:
    trace = EdgeTrace(
        run=TraceRun(started_at=NOW, finished_at=NOW, command=None, event_files=[], exit_code=0),
        edges=[
            ObservedEdge(
                from_=caller,
                to=target,
                kind="delegation" if target.startswith("agent://") else "tool",
                count=count,
                outcomes=EdgeOutcomes(observed=count),
            )
            for caller, target, count in edges
        ],
        unattributed=Unattributed(),
        recorder_errors=recorder_errors,
        events_total=sum(count for _, _, count in edges),
    )
    path.write_text(trace.model_dump_json(by_alias=True))
    return path


def check(*args: object):
    return runner.invoke(app, ["drift", "check", *(str(a) for a in args)])


@pytest.fixture
def manifests(tmp_path) -> Path:
    return write_manifests(tmp_path / "manifests", bank_docs())


# -- results ---------------------------------------------------------------------


def test_a_compliant_trace_passes(tmp_path, manifests) -> None:
    result = check("--manifest", manifests, "--trace", write_trace(tmp_path / "t.json"))
    assert result.exit_code == 0, result.stdout
    assert "PASS" in result.stdout


def test_drift_exits_one_and_names_the_edge(tmp_path, manifests) -> None:
    result = check(
        "--manifest", manifests, "--trace", write_trace(tmp_path / "t.json", DRIFT_EDGES)
    )

    assert result.exit_code == 1
    assert f"UNDECLARED_TOOL  {SUPPORT_AGENT} -> {TERMINATE_ACCOUNT}   (3 calls)" in result.stdout
    assert "runtime would deny: OUT_OF_SCOPE" in result.stdout
    assert f"declared in: {manifests / 'support-agent.yaml'}" in result.stdout


def test_json_output_is_the_report(tmp_path, manifests) -> None:
    trace = write_trace(tmp_path / "t.json", DRIFT_EDGES)
    result = check("--manifest", manifests, "--trace", trace, "--format", "json")

    report = json.loads(result.stdout)
    assert report["result"] == "drift"
    assert report["undeclared"][0]["from"] == SUPPORT_AGENT
    assert report["inputs"]["manifests_loaded"] == 3


def test_widening_the_manifest_passes(tmp_path) -> None:
    widened = write_manifests(tmp_path / "widened", bank_docs(widened=True))
    result = check("--manifest", widened, "--trace", write_trace(tmp_path / "t.json", DRIFT_EDGES))
    assert result.exit_code == 0, result.stdout


def test_manifests_in_several_locations_form_one_declared_set(tmp_path) -> None:
    docs = bank_docs()
    first = write_manifests(tmp_path / "a", {k: docs[k] for k in (BANK_ASSISTANT, BALANCE_AGENT)})
    second = write_manifests(tmp_path / "b", {SUPPORT_AGENT: docs[SUPPORT_AGENT]})

    result = check(
        "--manifest", first, "--manifest", second, "--trace", write_trace(tmp_path / "t.json")
    )
    assert result.exit_code == 0, result.stdout


def test_files_that_are_not_manifests_are_skipped_and_listed(tmp_path, manifests) -> None:
    (manifests / "notes.yaml").write_text(yaml.safe_dump({"kind": "SomethingElse"}))
    result = check(
        "--manifest", manifests, "--trace", write_trace(tmp_path / "t.json"), "--format", "json"
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["inputs"]["skipped_files"] == [str(manifests / "notes.yaml")]


def test_deterministic_output_is_byte_identical_and_matches_the_report_file(
    tmp_path, manifests
) -> None:
    trace = write_trace(tmp_path / "t.json", DRIFT_EDGES)
    report_path = tmp_path / "report.json"
    args = ("--manifest", manifests, "--trace", trace, "--format", "json", "--deterministic")

    first = check(*args, "--report", report_path)
    second = check(*args)

    assert first.stdout == second.stdout
    assert "generated_at" not in first.stdout
    assert report_path.read_text().strip() == first.stdout.strip()


def test_an_unknown_format_is_a_usage_error(tmp_path, manifests) -> None:
    result = check(
        "--manifest", manifests, "--trace", write_trace(tmp_path / "t.json"), "--format", "xml"
    )
    assert result.exit_code == 2


# -- every could-not-run cause exits 2, never 0 --------------------------------------


def _cycle(tmp_path: Path) -> tuple[list[Path], Path]:
    docs = {
        "loop-a": manifest_doc(
            "loop-a", hop_budget=4, downstream=[{"ref": "agent://loop-b", "max_hop_depth": 4}]
        ),
        "loop-b": manifest_doc(
            "loop-b", hop_budget=4, downstream=[{"ref": "agent://loop-a", "max_hop_depth": 4}]
        ),
    }
    return [write_manifests(tmp_path / "m", docs)], write_trace(tmp_path / "t.json")


def _invalid(tmp_path: Path) -> tuple[list[Path], Path]:
    directory = write_manifests(tmp_path / "m", bank_docs())
    broken = bank_docs()[SUPPORT_AGENT]
    del broken["spec"]["hop_budget"]
    (directory / "support-agent.yaml").write_text(yaml.safe_dump(broken))
    return [directory], write_trace(tmp_path / "t.json")


def _duplicate(tmp_path: Path) -> tuple[list[Path], Path]:
    docs = bank_docs()
    return (
        [
            write_manifests(tmp_path / "a", docs),
            write_manifests(tmp_path / "b", {SUPPORT_AGENT: docs[SUPPORT_AGENT]}),
        ],
        write_trace(tmp_path / "t.json"),
    )


def _with_trace(tmp_path: Path, content: str) -> tuple[list[Path], Path]:
    path = tmp_path / "t.json"
    path.write_text(content)
    return [write_manifests(tmp_path / "m", bank_docs())], path


CASES = {
    "NO_MANIFESTS_FOUND": lambda t: (
        [(t / "empty").mkdir() or t / "empty"],
        write_trace(t / "t.json"),
    ),
    "MANIFEST_INVALID": _invalid,
    "MANIFEST_DUPLICATE_AGENT": _duplicate,
    "DELEGATION_CYCLE": _cycle,
    "TRACE_MISSING": lambda t: ([write_manifests(t / "m", bank_docs())], t / "absent.json"),
    "TRACE_MALFORMED": lambda t: _with_trace(t, "not json"),
    "TRACE_UNSUPPORTED_VERSION": lambda t: _with_trace(t, json.dumps({"schema_version": 2})),
    "TRACE_RECORDER_ERRORS": lambda t: (
        [write_manifests(t / "m", bank_docs())],
        write_trace(t / "t.json", recorder_errors=1),
    ),
    "NO_EDGES_OBSERVED": lambda t: (
        [write_manifests(t / "m", bank_docs())],
        write_trace(t / "t.json", []),
    ),
}


@pytest.mark.parametrize("code", sorted(CASES))
def test_every_could_not_run_cause_exits_two(tmp_path, code) -> None:
    dirs, trace = CASES[code](tmp_path)
    args: list[object] = []
    for directory in dirs:
        args += ["--manifest", directory]

    result = check(*args, "--trace", trace, "--format", "json")

    assert result.exit_code == 2, result.stdout
    report = json.loads(result.stdout)
    assert report["result"] == "error"
    assert code in [e["code"] for e in report["errors"]]
    # It echoes what it was asked to read, so a failing CI job is self-describing.
    assert report["inputs"]["manifest_dirs"] == [str(d) for d in dirs]
    assert report["inputs"]["trace"] == str(trace)
    if code not in REACHES_THE_DIFFER:
        # Nothing was judged, so the report claims nothing about edges.
        assert report["summary"] == dict.fromkeys(report["summary"], 0)


# TRACE_RECORDER_ERRORS is raised by the differ itself: the trace parsed and its edges were
# counted, and only then was the evidence ruled incomplete. Such a report still says what it
# saw — useful, since the lost events are usually the point of interest.
REACHES_THE_DIFFER = {"TRACE_RECORDER_ERRORS"}


def test_lost_events_still_report_what_was_observed(tmp_path, manifests) -> None:
    report = json.loads(
        check(
            "--manifest",
            manifests,
            "--trace",
            write_trace(tmp_path / "t.json", recorder_errors=2),
            "--format",
            "json",
        ).stdout
    )

    assert report["result"] == "error"
    assert [e["code"] for e in report["errors"]] == ["TRACE_RECORDER_ERRORS"]
    assert "2 recorded event(s) were lost" in report["errors"][0]["message"]
    assert report["summary"]["edges_observed"] == len(CLEAN_EDGES)


# Codes that name the one file at fault. NO_EDGES_OBSERVED, TRACE_RECORDER_ERRORS and
# DELEGATION_CYCLE are about the run or the graph as a whole, so they carry no path.
FILE_SCOPED = {
    "MANIFEST_INVALID": lambda t, dirs: dirs[0] / "support-agent.yaml",
    "MANIFEST_DUPLICATE_AGENT": lambda t, dirs: dirs[1] / "support-agent.yaml",
    "TRACE_MISSING": lambda t, dirs: t / "absent.json",
    "TRACE_MALFORMED": lambda t, dirs: t / "t.json",
    "TRACE_UNSUPPORTED_VERSION": lambda t, dirs: t / "t.json",
}


@pytest.mark.parametrize("code", sorted(FILE_SCOPED))
def test_an_error_names_the_file_at_fault(tmp_path, code) -> None:
    """Without the path, 'MANIFEST_INVALID' sends a developer hunting through a directory."""
    dirs, trace = CASES[code](tmp_path)
    args: list[object] = []
    for directory in dirs:
        args += ["--manifest", directory]

    report = json.loads(check(*args, "--trace", trace, "--format", "json").stdout)

    [error] = [e for e in report["errors"] if e["code"] == code]
    assert error["path"] == str(FILE_SCOPED[code](tmp_path, dirs))


def test_every_invalid_manifest_is_reported_not_just_the_first(tmp_path) -> None:
    directory = write_manifests(tmp_path / "m", bank_docs())
    for name in (BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT):
        broken = bank_docs()[name]
        del broken["spec"]["hop_budget"]
        (directory / f"{name}.yaml").write_text(yaml.safe_dump(broken))

    report = json.loads(
        check(
            "--manifest", directory, "--trace", write_trace(tmp_path / "t.json"), "--format", "json"
        ).stdout
    )

    invalid = [e for e in report["errors"] if e["code"] == "MANIFEST_INVALID"]
    assert {e["path"] for e in invalid} == {
        str(directory / f"{name}.yaml") for name in (BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT)
    }
    assert all("hop_budget" in e["message"] for e in invalid)


def test_one_run_reports_every_bad_file_not_just_the_first(tmp_path) -> None:
    """The check reports every undeclared edge in a run; its errors are no different. Stopping
    at the first problem turns one CI round trip into four."""
    good = write_manifests(tmp_path / "good", {BANK_ASSISTANT: bank_docs()[BANK_ASSISTANT]})
    messy = write_manifests(tmp_path / "messy", {BALANCE_AGENT: bank_docs()[BALANCE_AGENT]})
    # Two files YAML cannot even parse...
    for name in ("broken-one.yaml", "broken-two.yaml"):
        (messy / name).write_text("kind: AgentManifest\n  bad: [indent\n")
    # ...and two that redeclare an agent the first directory already claimed.
    for name in ("dup-one.yaml", "dup-two.yaml"):
        (messy / name).write_text(yaml.safe_dump(bank_docs()[BANK_ASSISTANT]))

    report = json.loads(
        check(
            "--manifest",
            tmp_path / "absent",  # not a directory at all
            "--manifest",
            good,
            "--manifest",
            messy,
            "--trace",
            write_trace(tmp_path / "t.json"),
            "--format",
            "json",
        ).stdout
    )

    by_code: dict[str, set[str]] = {}
    for error in report["errors"]:
        by_code.setdefault(error["code"], set()).add(error["path"])

    # The missing location is reported, and does not stop the later ones being read.
    assert by_code["NO_MANIFESTS_FOUND"] == {str(tmp_path / "absent")}
    assert by_code["MANIFEST_INVALID"] == {
        str(messy / "broken-one.yaml"),
        str(messy / "broken-two.yaml"),
    }
    assert by_code["MANIFEST_DUPLICATE_AGENT"] == {
        str(messy / "dup-one.yaml"),
        str(messy / "dup-two.yaml"),
    }
    # And the manifests that were fine still loaded.
    assert report["inputs"]["manifests_loaded"] == 2


def test_a_manifest_directory_that_contributed_nothing_warns(tmp_path) -> None:
    """Usually a mistyped path — the check still runs, but says the directory did nothing."""
    populated = write_manifests(tmp_path / "m", bank_docs())
    empty = tmp_path / "elsewhere"
    empty.mkdir()

    report = json.loads(
        check(
            "--manifest",
            populated,
            "--manifest",
            empty,
            "--trace",
            write_trace(tmp_path / "t.json"),
            "--format",
            "json",
        ).stdout
    )

    assert report["result"] == "pass"
    assert [w["code"] for w in report["warnings"]] == ["UNUSED_MANIFEST_DIR"]
    assert str(empty) in report["warnings"][0]["message"]


def test_a_directory_that_contributed_manifests_does_not_warn(tmp_path, manifests) -> None:
    report = json.loads(
        check(
            "--manifest", manifests, "--trace", write_trace(tmp_path / "t.json"), "--format", "json"
        ).stdout
    )
    assert report["warnings"] == []


def test_a_trace_whose_counts_do_not_add_up_is_malformed(tmp_path, manifests) -> None:
    good = json.loads(write_trace(tmp_path / "good.json").read_text())
    good["edges"][0]["count"] = 99
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(good))

    result = check("--manifest", manifests, "--trace", bad, "--format", "json")

    assert result.exit_code == 2
    assert [e["code"] for e in json.loads(result.stdout)["errors"]] == ["TRACE_MALFORMED"]


# -- record ------------------------------------------------------------------------


def test_record_exits_with_the_commands_code_and_still_writes_the_trace(tmp_path) -> None:
    out = tmp_path / "edge-trace.json"
    result = runner.invoke(
        app,
        [
            "drift",
            "record",
            "--out",
            str(out),
            "--",
            sys.executable,
            "-c",
            "import sys; sys.exit(3)",
        ],
    )

    assert result.exit_code == 3
    trace = json.loads(out.read_text())
    assert trace["run"]["exit_code"] == 3
    assert trace["edges"] == []


def test_record_captures_what_the_wrapped_run_records(tmp_path) -> None:
    out = tmp_path / "edge-trace.json"
    child = (
        "import os; from app.services.edge_trace import EdgeRecorder; "
        "EdgeRecorder(os.environ['AGENTIC_AUTH_TRACE_PATH'], 'sdk').record("
        f"acting_agent='{SUPPORT_AGENT}', target='{TERMINATE_ACCOUNT}', "
        "outcome='observed', reason='OUT_OF_SCOPE')"
    )

    result = runner.invoke(
        app, ["drift", "record", "--out", str(out), "--", sys.executable, "-c", child]
    )

    assert result.exit_code == 0
    [recorded] = json.loads(out.read_text())["edges"]
    assert (recorded["from"], recorded["to"], recorded["count"]) == (
        SUPPORT_AGENT,
        TERMINATE_ACCOUNT,
        1,
    )


def test_record_aggregates_an_existing_events_file(tmp_path) -> None:
    events = tmp_path / "events.jsonl"
    EdgeRecorder(events, "sidecar").record(
        acting_agent=SUPPORT_AGENT, target=KB_SEARCH_TOOL, outcome="allow", reason=None
    )
    out = tmp_path / "edge-trace.json"

    result = runner.invoke(app, ["drift", "record", "--out", str(out), "--events", str(events)])

    assert result.exit_code == 0
    assert len(json.loads(out.read_text())["edges"]) == 1


def test_record_refuses_to_mix_a_new_run_into_existing_events(tmp_path) -> None:
    events = tmp_path / "events.jsonl"
    events.write_text("{}\n")
    result = runner.invoke(
        app,
        [
            "drift",
            "record",
            "--out",
            str(tmp_path / "t.json"),
            "--events",
            str(events),
            "--",
            sys.executable,
            "-c",
            "pass",
        ],
    )
    assert result.exit_code == 2


def test_record_without_a_command_needs_an_events_file(tmp_path) -> None:
    result = runner.invoke(app, ["drift", "record", "--out", str(tmp_path / "t.json")])
    assert result.exit_code == 2


# -- no network on the check path -----------------------------------------------------


def test_the_check_logic_imports_no_http_client() -> None:
    """FR-032: judging a trace needs manifests and a file, nothing on the network.

    The probe targets ``app.services.drift`` — where loading, compiling and diffing live.
    The ``app.cli`` package itself imports ``httpx`` because the manifest commands run
    discovery; that is the CLI shell, not the check.
    """
    probe = (
        "import sys; import app.services.drift; "
        "assert 'httpx' not in sys.modules, 'httpx was imported'"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
