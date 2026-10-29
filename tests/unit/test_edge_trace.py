"""Recording edge events and aggregating them into a trace."""

from __future__ import annotations

import json
import stat
import threading
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from app.schemas.edge_trace import EdgeEvent
from app.services.edge_trace import EdgeRecorder, aggregate
from tests.fixtures.bank import BANK_ASSISTANT, KB_SEARCH_TOOL, SUPPORT_AGENT, TERMINATE_ACCOUNT
from tests.fixtures.contracts import defs_schema

SCHEMA = "edge-trace.schema.json"
NOW = datetime.now(UTC)


def validator(definition: str) -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(defs_schema(SCHEMA, definition))


def lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def aggregate_one(path: Path):
    return aggregate([path], started_at=NOW, finished_at=NOW, command=None, exit_code=None)


def record_terminate(recorder: EdgeRecorder) -> None:
    recorder.record(
        acting_agent=SUPPORT_AGENT,
        target=TERMINATE_ACCOUNT,
        outcome="observed",
        reason="OUT_OF_SCOPE",
    )


# -- recording ------------------------------------------------------------------


def test_events_match_the_contract_and_the_file_is_private(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    recorder = EdgeRecorder(path, "sidecar")

    record_terminate(recorder)
    recorder.record(
        acting_agent=None, target=None, outcome="blocked_local", reason="UPSTREAM_NOT_MAPPED"
    )

    events = lines(path)
    assert len(events) == 2
    for event in events:
        validator("EdgeEvent").validate(event)
    assert (events[0]["kind"], events[1]["kind"]) == ("tool", None)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_concurrent_recorders_never_interleave_lines(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    recorders = [EdgeRecorder(path, "sidecar"), EdgeRecorder(path, "sdk")]

    def burst(recorder: EdgeRecorder) -> None:
        for _ in range(1000):
            record_terminate(recorder)

    threads = [threading.Thread(target=burst, args=(r,)) for r in recorders]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    events = lines(path)  # every line parses: nothing was split or merged
    assert len(events) == 2000
    assert {e["source"] for e in events} == {"sidecar", "sdk"}


def test_a_recorder_that_cannot_write_never_raises_and_reports_the_loss(tmp_path) -> None:
    path = tmp_path / "not-yet" / "events.jsonl"
    recorder = EdgeRecorder(path, "sdk")

    record_terminate(recorder)
    record_terminate(recorder)
    assert recorder.lost == 2

    path.parent.mkdir()
    record_terminate(recorder)

    loss, event = lines(path)
    validator("RecorderErrorLine").validate(loss)
    assert loss["recorder_error"] == 2
    validator("EdgeEvent").validate(event)

    trace = aggregate_one(path)
    assert trace.recorder_errors == 2
    assert trace.events_total == 1


def test_an_event_that_cannot_be_expressed_is_lost_not_guessed(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    recorder = EdgeRecorder(path, "sidecar")

    recorder.record(acting_agent="Not A Name", target="agent://x", outcome="allow", reason=None)

    assert recorder.lost == 1
    assert not path.exists()


# -- aggregation ------------------------------------------------------------------


def test_aggregation_deduplicates_counts_and_separates_the_unattributed(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    recorder = EdgeRecorder(path, "sidecar")
    record_terminate(recorder)
    record_terminate(recorder)
    recorder.record(
        acting_agent=BANK_ASSISTANT, target="agent://balance-agent", outcome="allow", reason=None
    )
    recorder.record(
        acting_agent=None, target=KB_SEARCH_TOOL, outcome="blocked_infra", reason="PDP_UNAVAILABLE"
    )
    recorder.record(
        acting_agent=None, target=None, outcome="blocked_local", reason="UPSTREAM_NOT_MAPPED"
    )

    trace = aggregate_one(path)

    assert [(e.from_, e.to) for e in trace.edges] == [
        (BANK_ASSISTANT, "agent://balance-agent"),
        (SUPPORT_AGENT, TERMINATE_ACCOUNT),
    ]
    terminate = trace.edges[1]
    assert (terminate.count, terminate.outcomes.observed, terminate.kind) == (2, 2, "tool")
    assert trace.unattributed.count == 2
    assert trace.unattributed.by_reason == {"PDP_UNAVAILABLE": 1, "UPSTREAM_NOT_MAPPED": 1}
    assert trace.events_total == 5
    assert trace.recorder_errors == 0
    validator("EdgeTrace").validate(trace.model_dump(mode="json", by_alias=True))


def test_unreadable_or_unknown_lines_count_against_the_trace(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    record_terminate(EdgeRecorder(path, "sidecar"))
    good = lines(path)[0]
    with path.open("a") as handle:
        handle.write("not json\n")
        handle.write(json.dumps({**good, "authorization": "Bearer abc"}) + "\n")  # unknown field
        handle.write('{"v": 1, "ts": ')  # truncated by a killed process

    trace = aggregate_one(path)

    assert trace.events_total == 1
    assert trace.recorder_errors == 3


def test_a_missing_events_file_is_an_empty_trace(tmp_path) -> None:
    trace = aggregate_one(tmp_path / "never-written.jsonl")
    assert (trace.edges, trace.events_total, trace.recorder_errors) == ([], 0, 0)


# -- nothing secret, by construction ------------------------------------------------


def test_the_event_shape_has_no_field_that_could_carry_a_secret() -> None:
    assert set(EdgeEvent.model_fields) == {
        "v",
        "ts",
        "source",
        "acting_agent",
        "target",
        "kind",
        "outcome",
        "reason",
    }


@pytest.mark.parametrize("marker", ["eyJ", "Bearer", "authorization"])
def test_no_token_or_header_reaches_events_or_the_trace(tmp_path, marker) -> None:
    events = tmp_path / "events.jsonl"
    recorder = EdgeRecorder(events, "sidecar")
    record_terminate(recorder)
    recorder.record(acting_agent=None, target=None, outcome="blocked_local", reason="UNAUTHORIZED")
    out = tmp_path / "trace.json"
    out.write_text(aggregate_one(events).model_dump_json(by_alias=True))

    for artifact in (events, out):
        assert marker not in artifact.read_text()
