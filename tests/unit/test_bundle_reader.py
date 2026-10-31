"""The export-bundle reader: every problem is named by its bundle line."""

from __future__ import annotations

import json

import pytest

from agentic_auth.services.bundle_import import BundleError, read_bundle, registration_plan
from tests.fixtures.chains import KB_SEARCH, NOTIFIER, ORCHESTRATOR, SUMMARIZER, chain_docs

HEADER = {
    "kind": "header",
    "source_deployment": "embedded",
    "package_version": "0.2.0",
    "exported_at": "2026-10-31T00:00:00+00:00",
}


def _write(tmp_path, records, counts=None):
    path = tmp_path / "bundle.ndjson"
    header = {**HEADER, "counts": counts or {}}
    path.write_text("\n".join(json.dumps(r) for r in [header, *records]) + "\n")
    return path


def _counts(agent=0, manifest=0, trust_anchor=0, audit=0):
    return {"agent": agent, "manifest": manifest, "trust_anchor": trust_anchor, "audit": audit}


def test_a_well_formed_bundle_reads_back(tmp_path) -> None:
    records = [
        {"kind": "agent", "id": "a1", "name": "x"},
        {"kind": "manifest", "agent_id": "a1", "version": 2, "doc": {"v": 2}},
        {"kind": "manifest", "agent_id": "a1", "version": 1, "doc": {"v": 1}},
        {"kind": "audit", "id": "00000000-0000-0000-0000-000000000001"},
    ]
    bundle = read_bundle(_write(tmp_path, records, _counts(agent=1, manifest=2, audit=1)))
    assert bundle.header["source_deployment"] == "embedded"
    # History is oldest first, whatever order the lines came in.
    assert bundle.manifest_history() == {"x": [{"v": 1}, {"v": 2}]}


@pytest.mark.parametrize(
    ("lines", "line", "message"),
    [
        (['{"kind":"agent","id":"a","name":"x"}'], 1, "first record must be the header"),
        ([json.dumps({**HEADER, "counts": {}}), "{not json"], 2, "not JSON"),
        ([json.dumps({**HEADER, "counts": {}}), '{"kind":"session"}'], 2, "unknown record kind"),
        (
            [json.dumps({**HEADER, "counts": {}}), '{"kind":"manifest","agent_id":"a"}'],
            2,
            "missing version, doc",
        ),
        ([json.dumps({"kind": "header"})], 1, "header is missing `source_deployment`"),
        (['["kind"]'], 1, "an object with a `kind`"),
    ],
)
def test_problems_name_their_line(tmp_path, lines, line, message) -> None:
    path = tmp_path / "bundle.ndjson"
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(BundleError) as exc:
        read_bundle(path)
    assert exc.value.line == line
    assert message in str(exc.value)


def test_a_truncated_bundle_is_caught_by_the_header_counts(tmp_path) -> None:
    path = _write(tmp_path, [{"kind": "agent", "id": "a1", "name": "x"}], _counts(agent=2))
    with pytest.raises(BundleError, match="header counts 2 agent"):
        read_bundle(path)


def test_an_empty_bundle_is_refused(tmp_path) -> None:
    path = tmp_path / "bundle.ndjson"
    path.write_text("\n")
    with pytest.raises(BundleError, match="empty bundle"):
        read_bundle(path)


def test_the_plan_registers_downstream_agents_first(tmp_path) -> None:
    docs = chain_docs()
    records = []
    for i, name in enumerate([ORCHESTRATOR, KB_SEARCH, SUMMARIZER, NOTIFIER]):
        records.append({"kind": "agent", "id": f"id{i}", "name": name})
        records.append({"kind": "manifest", "agent_id": f"id{i}", "version": 1, "doc": docs[name]})
    plan = registration_plan(read_bundle(_write(tmp_path, records, _counts(agent=4, manifest=4))))
    assert [name for name, _ in plan] == [NOTIFIER, SUMMARIZER, KB_SEARCH, ORCHESTRATOR]
