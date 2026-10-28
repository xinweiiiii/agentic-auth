"""Record a real run through the sidecar, then check it with the CLI (T043, SC-007).

The whole loop, in process: register the bank manifests, drive the PRD §2.3 calls through
an observe-mode sidecar with recording on, aggregate the events, and run
``agentic-auth drift check`` against manifest directories on disk.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import yaml
from typer.testing import CliRunner

from app.cli import app
from app.services.edge_trace import aggregate
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    CLEAN_CALLS,
    DRIFTED_CALLS,
    FRAUD_AGENT,
    FRAUD_CALLS,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    bank_docs,
)
from tests.fixtures.hops import consent_session, register_agents

runner = CliRunner()


def write_manifests(directory: Path, docs: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, doc in docs.items():
        (directory / f"{name}.yaml").write_text(yaml.safe_dump(doc))
    return directory


async def record_run(
    sidecar_stack,
    client,
    admin_headers,
    tmp_path: Path,
    calls,
    *,
    include_fraud_agent: bool = False,
) -> Path:
    await register_agents(client, admin_headers, bank_docs(include_fraud_agent=include_fraud_agent))
    session = await consent_session(client, admin_headers, BANK_ASSISTANT)

    events = tmp_path / "edge-events.jsonl"
    # Observe mode: an undeclared call is recorded rather than blocked, so every edge the
    # run would exercise is observed in one pass.
    sidecar = await sidecar_stack.client(observe_mode=True, trace_path=str(events))

    token = session["root_grant"]
    for _caller, target, data_class in calls:
        r = await sidecar.get(
            "/bare",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Agentic-Target": target,
                "X-Agentic-Data-Class": data_class,
            },
        )
        assert r.status_code == 200, r.text
        token = r.json()["received_token"]  # the upstream echoes the narrowed token it got

    now = datetime.now(UTC)
    trace = aggregate([events], started_at=now, finished_at=now, command=None, exit_code=0)
    out = tmp_path / "edge-trace.json"
    out.write_text(trace.model_dump_json(by_alias=True))
    return out


def check(manifest_dir: Path, trace: Path) -> tuple[int, dict]:
    result = runner.invoke(
        app,
        [
            "drift",
            "check",
            "--manifest",
            str(manifest_dir),
            "--trace",
            str(trace),
            "--format",
            "json",
        ],
    )
    return result.exit_code, json.loads(result.stdout)


async def test_an_undeclared_terminate_account_call_fails_the_check(
    sidecar_stack, client, admin_headers, tmp_path
) -> None:
    trace = await record_run(sidecar_stack, client, admin_headers, tmp_path, DRIFTED_CALLS)

    code, report = check(write_manifests(tmp_path / "manifests", bank_docs()), trace)

    assert code == 1
    [finding] = report["undeclared"]
    assert (finding["from"], finding["to"]) == (SUPPORT_AGENT, TERMINATE_ACCOUNT)
    assert (finding["verdict"], finding["runtime_reason"]) == ("UNDECLARED_TOOL", "OUT_OF_SCOPE")
    # Attributed to the verified acting agent at every hop — never to the human.
    recorded = {(e["from"], e["to"]) for e in json.loads(trace.read_text())["edges"]}
    assert (BANK_ASSISTANT, f"agent://{BALANCE_AGENT}") in recorded
    assert not any(caller.startswith("user:") for caller, _ in recorded)


async def test_removing_the_call_passes(sidecar_stack, client, admin_headers, tmp_path) -> None:
    trace = await record_run(sidecar_stack, client, admin_headers, tmp_path, CLEAN_CALLS)

    code, report = check(write_manifests(tmp_path / "manifests", bank_docs()), trace)

    assert code == 0, report
    assert report["summary"]["edges_undeclared"] == 0


async def test_widening_the_manifest_passes_with_no_agent_change(
    sidecar_stack, client, admin_headers, tmp_path
) -> None:
    trace = await record_run(sidecar_stack, client, admin_headers, tmp_path, DRIFTED_CALLS)

    code, report = check(write_manifests(tmp_path / "widened", bank_docs(widened=True)), trace)

    assert code == 0, report


async def test_an_undeclared_delegation_fails_the_check(
    sidecar_stack, client, admin_headers, tmp_path
) -> None:
    trace = await record_run(
        sidecar_stack, client, admin_headers, tmp_path, FRAUD_CALLS, include_fraud_agent=True
    )

    code, report = check(
        write_manifests(tmp_path / "manifests", bank_docs(include_fraud_agent=True)), trace
    )

    assert code == 1
    [finding] = report["undeclared"]
    assert (finding["from"], finding["to"]) == (BALANCE_AGENT, f"agent://{FRAUD_AGENT}")
    assert (finding["verdict"], finding["runtime_reason"]) == (
        "UNDECLARED_DELEGATION",
        "EDGE_NOT_IN_DAG",
    )
