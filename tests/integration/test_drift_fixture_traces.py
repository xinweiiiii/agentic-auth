"""Traces for the drift-check-fixture workflow.

``test_writes_fixture_traces`` records a real drifted run through the in-process stack and
writes it into ``examples/drift-fixture/`` so the GitHub Action can be exercised
against it. It writes into the source tree, so it runs only when
``AGENTIC_AUTH_WRITE_FIXTURE_TRACES=1`` — which the workflow sets.

The committed ``malformed.edge-trace.json`` is checked on every run: it must stay malformed
in exactly the way the workflow expects, or the "error" branch of the action goes untested.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from app.cli import app
from tests.fixtures.bank import DRIFTED_CALLS
from tests.integration.test_drift_end_to_end import record_run

FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "drift-fixture"


@pytest.mark.skipif(
    os.environ.get("AGENTIC_AUTH_WRITE_FIXTURE_TRACES") != "1",
    reason="writes into examples/drift-fixture; enabled by the drift-check-fixture workflow",
)
async def test_writes_fixture_traces(sidecar_stack, client, admin_headers, tmp_path) -> None:
    trace = await record_run(sidecar_stack, client, admin_headers, tmp_path, DRIFTED_CALLS)
    shutil.copyfile(trace, FIXTURE / "drifted.edge-trace.json")


def test_the_committed_malformed_trace_is_rejected_as_malformed() -> None:
    result = CliRunner().invoke(
        app,
        [
            "drift",
            "check",
            "--manifest",
            str(FIXTURE / "manifests"),
            "--trace",
            str(FIXTURE / "malformed.edge-trace.json"),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2
    assert [e["code"] for e in json.loads(result.stdout)["errors"]] == ["TRACE_MALFORMED"]
