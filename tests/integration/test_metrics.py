"""The audit and drift promises are measurable (T066, US6, FR-038–FR-043).

A known mix of decisions, a forced audit-write failure, chain queries and a drift run must
produce exactly the expected counts — and no label value anywhere may be an identity.
"""

from __future__ import annotations

import os
import re
import uuid

import httpx
import pytest
from httpx import ASGITransport
from sqlalchemy.exc import OperationalError
from typer.testing import CliRunner

from app.boundary.guarantee import Guarantee
from app.cli import app as cli
from app.config import get_settings
from app.schemas.authorize import DenyReason
from app.services.audit import AuditService
from app.services.audit_chain import ChainBreak
from tests.fixtures.bank import bank_docs
from tests.fixtures.chains import SUMMARIZER
from tests.fixtures.hops import authorize
from tests.unit.test_drift_cli import DRIFT_EDGES, write_manifests, write_trace

KB_TOOL = "mcp://kb.internal/search"
LEDGER_TOOL = "mcp://ledger.internal/read_ledger"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-", re.IGNORECASE)
ALLOWED_LABEL_VALUES = (
    {
        "allow",
        "deny",
        "true",
        "false",
        "tool",
        "agent",
        "complete",
        "incomplete",
        "not_found",
        "none",
        # -- Phase 4 (contracts/metrics.md) --
        "self",
        "ancestor",
        "sentinel",
        "reported",
        "unknown",
        "minted",
        "not_privileged",
        "already_minted",
        "tainted",
        "invalid_token",
        "too_large",
        "enrolled",
        "quarantined",
        "rejected",
        "key_revoked",
        "idp_unavailable",
        "reconciliation_rejected",
        "authorize",
        "exchange",
        "missing",
        "invalid",
        "wrong_agent",
        "not_enrolled",
        # -- Phase 5 ------------------------------------------------------------
        # step_up_outcomes
        "approved",
        "declined",
        "expired",
        "replayed",
        "out_of_ceiling",
        # step_up_resumptions
        "completed",
        "partial",
        "failed",
        # sandbox_runs
        "running",
        "deadline_exceeded",
        # proposals_ratified{edited} uses "true"/"false", already allowed above.
    }
    | {reason.value for reason in DenyReason}
    | {reason.value for reason in ChainBreak}
    # decisions_by_guarantee{level}, guarantee_degrades{from_level,to_level}. Bounded by
    # the enum, so adding a level cannot smuggle in an unbounded label.
    | {level.value for level in Guarantee}
)


def sample(metrics, name: str, **labels: str) -> float:
    return metrics.registry.get_sample_value(name, labels) or 0.0


async def test_a_known_mix_produces_exactly_those_counts(
    client, admin_headers, register_chain, consent, metrics_registry, monkeypatch
) -> None:
    await register_chain()
    sessions = [await consent() for _ in range(11)]

    allows = [
        (await authorize(client, s["root_grant"], target=KB_TOOL, data_class="kb.public")).json()
        for s in sessions[:7]
    ]
    for s in sessions[7:9]:
        await authorize(
            client, s["root_grant"], target=f"agent://{SUMMARIZER}", data_class="account.read"
        )
    await authorize(client, sessions[9]["root_grant"], target=LEDGER_TOOL, data_class="ledger.read")

    # One allow whose record cannot be committed.
    real_commit = AuditService._commit
    failures = {"left": 1}

    async def _fail_once(self, db):
        if failures["left"]:
            failures["left"] -= 1
            raise OperationalError("COMMIT", {}, ConnectionError("audit store unreachable"))
        await real_commit(self, db)

    monkeypatch.setattr(AuditService, "_commit", _fail_once)
    refused = (
        await authorize(client, sessions[10]["root_grant"], target=KB_TOOL, data_class="kb.public")
    ).json()
    assert refused["reason"] == "AUDIT_UNAVAILABLE"

    for decision in allows[:3]:
        r = await client.get(
            f"/v1/audit/actions/{decision['action_id']}/chain", headers=admin_headers
        )
        assert r.status_code == 200
    missing = await client.get(f"/v1/audit/actions/{uuid.uuid4()}/chain", headers=admin_headers)
    assert missing.status_code == 404

    m = metrics_registry
    decisions = "agentic_auth_decisions_total"
    assert sample(m, decisions, outcome="allow", enforced="true", target_kind="tool") == 7
    assert sample(m, decisions, outcome="deny", enforced="true", target_kind="agent") == 2
    assert sample(m, decisions, outcome="deny", enforced="true", target_kind="tool") == 1

    denials = "agentic_auth_denials_total"
    assert sample(m, denials, reason="EDGE_NOT_IN_DAG") == 2
    assert sample(m, denials, reason="OUT_OF_SCOPE") == 1
    assert sample(m, denials, reason="AUDIT_UNAVAILABLE") == 1

    assert sample(m, "agentic_auth_audit_write_failures_total", outcome="allow") == 1
    assert sample(m, "agentic_auth_chain_writes_total", complete="true", **{"break": "none"}) == 10

    assert sample(m, "agentic_auth_chain_queries_total", result="complete") == 3
    assert sample(m, "agentic_auth_chain_queries_total", result="not_found") == 1
    assert sample(m, "agentic_auth_chain_query_duration_seconds_count", result="complete") == 3
    assert sample(m, "agentic_auth_chain_query_duration_seconds_count", result="not_found") == 1


async def test_no_label_value_is_ever_an_identity(
    client, register_chain, consent, admin_headers, metrics_registry
) -> None:
    await register_chain()
    session = await consent()
    decision = (
        await authorize(client, session["root_grant"], target=KB_TOOL, data_class="kb.public")
    ).json()
    await authorize(
        client, session["root_grant"], target=f"agent://{SUMMARIZER}", data_class="account.read"
    )
    await client.get(f"/v1/audit/actions/{decision['action_id']}/chain", headers=admin_headers)

    for family in metrics_registry.registry.collect():
        for metric_sample in family.samples:
            for name, value in metric_sample.labels.items():
                if name == "le":
                    continue  # histogram bucket bounds
                assert value in ALLOWED_LABEL_VALUES, f"{metric_sample.name}{{{name}={value!r}}}"
                assert "user:" not in value and not UUID.search(value)


async def test_metrics_are_served_for_scraping(
    client, register_chain, consent, metrics_registry
) -> None:
    await register_chain()
    session = await consent()
    await authorize(client, session["root_grant"], target=KB_TOOL, data_class="kb.public")

    r = await client.get("/metrics")

    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert (
        'agentic_auth_decisions_total{enforced="true",outcome="allow",target_kind="tool"} 1.0'
        in r.text
    )


async def test_metrics_can_be_switched_off(monkeypatch) -> None:
    from app.main import create_app

    monkeypatch.setenv("AGENTIC_AUTH_METRICS_ENABLED", "false")
    get_settings.cache_clear()
    try:
        disabled = create_app()
    finally:
        monkeypatch.delenv("AGENTIC_AUTH_METRICS_ENABLED")
        get_settings.cache_clear()

    async with httpx.AsyncClient(
        transport=ASGITransport(app=disabled), base_url="http://test"
    ) as c:
        assert (await c.get("/metrics")).status_code == 404


def test_drift_check_writes_its_metrics_to_a_textfile(tmp_path) -> None:
    out = tmp_path / "drift.prom"
    result = CliRunner().invoke(
        cli,
        [
            "drift",
            "check",
            "--manifest",
            str(write_manifests(tmp_path / "manifests", bank_docs())),
            "--trace",
            str(write_trace(tmp_path / "t.json", DRIFT_EDGES)),
            "--metrics-out",
            str(out),
        ],
    )

    assert result.exit_code == 1
    content = out.read_text()
    assert 'agentic_auth_drift_checks_total{result="drift"} 1.0' in content
    assert 'agentic_auth_drift_undeclared_edges{verdict="UNDECLARED_TOOL"} 1.0' in content
    assert 'agentic_auth_drift_undeclared_edges{verdict="UNDECLARED_DELEGATION"} 0.0' in content
    assert "agentic_auth_drift_observed_edges 3.0" in content


@pytest.mark.parametrize("name", ["drift.txt", "drift"])
def test_the_metrics_textfile_must_be_a_prom_file(tmp_path, name) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "drift",
            "check",
            "--manifest",
            str(write_manifests(tmp_path / "manifests", bank_docs())),
            "--trace",
            str(write_trace(tmp_path / "t.json", DRIFT_EDGES)),
            "--metrics-out",
            str(tmp_path / name),
        ],
    )
    assert result.exit_code == 2


# -- Phase 4 (US6, T078): the new counters match a known mix ------------------------------


async def test_phase_4_counters_match_a_known_mix(
    client, admin_headers, consent, metrics_registry, flags, fake_idp, principal_assertion_for
) -> None:
    from app.sdk import AgenticAuthClient, AgentKey
    from tests.conftest import ADMIN_TOKEN
    from tests.fixtures.bank import (
        BALANCE_AGENT,
        BANK_ASSISTANT,
        KB_SEARCH_TOOL,
        SUPPORT_AGENT,
        TERMINATE_ACCOUNT,
        TERMINATE_PARAMS,
        bank_docs,
    )
    from tests.fixtures.hops import hop, register_agents

    await register_agents(client, admin_headers, bank_docs(widened=True))
    ids = {
        a["name"]: a["id"]
        for a in (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    }
    sdk = AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)

    # enrollments: 2 enrolled, 1 quarantined
    keys = {}
    for name in (BANK_ASSISTANT, BALANCE_AGENT):
        keys[name] = AgentKey.generate()
        await sdk.enroll(
            ids[name],
            key=keys[name],
            agent_name=name,
            principal_assertion=principal_assertion_for(name),
        )
    await sdk.enroll(ids[SUPPORT_AGENT], key=AgentKey.generate(), agent_name=SUPPORT_AGENT)

    # taint: two blocks (tool source), plus marks
    for _ in range(2):
        session = await consent(scope=BANK_ASSISTANT, user_sub="user:alice")
        _, t1 = await hop(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
        _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
        await authorize(client, t2, target=KB_SEARCH_TOOL, data_class="kb.internal")
        blocked = (
            await authorize(client, t2, target=TERMINATE_ACCOUNT, data_class="account.write")
        ).json()
        assert blocked["reason"] == "TAINTED_INTO_PRIVILEGED"

    # transaction mints: one minted, one already_minted, one not_privileged
    flags(taint_enforcement_enabled=False)
    session = await consent(scope=BANK_ASSISTANT, user_sub="user:alice")
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    _, tool = await hop(client, t2, target=TERMINATE_ACCOUNT, data_class="account.write")
    for _ in range(2):
        await client.post(
            "/v1/token/transaction",
            headers={"Authorization": f"Bearer {tool}"},
            json={"params": TERMINATE_PARAMS},
        )
    _, kb_tool = await hop(client, t2, target=KB_SEARCH_TOOL, data_class="kb.internal")
    await client.post(
        "/v1/token/transaction", headers={"Authorization": f"Bearer {kb_tool}"}, json={"params": {}}
    )

    # revocation: one revoke (+ an idempotent repeat), one refused hop at authorize
    await client.post(f"/v1/agents/{ids[BALANCE_AGENT]}/revoke", headers=admin_headers, json={})
    await client.post(f"/v1/agents/{ids[BALANCE_AGENT]}/revoke", headers=admin_headers, json={})
    refused = (
        await authorize(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    ).json()
    assert refused["reason"] == "AGENT_REVOKED"

    m = metrics_registry
    assert sample(m, "agentic_auth_taint_blocks_total", source_class="tool") == 2
    assert sample(m, "agentic_auth_taint_marks_total", propagation="self") >= 2
    assert sample(m, "agentic_auth_taint_marks_total", propagation="ancestor") >= 2
    assert sample(m, "agentic_auth_denials_total", reason="TAINTED_INTO_PRIVILEGED") == 2
    assert sample(m, "agentic_auth_transaction_mints_total", result="minted") == 1
    assert sample(m, "agentic_auth_transaction_mints_total", result="already_minted") == 1
    assert sample(m, "agentic_auth_transaction_mints_total", result="not_privileged") == 1
    assert sample(m, "agentic_auth_enrollments_total", outcome="enrolled") == 2
    assert sample(m, "agentic_auth_enrollments_total", outcome="quarantined") == 1
    assert sample(m, "agentic_auth_revocations_total") == 1
    assert sample(m, "agentic_auth_revoked_hop_refusals_total", where="authorize") == 1
    assert sample(m, "agentic_auth_denials_total", reason="AGENT_REVOKED") == 1

    # identity: with the flag on, a missing actor_token is counted
    flags(identity_required=True)
    session = await consent(scope=BANK_ASSISTANT, user_sub="user:alice")
    from tests.fixtures.hops import exchange

    d = (
        await authorize(
            client, session["root_grant"], target=KB_SEARCH_TOOL, data_class="kb.public"
        )
    ).json()
    r = await exchange(
        client,
        session["root_grant"],
        resource=KB_SEARCH_TOOL,
        scope="kb.public",
        action_id=d["action_id"],
    )
    assert r.status_code == 400
    assert sample(m, "agentic_auth_exchange_pop_failures_total", cause="missing") == 1


# ---------------------------------------------------------------------------------------
# Phase 6 (spec 007 FR-022): multi-process aggregation.
#
# Appended, not edited: the cases above are the Phase 3/4 metric contract and stay exactly as
# they were (see the no-regression gate in tests/conftest.py).
#
# With more than one uvicorn/gunicorn worker, each process holds its own counters. Without
# PROMETHEUS_MULTIPROC_DIR a scrape returns whichever worker answered, which silently
# under-reports every total on a dashboard — the kind of wrong number nobody notices.
# ---------------------------------------------------------------------------------------


def test_the_exposition_registry_switches_to_the_multiprocess_collector(
    tmp_path, monkeypatch
) -> None:
    """``exposition_registry()`` must consult the environment per call, not once at import:
    the directory is set by the process manager, which may start after this module is loaded."""
    from prometheus_client import CollectorRegistry

    from app.services.metrics import exposition_registry, get_metrics

    single = exposition_registry()
    assert single is get_metrics().registry, "single-process serves the live registry"

    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(tmp_path))
    multi = exposition_registry()
    assert isinstance(multi, CollectorRegistry)
    assert multi is not get_metrics().registry, "multiprocess must build a fresh collector"


def test_counters_from_several_processes_are_summed(tmp_path, monkeypatch) -> None:
    """The real aggregation, with values written by separate OS processes.

    Each child increments the same family by a different amount; the parent then collects from
    the shared directory and must see the sum, not one child's share.
    """
    import subprocess
    import sys

    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(tmp_path))

    child = """
import os, sys
from prometheus_client import CollectorRegistry, Counter, values

registry = CollectorRegistry()
c = Counter(
    "agentic_auth_decisions",
    "Decisions rendered, counted once recorded",
    ["outcome", "enforced", "target_kind"],
    registry=registry,
)
c.labels(outcome="allow", enforced="true", target_kind="tool").inc(int(sys.argv[1]))
"""
    for amount in (3, 5, 7):
        result = subprocess.run(
            [sys.executable, "-c", child, str(amount)],
            capture_output=True,
            text=True,
            env={**os.environ, "PROMETHEUS_MULTIPROC_DIR": str(tmp_path)},
        )
        assert result.returncode == 0, result.stderr[-2000:]

    from prometheus_client import CollectorRegistry, generate_latest, multiprocess

    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
    text = generate_latest(registry).decode()

    line = 'agentic_auth_decisions_total{enforced="true",outcome="allow",target_kind="tool"} 15.0'
    assert line in text, f"expected the sum of 3+5+7; got:\n{text}"
