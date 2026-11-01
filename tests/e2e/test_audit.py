"""Features → "Audit and operate".

The decision log, the chain query, audit export, metrics, and traces.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentic_auth.cli.audit import export_before
from agentic_auth.embedded import EmbeddedControlPlane
from agentic_auth.observability import surface
from agentic_auth.sdk import PolicyDenied
from agentic_auth.sidecar.app import build_app as build_sidecar
from agentic_auth.sidecar.config import SidecarConfig, Upstream
from tests.e2e.conftest import CONTROL_PLANE, asgi_client
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    READ_BALANCE,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    USER,
    bank_docs,
)
from tests.fixtures.discovery.server import RESOURCES

pytestmark = pytest.mark.e2e


async def test_every_decision_is_recorded_append_only(tmp_path: Path) -> None:
    """Decision log: allows and denies are both recorded, with the policy version they were
    judged under. The rows can't be edited or deleted, even by someone holding the store."""
    async with EmbeddedControlPlane.open(store=tmp_path / "cp.db", capabilities=RESOURCES) as cp:
        await cp.register(bank_docs())
        sdk = cp.client()
        session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
        await sdk.hop(
            session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
        )
        with pytest.raises(PolicyDenied):
            await sdk.authorize(
                session.context(), target=TERMINATE_ACCOUNT, data_class="account.write"
            )
        rows = (await sdk.audit.decisions())["data"]
        store = cp.store

    assert sorted((r["outcome"], r["deny_reason"]) for r in rows) == [
        ("allow", None),
        ("deny", "OUT_OF_SCOPE"),
    ]
    assert {r["policy_version"] for r in rows} == {1}
    assert {r["deployment"] for r in rows} == {"embedded"}

    with sqlite3.connect(store) as db:
        for statement in (
            "UPDATE audit_decisions SET outcome = 'allow'",
            "DELETE FROM audit_decisions",
        ):
            with pytest.raises(sqlite3.DatabaseError):
                db.execute(statement)
        assert db.execute("SELECT count(*) FROM audit_decisions").fetchone() == (2,)


async def test_one_query_traces_an_action_back_to_the_person(cp: EmbeddedControlPlane) -> None:
    """Chain query: from the action that called the tool, one query returns every agent
    involved and the consent at the root."""
    await cp.register(bank_docs())
    sdk = cp.client()
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, ctx = await sdk.hop(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    grant = await sdk.authorize(ctx, target=KB_SEARCH_TOOL, data_class="kb.internal")

    chain = await sdk.audit.chain(grant.action_id)

    assert chain["root_consent"]["user_sub"] == USER
    assert chain["root_consent"]["scope"] == BANK_ASSISTANT
    assert [hop["acting_agent"] for hop in chain["chain"]] == [
        BANK_ASSISTANT,
        BALANCE_AGENT,
        SUPPORT_AGENT,
    ]
    assert chain["complete"] is True


async def test_old_decisions_export_without_deleting_anything(tmp_path: Path) -> None:
    """Audit export: `agentic-auth audit export` writes every decision before a cutoff to
    a JSON-lines file, oldest first, and leaves the log as it was."""
    async with EmbeddedControlPlane.open(store=tmp_path / "cp.db", capabilities=RESOURCES) as cp:
        await cp.register(bank_docs())
        sdk = cp.client()
        session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
        _, ctx = await sdk.hop(
            session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
        )
        await sdk.authorize(ctx, target=READ_BALANCE, data_class="account.read")
        before = len((await sdk.audit.decisions())["data"])
        store = cp.store

    out = tmp_path / "archive.jsonl"
    exported = await export_before(
        f"sqlite+aiosqlite:///{store}", datetime.now(UTC) + timedelta(minutes=1), out
    )

    lines = [json.loads(line) for line in out.read_text().splitlines()]
    assert exported == before == len(lines) == 2
    assert [line["target"] for line in lines] == [f"agent://{BALANCE_AGENT}", READ_BALANCE]
    with sqlite3.connect(store) as db:
        assert db.execute("SELECT count(*) FROM audit_decisions").fetchone() == (2,)


async def test_enforcement_points_report_metrics_without_identities(cp, tool_server) -> None:
    """Metrics: a sidecar reports that it's up, its mode, and its decisions by outcome, in
    Prometheus format. No agent, person or target appears in any label."""
    tool_server("kb.internal")
    await cp.register(bank_docs())
    sdk = cp.client()
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, ctx = await sdk.hop(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    sidecar = build_sidecar(
        SidecarConfig(
            pdp_url=CONTROL_PLANE,
            upstream_map={
                "/kb": Upstream(
                    url="https://kb.internal", target=KB_SEARCH_TOOL, data_class="kb.internal"
                )
            },
        ).validate(),
        client=cp.http,
    )

    async with asgi_client(sidecar) as agent:
        await agent.get("/kb/search", headers={"Authorization": f"Bearer {ctx.token}"})
        exposition = (await agent.get("/__agentic/metrics")).text

    assert _series(exposition, "agentic_auth_pep_up") == 1.0
    assert any(
        line.startswith("agentic_auth_pep_info") and 'mode="enforcing"' in line
        for line in exposition.splitlines()
    )
    labels = " ".join(re.findall(r"\{([^}]*)\}", exposition))
    for identity in (USER, BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT, KB_SEARCH_TOOL):
        assert identity not in labels


async def test_decisions_emit_traces_with_pseudonymous_identities(cp, telemetry) -> None:
    """Traces and logs: with telemetry on, each decision emits a span carrying its outcome
    and reason. Agents and people appear only as keyed pseudonyms."""
    await cp.register(bank_docs())
    sdk = cp.client()
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
    await sdk.hop(session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read")
    with pytest.raises(PolicyDenied):
        await sdk.authorize(session.context(), target=TERMINATE_ACCOUNT, data_class="account.write")

    decides = telemetry.named(surface.SPAN_DECIDE)
    outcomes = sorted(span.attributes.get(surface.ATTR_OUTCOME) for span in decides)
    assert outcomes == ["allow", "deny"]
    exported = json.dumps([dict(span.attributes) for span in telemetry.spans()])
    for identity in (USER, BANK_ASSISTANT, BALANCE_AGENT):
        assert identity not in exported


def _series(text: str, name: str) -> float | None:
    for line in text.splitlines():
        if line.startswith(f"{name} "):
            return float(line.split()[1])
    return None
