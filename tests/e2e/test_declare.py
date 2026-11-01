"""Features → "Declare what an agent may do".

Manifests, reconciliation, immutable versions, the scope catalog, the CI drift check and
cold start — each driven as an integrator drives it.
"""

from __future__ import annotations

import contextlib
import copy
import json
from pathlib import Path

import pytest

from agentic_auth.coldstart.propose import propose
from agentic_auth.embedded import BASE_URL, EmbeddedControlPlane
from agentic_auth.schemas.authorize import DenyReason
from agentic_auth.schemas.edge_trace import EdgeTrace
from agentic_auth.sdk import ManifestRejected, PolicyDenied
from agentic_auth.sdk.drift import aggregate_trace, check_drift, exit_code_for
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_AGENTS,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    READ_BALANCE,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    TERMINATE_PARAMS,
    USER,
    bank_docs,
)
from tests.fixtures.discovery.server import RESOURCES

pytestmark = pytest.mark.e2e


async def test_manifests_register_and_reconcile(cp: EmbeddedControlPlane) -> None:
    """Manifests: each agent's declaration is accepted as version 1, and a session can be
    consented against the scope they compose into."""
    registrations = await cp.register(bank_docs())

    assert [r.status for r in registrations] == ["reconciled"] * len(BANK_AGENTS)
    assert {r.manifest_version for r in registrations} == {1}

    stored = await cp.client().admin.manifest(SUPPORT_AGENT)
    assert stored["doc"]["spec"]["tools"][0]["ref"] == KB_SEARCH_TOOL

    session = await cp.client().consent(scope=BANK_ASSISTANT, user_sub=USER)
    assert session.policy_version == 1 and session.hop_budget == 4


async def test_reconciliation_rejects_a_declaration_the_tool_does_not_publish(
    cp: EmbeddedControlPlane,
) -> None:
    """Reconciliation: a manifest claiming a data class the tool host doesn't publish is
    refused with a diff naming the exact tool and its remedy. The rejected version is kept
    for the reconciliation report, but no policy is compiled from it."""
    overreach = bank_docs()[SUPPORT_AGENT]
    overreach["spec"]["tools"][0]["data_classes"] = ["kb.secret"]
    overreach["spec"]["data_classes"]["reads"] = ["kb.secret"]

    with pytest.raises(ManifestRejected) as rejected:
        await cp.client().admin.register_agent(SUPPORT_AGENT, overreach)

    assert not rejected.value.needs_review
    [entry] = rejected.value.diff
    assert (entry["tool_ref"], entry["code"]) == (KB_SEARCH_TOOL, "DECLARED_EXCEEDS_DISCOVERED")
    assert "kb.secret" in entry["remedy"]

    admin = cp.client().admin
    [agent] = (await admin.agents())["data"]
    assert agent["latest_status"] == "rejected"
    assert (await admin.reconciliation(agent["id"]))["diff"] == rejected.value.diff
    with pytest.raises(Exception, match="no compiled policy"):
        await cp.client().consent(scope=SUPPORT_AGENT, user_sub=USER)


async def test_a_manifest_change_is_a_new_version_and_sessions_keep_theirs(
    cp: EmbeddedControlPlane,
) -> None:
    """Immutable versions: a change creates version 2, version 1 still reads back exactly
    as it was, and a session consented under version 1 keeps deciding against it."""
    await cp.register(bank_docs())
    sdk = cp.client()
    before = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
    original = await sdk.admin.manifest(SUPPORT_AGENT, version=1)

    widened = bank_docs(widened=True)[SUPPORT_AGENT]
    submitted = await sdk.admin.submit_manifest(SUPPORT_AGENT, widened)

    assert submitted.version == 2
    assert (await sdk.admin.manifest(SUPPORT_AGENT, version=1))["doc"] == original["doc"]
    # The older session still cannot reach the tool version 2 added.
    ctx = await _support_context(sdk, before)
    with pytest.raises(PolicyDenied) as denied:
        await sdk.authorize(ctx, target=TERMINATE_ACCOUNT, data_class="account.write")
    assert denied.value.reason is DenyReason.OUT_OF_SCOPE


async def test_the_scope_catalog_shows_what_consent_grants(cp: EmbeddedControlPlane) -> None:
    """Scope catalog: consenting to bank-assistant grants every tool reachable down its
    declared chain, and nothing else."""
    await cp.register(bank_docs())

    catalog = await cp.client().admin.scope_catalog(BANK_ASSISTANT)

    assert catalog["scope"] == BANK_ASSISTANT
    assert {t["ref"] for t in catalog["tools"]} == {READ_BALANCE, KB_SEARCH_TOOL}
    assert catalog["downstream_agents"] == [f"agent://{BALANCE_AGENT}"]
    assert TERMINATE_ACCOUNT not in json.dumps(catalog)


async def test_the_drift_check_fails_on_an_undeclared_call(
    cp: EmbeddedControlPlane, tmp_path: Path
) -> None:
    """CI drift check: record the agents' calls, then check them against the manifests in
    the repository. A call to a tool support-agent never declared fails the check and names
    the manifest to change; the same run without it passes."""
    manifests = _write_manifests(tmp_path / "manifests", bank_docs())
    await cp.register(bank_docs())

    clean = await _record(cp, tmp_path / "clean", reach_for_terminate=False)
    drifted = await _record(cp, tmp_path / "drifted", reach_for_terminate=True)

    passing = check_drift([manifests], clean)
    failing = check_drift([manifests], drifted)

    assert (passing.result, exit_code_for(passing)) == ("pass", 0)
    assert failing.result == "drift" and exit_code_for(failing) != 0
    [edge] = failing.undeclared
    assert (edge.from_, edge.to, edge.verdict) == (
        SUPPORT_AGENT,
        TERMINATE_ACCOUNT,
        "UNDECLARED_TOOL",
    )
    assert edge.manifest_path.endswith(f"{SUPPORT_AGENT}.json")


async def test_cold_start_proposes_a_manifest_that_governs_only_after_review(
    cp: EmbeddedControlPlane, tmp_path: Path
) -> None:
    """Cold start: an agent registered with no manifest authorizes nothing. Its calls are
    recorded under test, a manifest is proposed from the trace, and a person reviews it.
    Only what the reviewed manifest declares is then allowed."""
    created = await cp.http.post(
        f"{BASE_URL}/v1/agents",
        json={"name": SUPPORT_AGENT},
        headers={"Authorization": f"Bearer {cp.admin_token}"},
    )
    assert created.status_code == 201
    with pytest.raises(Exception, match="no compiled policy"):
        await cp.client().consent(scope=SUPPORT_AGENT, user_sub=USER)

    # Under test: the agent runs against its test environment with recording on. Only the
    # trace crosses over; nothing from the test environment's policy does.
    async with EmbeddedControlPlane.open(capabilities=RESOURCES) as test_env:
        # The test environment lets support-agent use both tools, so its tests exercise
        # everything it does.
        await test_env.register(bank_docs(widened=True, trust_kb=True))
        trace = await _record(test_env, tmp_path / "under-test", reach_for_terminate=True)

    proposal = propose(
        EdgeTrace.model_validate_json(trace.read_text()), SUPPORT_AGENT, run_id="local"
    )
    observed = proposal["x-proposal"]["observed"]["tools"]
    assert set(observed) == {KB_SEARCH_TOOL, TERMINATE_ACCOUNT}
    assert not proposal["x-proposal"]["covers_no_behaviour"]

    # The review: fill in what a trace can't know, and drop what the agent shouldn't do.
    reviewed = copy.deepcopy(proposal)
    reviewed.pop("x-proposal")
    reviewed["spec"]["tools"] = [
        {"ref": KB_SEARCH_TOOL, "data_classes": ["kb.internal"], "privileged": False}
    ]
    reviewed["spec"]["data_classes"] = {"reads": ["kb.internal"], "writes": []}
    submitted = await cp.client().admin.submit_manifest(SUPPORT_AGENT, reviewed)
    assert submitted.version == 1

    sdk = cp.client()
    session = await sdk.consent(scope=SUPPORT_AGENT, user_sub=USER)
    allowed = await sdk.authorize(
        session.context(), target=KB_SEARCH_TOOL, data_class="kb.internal"
    )
    assert allowed.target == KB_SEARCH_TOOL
    with pytest.raises(PolicyDenied) as denied:
        await sdk.authorize(session.context(), target=TERMINATE_ACCOUNT, data_class="account.write")
    assert denied.value.reason is DenyReason.OUT_OF_SCOPE


# -- helpers ----------------------------------------------------------------------------


async def _support_context(sdk, session):
    """bank-assistant -> balance-agent -> support-agent: the context support-agent holds."""
    _, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, ctx = await sdk.hop(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return ctx


async def _record(cp: EmbeddedControlPlane, directory: Path, *, reach_for_terminate: bool) -> Path:
    """Run the bank chain with edge recording on, as `agentic-auth drift record` does, and
    aggregate what was recorded into one trace file."""
    directory.mkdir(parents=True)
    events = directory / "events.jsonl"
    sdk = cp.client(trace_path=events)
    try:
        session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
        ctx = await _support_context(sdk, session)
        await sdk.authorize(ctx, target=KB_SEARCH_TOOL, data_class="kb.internal")
        if reach_for_terminate:
            # Refused or not, the attempt is what the drift check is about.
            with contextlib.suppress(PolicyDenied):
                await sdk.authorize(
                    ctx,
                    target=TERMINATE_ACCOUNT,
                    data_class="account.write",
                    params=TERMINATE_PARAMS,
                )
    finally:
        await sdk.aclose()
    trace = directory / "trace.json"
    aggregate_trace([events], out=trace)
    return trace


def _write_manifests(directory: Path, docs: dict) -> Path:
    directory.mkdir(parents=True)
    for name, doc in docs.items():
        (directory / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")
    return directory
