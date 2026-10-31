"""The conformance scenarios (contracts/conformance-suite.md), each run against both
deployments. A scenario asserts the behaviour it is about *and* records a transcript;
``test_zz_identical.py`` then requires the two deployments' transcripts to be equal.
"""

from __future__ import annotations

import pytest

from agentic_auth.schemas.authorize import DenyReason, Taint
from agentic_auth.sdk import AgentKey, ManifestRejected, PolicyDenied
from tests.conformance.transcript import Transcript, audit_view, chain_view
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    READ_BALANCE,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    TERMINATE_PARAMS,
    USER,
    bank_docs,
)
from tests.fixtures.chains import (
    KB_SEARCH,
    NOTIFIER,
    ORCHESTRATOR,
    SUMMARIZER,
    chain_docs,
    manifest_doc,
)

pytestmark = pytest.mark.conformance


def _t(request, deployment) -> Transcript:
    return Transcript(request.node.originalname, deployment.name)


async def _denied(coro) -> PolicyDenied:
    with pytest.raises(PolicyDenied) as exc:
        await coro
    return exc.value


async def _to_support(sdk, session):
    """bank-assistant -> balance-agent -> support-agent: the context support-agent holds."""
    _, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, ctx = await sdk.hop(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return ctx


async def test_s01_three_hop_allow(request, deployment) -> None:
    t = _t(request, deployment)
    await deployment.register(chain_docs())
    sdk = deployment.sdk
    session = await sdk.consent(scope=ORCHESTRATOR, user_sub=USER)
    t.add("session", {"hop_budget": session.hop_budget, "policy_version": session.policy_version})

    ctx = session.context()
    for target, data_class in (
        (f"agent://{KB_SEARCH}", "kb.internal"),
        (f"agent://{SUMMARIZER}", "account.read"),
        (f"agent://{NOTIFIER}", "account.write"),
    ):
        grant, ctx = await sdk.hop(ctx, target=target, data_class=data_class)
        t.grant(target, grant)
        t.add("ctx", {"hop": ctx.hop, "act_chain": ctx.act_chain})

    assert ctx.act_chain == [
        USER,
        f"agent://{ORCHESTRATOR}",
        f"agent://{KB_SEARCH}",
        f"agent://{SUMMARIZER}",
    ]
    t.add("audit", audit_view(await sdk.audit.decisions()))
    t.save()


async def test_s02_out_of_scope(request, deployment) -> None:
    t = _t(request, deployment)
    await deployment.register(chain_docs())
    session = await deployment.sdk.consent(scope=ORCHESTRATOR, user_sub=USER)
    denied = await _denied(
        deployment.sdk.authorize(
            session.context(), target="mcp://ledger.internal/read_ledger", data_class="ledger.read"
        )
    )
    assert denied.reason is DenyReason.OUT_OF_SCOPE and not denied.recoverable
    t.denial("ledger", denied)
    t.add("audit", audit_view(await deployment.sdk.audit.decisions()))
    t.save()


async def test_s03_hop_budget_exceeded(request, deployment) -> None:
    t = _t(request, deployment)
    await deployment.register(chain_docs())
    sdk = deployment.sdk
    tight = manifest_doc(
        SUMMARIZER,
        hop_budget=2,
        tools=chain_docs()[SUMMARIZER]["spec"]["tools"],
        downstream=[{"ref": f"agent://{NOTIFIER}", "max_hop_depth": 2}],
    )
    submitted = await sdk.admin.submit_manifest(SUMMARIZER, tight)
    t.add("submitted", {"version": submitted.version, "status": submitted.status})
    session = await sdk.consent(scope=ORCHESTRATOR, user_sub=USER)
    ctx = session.context()
    for target, data_class in (
        (f"agent://{KB_SEARCH}", "kb.internal"),
        (f"agent://{SUMMARIZER}", "account.read"),
    ):
        grant, ctx = await sdk.hop(ctx, target=target, data_class=data_class)
        t.grant(target, grant)

    denied = await _denied(
        sdk.authorize(ctx, target=f"agent://{NOTIFIER}", data_class="account.write")
    )
    assert denied.reason is DenyReason.HOP_BUDGET_EXCEEDED and denied.hop == 3
    t.denial("notifier", denied)
    t.save()


async def test_s04_edge_not_in_dag(request, deployment) -> None:
    t = _t(request, deployment)
    await deployment.register(chain_docs())
    session = await deployment.sdk.consent(scope=ORCHESTRATOR, user_sub=USER)
    denied = await _denied(
        deployment.sdk.authorize(
            session.context(), target=f"agent://{SUMMARIZER}", data_class="account.read"
        )
    )
    assert denied.reason is DenyReason.EDGE_NOT_IN_DAG
    t.denial("skip-a-hop", denied)
    t.save()


async def test_s05_tainted_into_privileged(request, deployment) -> None:
    """The PRD §2.3 injection: support-agent reads the KB it does not trust, then reaches
    for terminate_account. Refused, and never recoverable."""
    t = _t(request, deployment)
    await deployment.register(bank_docs(widened=True))
    sdk = deployment.sdk
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
    ctx = await _to_support(sdk, session)

    read = await sdk.authorize(ctx, target=KB_SEARCH_TOOL, data_class="kb.internal")
    t.grant("kb", read)
    denied = await _denied(
        sdk.authorize(
            ctx, target=TERMINATE_ACCOUNT, data_class="account.write", params=TERMINATE_PARAMS
        )
    )
    assert denied.reason is DenyReason.TAINTED_INTO_PRIVILEGED and not denied.recoverable
    t.denial("terminate", denied)
    t.add("audit", audit_view(await sdk.audit.decisions()))
    t.save()


async def test_s06_scope_not_consented_is_recoverable(request, deployment) -> None:
    t = _t(request, deployment)
    await deployment.register(chain_docs())
    session = await deployment.sdk.consent(scope=ORCHESTRATOR, user_sub=USER)
    denied = await _denied(
        deployment.sdk.authorize(
            session.context(), target=f"agent://{KB_SEARCH}", data_class="account.write"
        )
    )
    assert denied.reason is DenyReason.SCOPE_NOT_CONSENTED and denied.recoverable
    t.denial("undeclared-class", denied)
    t.save()


async def test_s07_transaction_token_is_bound_to_its_params(request, deployment) -> None:
    t = _t(request, deployment)
    await deployment.register(bank_docs(widened=True, trust_kb=True))
    sdk = deployment.sdk
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
    ctx = await _to_support(sdk, session)
    grant = await sdk.authorize(
        ctx, target=TERMINATE_ACCOUNT, data_class="account.write", params=TERMINATE_PARAMS
    )
    t.grant("terminate", grant)
    assert grant.transaction_token is not None

    verifier = await deployment.verifier(identity_required=False)
    tampered = verifier.admit(
        grant.headers(),
        target=TERMINATE_ACCOUNT,
        params={**TERMINATE_PARAMS, "account_id": "acc-99"},
        privileged=True,
    )
    exact = verifier.admit(
        grant.headers(), target=TERMINATE_ACCOUNT, params=TERMINATE_PARAMS, privileged=True
    )
    assert not tampered.ok and exact.ok
    t.add("admit", {"tampered": tampered.reason, "exact": exact.ok})
    t.save()


async def test_s08_revocation_mid_chain(request, deployment) -> None:
    t = _t(request, deployment)
    deployment.flags(taint_enforcement_enabled=False)
    await deployment.register(bank_docs(widened=True))
    sdk = deployment.sdk
    for name in (BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT):
        outcome = await deployment.enroll(name, AgentKey.generate())
        t.add(f"enroll:{name}", outcome["status"])

    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    revoked = await sdk.revoke(await sdk.admin.agent_id(BALANCE_AGENT), reason="compromised")
    t.add("revoke", {"status": revoked["status"]})

    denied = await _denied(
        sdk.authorize(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    )
    assert denied.reason is DenyReason.AGENT_REVOKED
    t.denial("after-revoke", denied)
    t.save()


async def test_s09_identity_without_a_grant_is_not_admitted(request, deployment) -> None:
    t = _t(request, deployment)
    deployment.flags(taint_enforcement_enabled=False)
    await deployment.register(bank_docs(widened=True))
    keys = {name: AgentKey.generate() for name in (BANK_ASSISTANT, BALANCE_AGENT)}
    for name, key in keys.items():
        await deployment.enroll(name, key)

    session = await deployment.sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
    assistant = deployment.agent_client(BANK_ASSISTANT, keys[BANK_ASSISTANT])
    _, ctx = await assistant.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    balance = deployment.agent_client(BALANCE_AGENT, keys[BALANCE_AGENT])
    grant = await balance.authorize(ctx, target=READ_BALANCE, data_class="account.read")
    t.grant("read_balance", grant)

    verifier = await deployment.verifier(agents=[BALANCE_AGENT])
    identity_only = {k: v for k, v in grant.headers().items() if k != "Authorization"}
    refused = verifier.admit(identity_only, target=READ_BALANCE)
    admitted = verifier.admit(grant.headers(), target=READ_BALANCE)
    assert not refused.ok and admitted.ok
    t.add("admit", {"identity_only": refused.reason, "with_grant": admitted.ok})
    t.save()


async def test_s10_chain_query_reaches_the_consenting_human(request, deployment) -> None:
    t = _t(request, deployment)
    await deployment.register(chain_docs())
    sdk = deployment.sdk
    session = await sdk.consent(scope=ORCHESTRATOR, user_sub=USER)
    ctx = session.context()
    grant = None
    for target, data_class in (
        (f"agent://{KB_SEARCH}", "kb.internal"),
        (f"agent://{SUMMARIZER}", "account.read"),
        (f"agent://{NOTIFIER}", "account.write"),
    ):
        grant, ctx = await sdk.hop(ctx, target=target, data_class=data_class)
    assert grant is not None and grant.action_id is not None

    chain = chain_view(await sdk.audit.chain(grant.action_id))
    assert chain["complete"] and chain["root"] == {"user_sub": USER, "scope": ORCHESTRATOR}
    assert [h["acting_agent"] for h in chain["hops"]] == [ORCHESTRATOR, KB_SEARCH, SUMMARIZER]
    t.add("chain", chain)
    t.save()


async def test_s11_audit_rows_are_append_only(request, deployment) -> None:
    t = _t(request, deployment)
    await deployment.register(chain_docs())
    session = await deployment.sdk.consent(scope=ORCHESTRATOR, user_sub=USER)
    await deployment.sdk.hop(
        session.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal"
    )
    update = await deployment.raw_sql("UPDATE audit_decisions SET outcome = 'deny'")
    delete = await deployment.raw_sql("DELETE FROM audit_decisions")
    assert (update, delete) == ("refused", "refused")
    rows = audit_view(await deployment.sdk.audit.decisions())
    assert [r["outcome"] for r in rows] == ["allow"] and rows[0]["chain_complete"]
    t.add("raw", {"update": update, "delete": delete})
    t.add("audit", rows)
    t.save()


async def test_s12_reconciliation_rejects_with_a_diff(request, deployment) -> None:
    t = _t(request, deployment)
    overreach = manifest_doc(
        KB_SEARCH,
        hop_budget=4,
        tools=[
            {
                "ref": "mcp://kb.internal/search",
                "data_classes": ["kb.secret"],
                "privileged": False,
            }
        ],
    )
    with pytest.raises(ManifestRejected) as exc:
        await deployment.sdk.admin.register_agent(KB_SEARCH, overreach)
    assert exc.value.diff and not exc.value.needs_review
    t.add("diff", exc.value.diff)
    t.save()


def test_taint_is_a_recognised_label() -> None:
    """Guards the Taint import used by the transcript's grant view."""
    assert Taint.UNTRUSTED_EXTERNAL.value == "untrusted_external"
