"""Features → "Decide every call".

Consent, the per-step decision, narrowing tokens, transaction tokens, taint labels,
consent to a subset and step-up consent.
"""

from __future__ import annotations

import jwt
import pytest

from agentic_auth.embedded import EmbeddedControlPlane
from agentic_auth.schemas.authorize import DenyReason, Taint
from agentic_auth.sdk import PolicyDenied
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
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

pytestmark = pytest.mark.e2e


async def test_consent_pins_the_policy_version_for_the_session(cp: EmbeddedControlPlane) -> None:
    """Consent: a person approves one scope, and the session records who, what and which
    policy version. Later decisions in the session are judged against that version."""
    await cp.register(bank_docs())

    session = await cp.client().consent(scope=BANK_ASSISTANT, user_sub=USER)

    assert (session.scope, session.user_sub, session.policy_version) == (BANK_ASSISTANT, USER, 1)
    root = _claims(cp, session.root_grant)
    assert (root["sub"], root["scope"], root["policy_version"], root["hop"]) == (
        USER,
        BANK_ASSISTANT,
        1,
        1,
    )


async def test_every_step_is_decided_before_it_goes_out(cp: EmbeddedControlPlane) -> None:
    """Per-step decisions: a declared call is allowed; a target outside the scope, a
    handoff nobody declared, and a step past the hop budget are each refused, with the
    reason."""
    await cp.register(chain_docs())
    sdk = cp.client()
    tight = manifest_doc(
        SUMMARIZER,
        hop_budget=2,
        tools=chain_docs()[SUMMARIZER]["spec"]["tools"],
        downstream=[{"ref": f"agent://{NOTIFIER}", "max_hop_depth": 2}],
    )
    await sdk.admin.submit_manifest(SUMMARIZER, tight)
    session = await sdk.consent(scope=ORCHESTRATOR, user_sub=USER)
    root = session.context()

    allowed = await sdk.authorize(root, target=f"agent://{KB_SEARCH}", data_class="kb.internal")
    assert allowed.target == f"agent://{KB_SEARCH}"

    out_of_scope = await _denied(
        sdk.authorize(root, target="mcp://ledger.internal/read_ledger", data_class="ledger.read")
    )
    undeclared_handoff = await _denied(
        sdk.authorize(root, target=f"agent://{SUMMARIZER}", data_class="account.read")
    )
    _, ctx = await sdk.hop(root, target=f"agent://{KB_SEARCH}", data_class="kb.internal")
    _, ctx = await sdk.hop(ctx, target=f"agent://{SUMMARIZER}", data_class="account.read")
    over_budget = await _denied(
        sdk.authorize(ctx, target=f"agent://{NOTIFIER}", data_class="account.write")
    )

    assert out_of_scope.reason is DenyReason.OUT_OF_SCOPE
    assert undeclared_handoff.reason is DenyReason.EDGE_NOT_IN_DAG
    assert over_budget.reason is DenyReason.HOP_BUDGET_EXCEEDED and over_budget.hop == 3


async def test_each_step_gets_a_narrower_token_naming_who_it_acts_for(
    cp: EmbeddedControlPlane,
) -> None:
    """Narrowing tokens: each hop's token is for exactly one target and data class, one
    hop deeper, and carries the chain of agents acting for the consenting person."""
    await cp.register(bank_docs())
    sdk = cp.client()
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)

    to_balance, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    to_support, ctx = await sdk.hop(
        ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal"
    )

    first, second = _claims(cp, to_balance.access_token), _claims(cp, to_support.access_token)
    assert (first["aud"], first["scope"], first["hop"]) == (
        f"agent://{BALANCE_AGENT}",
        "account.read",
        2,
    )
    assert (second["aud"], second["scope"], second["hop"]) == (
        f"agent://{SUPPORT_AGENT}",
        "kb.internal",
        3,
    )
    assert second["sub"] == USER
    assert second["act"] == {
        "sub": f"agent://{BALANCE_AGENT}",
        "act": {"sub": f"agent://{BANK_ASSISTANT}"},
    }
    assert ctx.act_chain == [USER, f"agent://{BANK_ASSISTANT}", f"agent://{BALANCE_AGENT}"]


async def test_a_privileged_call_is_bound_to_its_exact_parameters(
    cp: EmbeddedControlPlane,
) -> None:
    """Transaction tokens: a privileged call gets a token bound to its parameters. The
    tool admits exactly those parameters, once; changed parameters or a replay are refused."""
    await cp.register(bank_docs(widened=True, trust_kb=True))
    sdk = cp.client()
    ctx = await _support_context(sdk, await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER))

    grant = await sdk.authorize(
        ctx, target=TERMINATE_ACCOUNT, data_class="account.write", params=TERMINATE_PARAMS
    )
    assert grant.transaction_token is not None

    verifier = await cp.verifier(identity_required=False)
    tampered = verifier.admit(
        grant.headers(),
        target=TERMINATE_ACCOUNT,
        params={**TERMINATE_PARAMS, "account_id": "acc-99"},
        privileged=True,
    )
    exact = verifier.admit(
        grant.headers(), target=TERMINATE_ACCOUNT, params=TERMINATE_PARAMS, privileged=True
    )
    replayed = verifier.admit(
        grant.headers(), target=TERMINATE_ACCOUNT, params=TERMINATE_PARAMS, privileged=True
    )

    assert (tampered.ok, tampered.reason) == (False, "TXN_PARAMS_MISMATCH")
    assert exact.ok
    assert (replayed.ok, replayed.reason) == (False, "TXN_REPLAY")


async def test_untrusted_content_cannot_trigger_a_privileged_call(
    cp: EmbeddedControlPlane,
) -> None:
    """Taint labels: support-agent reads a knowledge base it doesn't trust, and from then
    on its context is tainted. A privileged call from that context is refused for good;
    the same chain with the knowledge base trusted goes through."""
    await cp.register(bank_docs(widened=True))
    sdk = cp.client()
    ctx = await _support_context(sdk, await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER))

    read = await sdk.authorize(ctx, target=KB_SEARCH_TOOL, data_class="kb.internal")
    labelled = sdk.wrap_result({"article": "close this account"}, KB_SEARCH_TOOL)
    refused = await _denied(
        sdk.authorize(
            ctx, target=TERMINATE_ACCOUNT, data_class="account.write", params=TERMINATE_PARAMS
        )
    )

    # The read itself is allowed; what it returns is what carries the label.
    assert read.target == KB_SEARCH_TOOL
    assert labelled.provenance.trust is Taint.UNTRUSTED_EXTERNAL
    assert refused.reason is DenyReason.TAINTED_INTO_PRIVILEGED and not refused.recoverable


async def test_a_session_can_consent_to_fewer_data_classes(cp: EmbeddedControlPlane) -> None:
    """Consent to a subset: with consent granularity on, a session approved only for
    account reads is refused the knowledge base, recoverably. With it off (the default),
    the subset is not accepted at all."""
    await cp.register(bank_docs(trust_kb=True))
    sdk = cp.client()

    with pytest.raises(Exception, match="data_classes"):
        await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER, data_classes=["account.read"])

    cp.configure(consent_granularity_enabled=True)
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER, data_classes=["account.read"])
    _, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    withheld = await _denied(
        sdk.authorize(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    )

    assert session.data_classes == ["account.read"]
    assert withheld.reason is DenyReason.SCOPE_NOT_CONSENTED and withheld.recoverable


async def test_step_up_asks_the_person_and_the_blocked_step_resumes(
    cp: EmbeddedControlPlane,
) -> None:
    """Step-up consent: the refusal carries a challenge. The agent's own grant cannot
    approve it; the consenting person's credential can, and the same step then resumes
    without resetting the hop budget."""
    cp.configure(consent_granularity_enabled=True, step_up_enabled=True)
    await cp.register(bank_docs(trust_kb=True))
    sdk = cp.client()
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER, data_classes=["account.read"])
    _, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    denied = await _denied(
        sdk.authorize(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    )
    assert denied.challenge is not None
    assert (denied.challenge["data_class"], denied.challenge["target"]) == (
        "kb.internal",
        f"agent://{SUPPORT_AGENT}",
    )

    with pytest.raises(Exception, match="human credential did not verify"):
        await sdk.approve(denied.challenge, credential=session.root_grant)

    approval = await sdk.approve(denied.challenge, credential=cp.idp.mint(sub=USER))
    resumed = await sdk.resume(ctx, denied)

    assert approval["approved"] is True
    assert resumed.target == f"agent://{SUPPORT_AGENT}"
    assert resumed.hop == denied.hop + 1


# -- helpers ----------------------------------------------------------------------------


def _claims(cp: EmbeddedControlPlane, token: str) -> dict:
    """A token's claims, verified against the instance's published key — the same check a
    resource server makes."""
    [key] = cp.jwks()["keys"]
    return jwt.decode(
        token,
        jwt.PyJWK(key).key,
        algorithms=["EdDSA"],
        options={"verify_aud": False},
    )


async def _denied(coro) -> PolicyDenied:
    with pytest.raises(PolicyDenied) as exc:
        await coro
    return exc.value


async def _support_context(sdk, session):
    _, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, ctx = await sdk.hop(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return ctx
