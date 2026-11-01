"""Features → "Prove who the agent is".

Enrollment, the offline verifier, revocation and required identity.
"""

from __future__ import annotations

import pytest

from agentic_auth.embedded import EmbeddedControlPlane
from agentic_auth.schemas.authorize import DenyReason
from agentic_auth.sdk import AgentKey, PolicyDenied
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    READ_BALANCE,
    SUPPORT_AGENT,
    USER,
    bank_docs,
)

pytestmark = pytest.mark.e2e


async def test_enrollment_binds_a_key_to_a_person_or_quarantines(
    cp: EmbeddedControlPlane,
) -> None:
    """Enrollment: an agent that proves its key and is named by its owner's ID token is
    enrolled. One whose ID token names a different agent is quarantined: identified, and
    authorized for nothing."""
    await cp.register(bank_docs())
    sdk = cp.client()

    enrolled = await cp.enroll_test_principal(BALANCE_AGENT, AgentKey.generate(), principal=USER)
    quarantined = await sdk.enroll(
        await sdk.admin.agent_id(SUPPORT_AGENT),
        key=AgentKey.generate(),
        agent_name=SUPPORT_AGENT,
        principal_assertion=cp.idp.mint(agent=BALANCE_AGENT, sub=USER),
        enroll_token=cp.enroll_token,
    )

    assert enrolled["status"] == "enrolled" and enrolled["trust_anchor_version"] == 1
    assert quarantined["status"] == "quarantined"
    assert quarantined["reason"] == "PRINCIPAL_UNBINDABLE"
    identity = await sdk.identity.of(SUPPORT_AGENT)
    assert (identity["status"], identity["trust_anchor_version"]) == ("quarantined", None)


async def test_the_verifier_checks_calls_with_no_network_call(cp: EmbeddedControlPlane) -> None:
    """Offline verifier: after one bootstrap, the tool admits a call carrying a grant and
    the agent's identity even while the control plane is unreachable."""
    _, balance = await _enrolled_balance_agent(cp)
    verifier = await cp.verifier(agents=[BALANCE_AGENT])
    grant = await _read_balance_grant(cp, balance)

    cp.cut()
    try:
        admission = verifier.admit(grant.headers(), target=READ_BALANCE)
    finally:
        cp.restore()

    assert admission.ok
    assert admission.identity is not None and admission.grant is not None


async def test_revocation_cuts_off_the_agent_and_every_chain_through_it(
    cp: EmbeddedControlPlane,
) -> None:
    """Revocation: once an agent is revoked, the next hop through it is refused by the
    control plane, and a verifier refuses its identity at its next refresh."""
    _, balance = await _enrolled_balance_agent(cp)
    verifier = await cp.verifier(agents=[BALANCE_AGENT])
    sdk = cp.client()
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, ctx = await sdk.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    grant = await balance.authorize(ctx, target=READ_BALANCE, data_class="account.read")
    assert verifier.admit(grant.headers(), target=READ_BALANCE).ok

    revoked = await sdk.revoke(await sdk.admin.agent_id(BALANCE_AGENT), reason="key compromised")
    await verifier.anchors.refresh(raise_on_error=True)

    with pytest.raises(PolicyDenied) as through_it:
        await sdk.authorize(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    assert revoked["status"] == "revoked"
    assert through_it.value.reason is DenyReason.AGENT_REVOKED
    after = verifier.admit(grant.headers(), target=READ_BALANCE)
    assert (after.ok, after.reason) == (False, "IDENTITY_REVOKED")


async def test_required_identity_refuses_agents_that_have_not_enrolled(
    cp: EmbeddedControlPlane,
) -> None:
    """Required identity: with it on, an enrolled agent proves its key and carries on,
    while the next agent down the chain, which never enrolled, is refused."""
    await cp.register(bank_docs())
    key = AgentKey.generate()
    await cp.enroll_test_principal(BANK_ASSISTANT, key, principal=USER)
    cp.configure(identity_required=True)
    session = await cp.client().consent(scope=BANK_ASSISTANT, user_sub=USER)

    _, ctx = await cp.client(BANK_ASSISTANT, key=key).hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    with pytest.raises(PolicyDenied) as never_enrolled:
        await cp.client().authorize(ctx, target=READ_BALANCE, data_class="account.read")

    assert ctx.act_chain == [USER, f"agent://{BANK_ASSISTANT}"]
    assert never_enrolled.value.reason is DenyReason.AGENT_NOT_ENROLLED


# -- helpers ----------------------------------------------------------------------------


async def _enrolled_balance_agent(cp: EmbeddedControlPlane):
    """The bank chain registered, balance-agent enrolled, and the client it uses."""
    await cp.register(bank_docs())
    key = AgentKey.generate()
    outcome = await cp.enroll_test_principal(BALANCE_AGENT, key, principal=USER)
    assert outcome["status"] == "enrolled"
    return key, cp.client(BALANCE_AGENT, key=key)


async def _read_balance_grant(cp: EmbeddedControlPlane, balance):
    session = await cp.client().consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, ctx = await cp.client().hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    return await balance.authorize(ctx, target=READ_BALANCE, data_class="account.read")
