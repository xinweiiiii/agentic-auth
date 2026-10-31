"""An agent nobody can modify is still governed, at the resource the team owns
(US2; FR-007..FR-009; SC-004, SC-005).

The harness here deliberately does **not** cooperate: it builds presentations by hand,
including ones a well-behaved SDK would never send. That is the point of the rung — the
external agent's cooperation is irrelevant, so the tests must not quietly assume it.

Every refusal is asserted twice: the status the caller sees, and whether the tool
*actually ran*. A guard that returns 403 after executing the handler would pass the first
check and fail the one that matters.
"""

from __future__ import annotations

import pytest

from agentic_auth.sdk import AgenticAuthClient, AgentKey
from tests.conftest import ADMIN_TOKEN
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    READ_BALANCE,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    TERMINATE_PARAMS,
    USER,
    bank_docs,
)
from tests.fixtures.hops import register_agents


@pytest.fixture
async def guarded(client, admin_headers, flags, fake_idp, principal_assertion_for, resource_stack):
    """Bank agents enrolled, identity on, the guarded resource bootstrapped and offline."""
    flags(taint_enforcement_enabled=False)  # this file is about admission, not taint
    await register_agents(client, admin_headers, bank_docs(widened=True))
    listing = (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    ids = {a["name"]: a["id"] for a in listing}

    keys: dict[str, AgentKey] = {}
    sdk = AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)
    for name in (BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT):
        key = AgentKey.generate(kid=f"{name}-k1")
        outcome = await sdk.enroll(
            ids[name], key=key, agent_name=name, principal_assertion=principal_assertion_for(name)
        )
        assert outcome["status"] == "enrolled", outcome
        keys[name] = key
    flags(identity_required=True)

    resource, recorder, verifier = await resource_stack.build_guarded(
        agents=[BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT]
    )

    from types import SimpleNamespace

    return SimpleNamespace(
        keys=keys,
        ids=ids,
        resource=resource,
        recorder=recorder,
        verifier=verifier,
        stack=resource_stack,
    )


def _sdk(client, key: AgentKey | None = None, name: str | None = None) -> AgenticAuthClient:
    return AgenticAuthClient(
        base_url="http://test",
        admin_token=ADMIN_TOKEN,
        client=client,
        identity_key=key,
        agent_name=name,
    )


async def _grant_for(client, guarded, target: str, data_class: str, *, params=None):
    """Walk the chain properly and return the headers a cooperating agent would send."""
    root = _sdk(client, guarded.keys[BANK_ASSISTANT], BANK_ASSISTANT)
    session = await root.consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, ctx = await root.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    balance = _sdk(client, guarded.keys[BALANCE_AGENT], BALANCE_AGENT)
    if target == READ_BALANCE:
        grant = await balance.authorize(ctx, target=target, data_class=data_class)
        return grant.headers()

    _, ctx = await balance.hop(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    support = _sdk(client, guarded.keys[SUPPORT_AGENT], SUPPORT_AGENT)
    grant = await support.authorize(ctx, target=target, data_class=data_class, params=params)
    return grant.headers()


# -- the full valid set is admitted -------------------------------------------------


async def test_a_complete_presentation_is_admitted(client, guarded) -> None:
    headers = await _grant_for(client, guarded, READ_BALANCE, "account.read")

    response = await guarded.resource.get("/read_balance", headers=headers)

    assert response.status_code == 200
    assert guarded.recorder.executed == [READ_BALANCE]
    assert guarded.recorder.last[1].ok


async def test_a_privileged_call_with_a_bound_authority_is_admitted(client, guarded) -> None:
    headers = await _grant_for(
        client, guarded, TERMINATE_ACCOUNT, "account.write", params=TERMINATE_PARAMS
    )

    response = await guarded.resource.post(
        "/terminate_account", headers=headers, json=TERMINATE_PARAMS
    )

    assert response.status_code == 200, response.text
    assert guarded.recorder.executed == [TERMINATE_ACCOUNT]
    # The guard buffered the body to bind it, then replayed exactly those bytes.
    assert guarded.recorder.bodies[-1]


# -- the uncooperative matrix (SC-004) ----------------------------------------------


async def test_nothing_presented_is_refused(guarded) -> None:
    response = await guarded.resource.get("/read_balance")

    assert response.status_code == 401
    assert response.json()["error"]["details"]["reason"] == "GRANT_MISSING"
    assert guarded.recorder.executed == [], "the tool must not run"


async def test_identity_only_is_refused(client, guarded) -> None:
    """The headline rule: proving who you are authorizes nothing (FR-015/FR-017)."""
    headers = await _grant_for(client, guarded, READ_BALANCE, "account.read")
    identity_only = {"Agent-Identity": headers["Agent-Identity"]}

    response = await guarded.resource.get("/read_balance", headers=identity_only)

    assert response.status_code == 401
    assert response.json()["error"]["details"]["reason"] == "GRANT_MISSING"
    assert guarded.recorder.executed == []


async def test_grant_only_is_refused_when_identity_is_required(client, guarded) -> None:
    headers = await _grant_for(client, guarded, READ_BALANCE, "account.read")
    grant_only = {"Authorization": headers["Authorization"]}

    response = await guarded.resource.get("/read_balance", headers=grant_only)

    assert response.status_code == 401
    assert response.json()["error"]["details"]["reason"] == "IDENTITY_MISSING"
    assert guarded.recorder.executed == []


async def test_a_grant_for_another_target_is_refused(client, guarded) -> None:
    """A grant is for one target. Presenting a read_balance grant at terminate_account is
    the repurposing the whole design exists to stop."""
    headers = await _grant_for(client, guarded, READ_BALANCE, "account.read")

    response = await guarded.resource.post(
        "/terminate_account", headers=headers, json=TERMINATE_PARAMS
    )

    assert response.status_code == 403
    assert guarded.recorder.last[1].reason in {"GRANT_TARGET_MISMATCH", "GRANT_INVALID"}
    assert guarded.recorder.executed == []


async def test_a_privileged_call_without_a_bound_authority_is_refused(client, guarded) -> None:
    headers = await _grant_for(
        client, guarded, TERMINATE_ACCOUNT, "account.write", params=TERMINATE_PARAMS
    )
    without_txn = {k: v for k, v in headers.items() if k.lower() != "txn-token"}

    response = await guarded.resource.post(
        "/terminate_account", headers=without_txn, json=TERMINATE_PARAMS
    )

    assert response.status_code == 401
    assert response.json()["error"]["details"]["reason"] == "TXN_MISSING"
    assert guarded.recorder.executed == []


async def test_mutated_parameters_are_refused(client, guarded) -> None:
    """The authority was bound to account acc-42. Presenting it for another account is
    exactly FR-9's repurposing case, caught at the resource."""
    headers = await _grant_for(
        client, guarded, TERMINATE_ACCOUNT, "account.write", params=TERMINATE_PARAMS
    )
    mutated = {**TERMINATE_PARAMS, "account_id": "acc-99"}

    response = await guarded.resource.post("/terminate_account", headers=headers, json=mutated)

    assert response.status_code == 403
    assert guarded.recorder.last[1].reason == "TXN_PARAMS_MISMATCH"
    assert guarded.recorder.executed == []


async def test_a_replayed_bound_authority_is_refused(client, guarded) -> None:
    headers = await _grant_for(
        client, guarded, TERMINATE_ACCOUNT, "account.write", params=TERMINATE_PARAMS
    )

    first = await guarded.resource.post(
        "/terminate_account", headers=headers, json=TERMINATE_PARAMS
    )
    second = await guarded.resource.post(
        "/terminate_account", headers=headers, json=TERMINATE_PARAMS
    )

    assert first.status_code == 200
    assert second.status_code == 403
    assert guarded.recorder.last[1].reason == "TXN_REPLAY"
    assert guarded.recorder.executed == [TERMINATE_ACCOUNT], "it must run exactly once"


async def test_a_body_too_large_to_bind_is_refused(client, resource_stack, guarded) -> None:
    """Over the cap is a refusal, never a forward: a body we cannot bind is a body we can
    say nothing about."""
    small, recorder, _ = await resource_stack.build_guarded(
        agents=[BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT], max_body_bytes=16
    )
    headers = await _grant_for(
        client, guarded, TERMINATE_ACCOUNT, "account.write", params=TERMINATE_PARAMS
    )

    response = await small.post(
        "/terminate_account", headers=headers, json={"account_id": "x" * 500}
    )

    assert response.status_code == 403
    assert response.json()["error"]["details"]["reason"] == "BODY_TOO_LARGE_TO_BIND"
    assert recorder.executed == []


async def test_a_non_object_body_on_a_privileged_call_is_refused(client, guarded) -> None:
    headers = await _grant_for(
        client, guarded, TERMINATE_ACCOUNT, "account.write", params=TERMINATE_PARAMS
    )

    response = await guarded.resource.post(
        "/terminate_account",
        headers={**headers, "content-type": "application/json"},
        content=b'["not", "an", "object"]',
    )

    assert response.status_code == 403
    assert guarded.recorder.executed == []


# -- opt-in per resource (spec story 2 scenario 8) -----------------------------------


async def test_an_unguarded_route_in_the_same_app_is_untouched(guarded) -> None:
    response = await guarded.resource.get("/public/health")

    assert response.status_code == 200
    assert guarded.recorder.executed == ["public"]
    assert guarded.recorder.admissions == [], "the guard must not even look at it"


# -- the guarantee level it reports ---------------------------------------------------


async def test_a_refusal_names_the_guarantee_level(guarded) -> None:
    response = await guarded.resource.get("/read_balance")

    assert response.json()["error"]["details"]["guarantee_level"] == "full"


# -- offline after bootstrap (SC-005) -------------------------------------------------


async def test_verification_completes_with_the_control_plane_cut(
    client, guarded, resource_stack
) -> None:
    """The guard verifies identity against material pinned at bootstrap, with no call at
    request time. An outage in the control plane must not take every protected resource
    down with it."""
    headers = await _grant_for(client, guarded, READ_BALANCE, "account.read")
    resource_stack.transport.cut = True
    before = resource_stack.transport.requests

    response = await guarded.resource.get("/read_balance", headers=headers)

    assert response.status_code == 200
    assert resource_stack.transport.requests == before, "no network call on the request path"


async def test_a_stale_anchor_view_refuses(client, guarded, resource_stack) -> None:
    """Fail closed on staleness: a verifier that cannot refresh its revocation view does
    not know whether this agent is still trusted, and admitting on that is how a revoked
    agent keeps working (FR-009)."""
    headers = await _grant_for(client, guarded, READ_BALANCE, "account.read")
    resource_stack.transport.cut = True

    # Age the view past the freshness window without touching the clock the tokens use:
    # identity.py compares `anchors.as_of()` against now, so backdating that one field is
    # exactly what a verifier that has not refreshed for too long looks like.
    from datetime import UTC, datetime, timedelta

    guarded.verifier.anchors._as_of = datetime.now(UTC) - timedelta(
        seconds=guarded.verifier.freshness_seconds + 60
    )

    response = await guarded.resource.get("/read_balance", headers=headers)

    assert response.status_code == 403
    assert guarded.recorder.last[1].reason == "IDENTITY_STALE"
    assert guarded.recorder.executed == []
