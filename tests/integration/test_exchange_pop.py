"""Proof of possession at the exchange."""

from __future__ import annotations

import pytest

from agentic_auth.schemas.authorize import DenyReason
from tests.conftest import ADMIN_TOKEN
from tests.fixtures.bank import BALANCE_AGENT, BANK_ASSISTANT, READ_BALANCE, USER, bank_docs
from tests.fixtures.hops import authorize, exchange, register_agents
from tests.fixtures.identity import actor_token, agent_keypair, identity_document, sign_challenge


@pytest.fixture
async def enrolled_balance_agent(
    client, admin_headers, consent, flags, fake_idp, principal_assertion_for
):
    """The bank chain registered; balance-agent enrolled with a key we hold; identity on."""
    await register_agents(client, admin_headers, bank_docs())
    agents = {
        a["name"]: a["id"]
        for a in (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    }
    key = agent_keypair(BALANCE_AGENT)
    doc = identity_document(key, principal_assertion=principal_assertion_for(BALANCE_AGENT))
    challenge = (
        await client.post(
            f"/v1/agents/{agents[BALANCE_AGENT]}/enroll",
            headers=admin_headers,
            json={"identity_doc": doc},
        )
    ).json()
    done = await client.post(
        f"/v1/agents/{agents[BALANCE_AGENT]}/enroll/complete",
        headers=admin_headers,
        json={
            "challenge_id": challenge["challenge_id"],
            "signed_response": sign_challenge(key, challenge["nonce"]),
        },
    )
    assert done.json()["status"] == "enrolled", done.text
    flags(identity_required=True)
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    return key, session


async def _balance_token(client, session):
    """bank-assistant (root, NOT enrolled) delegating to balance-agent."""
    return session["root_grant"]


async def test_a_valid_actor_token_mints(client, enrolled_balance_agent, flags) -> None:
    key, session = enrolled_balance_agent
    # hop 1: bank-assistant is not enrolled -> with identity on it is refused. So enroll it too? No:
    # this test exercises balance-agent; get its token with identity OFF, then turn it on.
    flags(identity_required=False)
    d = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
    ).json()
    r = await exchange(
        client,
        session["root_grant"],
        resource=f"agent://{BALANCE_AGENT}",
        scope="account.read",
        action_id=d["action_id"],
    )
    t1 = r.json()["access_token"]
    flags(identity_required=True)

    d = (await authorize(client, t1, target=READ_BALANCE, data_class="account.read")).json()
    assert d["outcome"] == "allow"
    r = await exchange(
        client,
        t1,
        resource=READ_BALANCE,
        scope="account.read",
        action_id=d["action_id"],
        actor_token=actor_token(key, t1),
        actor_token_type="urn:ietf:params:oauth:token-type:jwt",
    )
    assert r.status_code == 200, r.text


async def _t1(client, session, flags):
    flags(identity_required=False)
    d = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
    ).json()
    r = await exchange(
        client,
        session["root_grant"],
        resource=f"agent://{BALANCE_AGENT}",
        scope="account.read",
        action_id=d["action_id"],
    )
    flags(identity_required=True)
    return r.json()["access_token"]


async def _decided(client, t1):
    d = (await authorize(client, t1, target=READ_BALANCE, data_class="account.read")).json()
    assert d["outcome"] == "allow"
    return d["action_id"]


async def test_a_missing_actor_token_is_refused_with_the_fix(
    client, enrolled_balance_agent, flags
) -> None:
    key, session = enrolled_balance_agent
    t1 = await _t1(client, session, flags)
    action_id = await _decided(client, t1)
    r = await exchange(client, t1, resource=READ_BALANCE, scope="account.read", action_id=action_id)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"
    assert "actor_token is required" in r.json()["error_description"]


async def test_another_agents_key_is_refused(client, enrolled_balance_agent, flags) -> None:
    key, session = enrolled_balance_agent
    t1 = await _t1(client, session, flags)
    action_id = await _decided(client, t1)
    r = await exchange(
        client,
        t1,
        resource=READ_BALANCE,
        scope="account.read",
        action_id=action_id,
        actor_token=actor_token(key, t1, bad=True),
        actor_token_type="urn:ietf:params:oauth:token-type:jwt",
    )
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


async def test_a_wrong_subject_hash_is_refused(client, enrolled_balance_agent, flags) -> None:
    key, session = enrolled_balance_agent
    t1 = await _t1(client, session, flags)
    action_id = await _decided(client, t1)
    r = await exchange(
        client,
        t1,
        resource=READ_BALANCE,
        scope="account.read",
        action_id=action_id,
        actor_token=actor_token(key, t1, bad_hash=True),
        actor_token_type="urn:ietf:params:oauth:token-type:jwt",
    )
    assert r.status_code == 400
    assert "hash" in r.json()["error_description"]


async def test_an_actor_token_for_a_different_agent_is_refused(
    client, enrolled_balance_agent, flags
) -> None:
    key, session = enrolled_balance_agent
    t1 = await _t1(client, session, flags)
    action_id = await _decided(client, t1)
    r = await exchange(
        client,
        t1,
        resource=READ_BALANCE,
        scope="account.read",
        action_id=action_id,
        actor_token=actor_token(key, t1, sub="agent://support-agent"),
        actor_token_type="urn:ietf:params:oauth:token-type:jwt",
    )
    assert r.status_code == 400
    assert "different agent" in r.json()["error_description"]


async def test_a_never_enrolled_holder_is_refused_and_recorded(
    client, enrolled_balance_agent, flags
) -> None:
    """bank-assistant (the root) never enrolled: with identity on, its hop is AGENT_NOT_ENROLLED."""
    _, session = enrolled_balance_agent
    d = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
    ).json()
    assert d["outcome"] == "allow"  # authorize still decides; the exchange enforces possession
    r = await exchange(
        client,
        session["root_grant"],
        resource=f"agent://{BALANCE_AGENT}",
        scope="account.read",
        action_id=d["action_id"],
    )
    assert r.status_code == 403
    assert r.json()["error"] == "invalid_target"
    rows = (
        await client.get(
            "/v1/audit/decisions?outcome=deny", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
        )
    ).json()["data"]
    assert any(row["deny_reason"] == DenyReason.AGENT_NOT_ENROLLED.value for row in rows)


async def test_with_the_flag_off_no_actor_token_is_needed(
    client, enrolled_balance_agent, flags
) -> None:
    _, session = enrolled_balance_agent
    flags(identity_required=False)
    d = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
    ).json()
    r = await exchange(
        client,
        session["root_grant"],
        resource=f"agent://{BALANCE_AGENT}",
        scope="account.read",
        action_id=d["action_id"],
    )
    assert r.status_code == 200
