"""Revoking an agent cuts off everything built on it."""

from __future__ import annotations

import uuid

import pytest

from agentic_auth.schemas.authorize import DenyReason
from agentic_auth.sdk import AgenticAuthClient, AgentKey
from tests.conftest import ADMIN_TOKEN
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    READ_BALANCE,
    SUPPORT_AGENT,
    USER,
    bank_docs,
)
from tests.fixtures.hops import authorize, exchange, hop, register_agents


@pytest.fixture
async def enrolled(client, admin_headers, flags, fake_idp, principal_assertion_for):
    flags(taint_enforcement_enabled=False)
    await register_agents(client, admin_headers, bank_docs(widened=True))
    ids = {
        a["name"]: a["id"]
        for a in (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    }
    sdk = AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)
    keys = {}
    for name in (BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT):
        key = AgentKey.generate()
        assert (
            await sdk.enroll(
                ids[name],
                key=key,
                agent_name=name,
                principal_assertion=principal_assertion_for(name),
            )
        )["status"] == "enrolled"
        keys[name] = key
    from types import SimpleNamespace

    return SimpleNamespace(ids=ids, keys=keys, sdk=sdk)


async def revoke(client, admin_headers, agent_id, reason=None):
    return await client.post(
        f"/v1/agents/{agent_id}/revoke",
        headers=admin_headers,
        json={"reason": reason} if reason else {},
    )


async def test_the_next_hop_after_a_mid_chain_revocation_is_refused(
    client, admin_headers, consent, enrolled
) -> None:
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )

    r = await revoke(client, admin_headers, enrolled.ids[BALANCE_AGENT], "compromised")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "revoked" and r.json()["trust_anchor_version"] == 1

    d = (
        await authorize(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    ).json()
    assert d["outcome"] == "deny" and d["reason"] == DenyReason.AGENT_REVOKED.value
    assert d["recoverable"] is False

    rows = (await client.get("/v1/audit/decisions?outcome=deny", headers=admin_headers)).json()[
        "data"
    ]
    assert any(row["deny_reason"] == DenyReason.AGENT_REVOKED.value for row in rows)


async def test_a_cached_allow_is_not_served_after_revocation_and_the_exchange_re_decides(
    client, admin_headers, consent, enrolled
) -> None:
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    early = (await authorize(client, t1, target=READ_BALANCE, data_class="account.read")).json()
    assert early["outcome"] == "allow"

    await revoke(client, admin_headers, enrolled.ids[BALANCE_AGENT])

    # the exchange spending the earlier allow re-decides and refuses
    r = await exchange(
        client, t1, resource=READ_BALANCE, scope="account.read", action_id=early["action_id"]
    )
    assert r.status_code == 403 and r.json()["error"] == "invalid_target"
    # and a fresh authorize (which would have hit the cache) refuses too
    again = (await authorize(client, t1, target=READ_BALANCE, data_class="account.read")).json()
    assert again["reason"] == DenyReason.AGENT_REVOKED.value


async def test_a_chain_not_passing_through_the_revoked_agent_is_unaffected(
    client, admin_headers, consent, enrolled
) -> None:
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    await revoke(client, admin_headers, enrolled.ids[SUPPORT_AGENT])
    d = (
        await authorize(
            client, session["root_grant"], target=KB_SEARCH_TOOL, data_class="kb.public"
        )
    ).json()
    assert d["outcome"] == "allow"
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    assert t1 is not None


async def test_revoke_is_idempotent_and_counted_once(
    client, admin_headers, enrolled, metrics_registry
) -> None:
    first = await revoke(client, admin_headers, enrolled.ids[SUPPORT_AGENT])
    second = await revoke(client, admin_headers, enrolled.ids[SUPPORT_AGENT])
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert metrics_registry.registry.get_sample_value("agentic_auth_revocations_total") == 1


async def test_unknown_and_never_enrolled_agents(client, admin_headers, enrolled) -> None:
    assert (await revoke(client, admin_headers, str(uuid.uuid4()))).status_code == 404
    r = await client.post(
        "/v1/agents",
        headers=admin_headers,
        json={
            "name": "fresh",
            "manifest": __import__(
                "tests.fixtures.manifests", fromlist=["base_manifest"]
            ).base_manifest("fresh"),
        },
    )
    fresh_id = r.json()["agent_id"]
    r = await revoke(client, admin_headers, fresh_id)
    assert r.status_code == 409 and r.json()["error"]["code"] == "not_enrolled"


async def test_revoke_requires_admin(client, enrolled, flags) -> None:
    flags(audit_read_token="reader")
    r = await client.post(
        f"/v1/agents/{enrolled.ids[SUPPORT_AGENT]}/revoke",
        headers={"Authorization": "Bearer reader"},
    )
    assert r.status_code == 401
    assert (
        await client.post(f"/v1/agents/{enrolled.ids[SUPPORT_AGENT]}/revoke")
    ).status_code == 401


async def test_a_revoked_agent_can_never_enroll_again_even_with_a_new_key(
    client, admin_headers, enrolled, principal_assertion_for
) -> None:
    await revoke(client, admin_headers, enrolled.ids[SUPPORT_AGENT])
    from tests.fixtures.identity import agent_keypair, identity_document

    doc = identity_document(
        agent_keypair(SUPPORT_AGENT), principal_assertion=principal_assertion_for(SUPPORT_AGENT)
    )
    r = await client.post(
        f"/v1/agents/{enrolled.ids[SUPPORT_AGENT]}/enroll",
        headers=admin_headers,
        json={"identity_doc": doc},
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "key_revoked"


async def test_a_revoked_key_is_never_re_pinned_by_another_enrollment(
    client, admin_headers, consent, principal_assertion_for, fake_idp, flags
) -> None:
    """Rotation revokes anchor v1; presenting v1's key again later is refused."""
    flags(taint_enforcement_enabled=False)
    await register_agents(client, admin_headers, bank_docs())
    ids = {
        a["name"]: a["id"]
        for a in (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    }
    sdk = AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)
    k1, k2 = AgentKey.generate(), AgentKey.generate()
    assert (
        await sdk.enroll(
            ids[SUPPORT_AGENT],
            key=k1,
            agent_name=SUPPORT_AGENT,
            principal_assertion=principal_assertion_for(SUPPORT_AGENT),
        )
    )["trust_anchor_version"] == 1
    assert (
        await sdk.enroll(
            ids[SUPPORT_AGENT],
            key=k2,
            agent_name=SUPPORT_AGENT,
            principal_assertion=principal_assertion_for(SUPPORT_AGENT),
        )
    )["trust_anchor_version"] == 2
    from agentic_auth.sdk.client import ControlPlaneUnavailable

    with pytest.raises(ControlPlaneUnavailable, match="409"):
        await sdk.enroll(
            ids[SUPPORT_AGENT],
            key=k1,
            agent_name=SUPPORT_AGENT,
            principal_assertion=principal_assertion_for(SUPPORT_AGENT),
        )


async def test_the_identity_read_and_the_revocation_list_show_it(
    client, admin_headers, enrolled
) -> None:
    r = await revoke(client, admin_headers, enrolled.ids[SUPPORT_AGENT], "compromised")
    revoked_at = r.json()["revoked_at"]
    identity = (
        await client.get(
            f"/v1/agents/{enrolled.ids[SUPPORT_AGENT]}/identity", headers=admin_headers
        )
    ).json()
    assert identity["status"] == "revoked" and identity["revoked"] is True
    assert identity["jwks"] is not None  # still readable after revocation
    assert identity["revoked_at"] is not None

    listing = (await client.get("/v1/identity/revocations", headers=admin_headers)).json()
    assert [i["agent"] for i in listing["items"]] == [SUPPORT_AGENT]
    assert listing["items"][0]["trust_anchor_version"] == 1
    assert listing["items"][0]["revoked_at"] == revoked_at
    assert listing["page"]["next_cursor"] is None

    # since= excludes it when set after the revocation
    later = (
        await client.get(
            "/v1/identity/revocations?since=2999-01-01T00:00:00Z", headers=admin_headers
        )
    ).json()
    assert later["items"] == []
    assert (await client.get("/v1/identity/revocations")).status_code == 401
    assert (
        await client.get(
            "/v1/identity/revocations?since=2999-01-01T00:00:00", headers=admin_headers
        )
    ).status_code == 422


async def test_the_revocation_list_pages(client, admin_headers, enrolled) -> None:
    for name in (BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT):
        await revoke(client, admin_headers, enrolled.ids[name])
    page1 = (await client.get("/v1/identity/revocations?limit=2", headers=admin_headers)).json()
    assert len(page1["items"]) == 2 and page1["page"]["next_cursor"]
    page2 = (
        await client.get(
            f"/v1/identity/revocations?limit=2&cursor={page1['page']['next_cursor']}",
            headers=admin_headers,
        )
    ).json()
    assert len(page2["items"]) == 1 and page2["page"]["next_cursor"] is None
    assert {i["agent"] for i in page1["items"]} | {i["agent"] for i in page2["items"]} == {
        BANK_ASSISTANT,
        BALANCE_AGENT,
        SUPPORT_AGENT,
    }


async def test_the_revoked_set_is_rebuilt_from_the_table_after_a_redis_flush(
    client, admin_headers, consent, enrolled, redis_client
) -> None:
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    await revoke(client, admin_headers, enrolled.ids[BALANCE_AGENT])
    await redis_client.flushdb()  # loses the set AND the ready flag
    d = (await authorize(client, t1, target=READ_BALANCE, data_class="account.read")).json()
    assert d["reason"] == DenyReason.AGENT_REVOKED.value  # the table is the source of truth


async def test_delegating_to_a_revoked_agent_is_refused_and_recorded(
    client, admin_headers, consent, enrolled
) -> None:
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    await revoke(client, admin_headers, enrolled.ids[BALANCE_AGENT])
    d = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
    ).json()
    assert d["outcome"] == "deny" and d["reason"] == DenyReason.AGENT_REVOKED.value
    assert d["recorded"] is True
