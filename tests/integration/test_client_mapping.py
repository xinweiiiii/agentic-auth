"""An MCP client registered at the IdP maps to an agent, or goes through cold start
(feature 011, US3, M4).

Identified is not authorized: a token's ``azp`` names the client, and only an admin's mapping
turns that into an agent, and so a scope. A client nobody mapped gets nothing.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from agentic_auth.models import AuditDecision, Session
from tests.fixtures.chains import KB_SEARCH, ORCHESTRATOR
from tests.fixtures.idp.server import ISSUER

CONTROL_PLANE = "https://authz.test"


@pytest.fixture
def mapping_on(fake_idp, flags, metrics_registry):
    flags(
        verified_consent_enabled=True,
        client_mapping_enabled=True,
        consent_idp_audiences=CONTROL_PLANE,
    )
    return fake_idp


async def _agent_id(client, admin_headers, name: str) -> str:
    agents = (await client.get("/v1/agents?limit=100", headers=admin_headers)).json()["data"]
    return next(a["id"] for a in agents if a["name"] == name)


async def _map(client, admin_headers, agent_id: str, client_id: str):
    return await client.post(
        f"/v1/agents/{agent_id}/clients", headers=admin_headers, json={"client_id": client_id}
    )


async def _consent(client, admin_headers, token: str, **body):
    return await client.post(
        "/v1/consent", headers=admin_headers, json={"subject_token": token, **body}
    )


# -- the routes -----------------------------------------------------------------------------


async def test_a_mapping_is_created_listed_and_soft_removed(
    client, admin_headers, register_chain, mapping_on
) -> None:
    await register_chain()
    agent = await _agent_id(client, admin_headers, ORCHESTRATOR)

    created = await _map(client, admin_headers, agent, "desktop-client")
    assert created.status_code == 201
    body = created.json()
    assert body["agent_id"] == agent
    assert body["issuer"] == ISSUER
    assert body["client_id"] == "desktop-client"
    assert body["created_by"] == "admin"
    assert body["removed_at"] is None

    listed = (await client.get(f"/v1/agents/{agent}/clients", headers=admin_headers)).json()
    assert [m["client_id"] for m in listed["data"]] == ["desktop-client"]

    removed = await client.delete(
        f"/v1/agents/{agent}/clients/desktop-client", headers=admin_headers
    )
    assert removed.status_code == 204
    again = await client.delete(f"/v1/agents/{agent}/clients/desktop-client", headers=admin_headers)
    assert again.status_code == 204  # idempotent

    active = (await client.get(f"/v1/agents/{agent}/clients", headers=admin_headers)).json()
    assert active["data"] == []
    history = (
        await client.get(f"/v1/agents/{agent}/clients?include_removed=true", headers=admin_headers)
    ).json()["data"]
    assert len(history) == 1
    assert history[0]["removed_at"] is not None and history[0]["removed_by"] == "admin"


async def test_remapping_after_removal_is_a_new_row(
    client, admin_headers, register_chain, mapping_on
) -> None:
    await register_chain()
    agent = await _agent_id(client, admin_headers, ORCHESTRATOR)
    await _map(client, admin_headers, agent, "c1")
    await client.delete(f"/v1/agents/{agent}/clients/c1", headers=admin_headers)
    assert (await _map(client, admin_headers, agent, "c1")).status_code == 201

    history = (
        await client.get(f"/v1/agents/{agent}/clients?include_removed=true", headers=admin_headers)
    ).json()["data"]
    assert len(history) == 2
    assert history[0]["removed_at"] is None  # newest first


async def test_one_client_cannot_act_as_two_agents(
    client, admin_headers, register_chain, mapping_on
) -> None:
    await register_chain()
    first = await _agent_id(client, admin_headers, ORCHESTRATOR)
    second = await _agent_id(client, admin_headers, KB_SEARCH)

    assert (await _map(client, admin_headers, first, "shared")).status_code == 201
    conflict = await _map(client, admin_headers, second, "shared")
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "client_already_mapped"
    same_agent = await _map(client, admin_headers, first, "shared")
    assert same_agent.status_code == 409


async def test_one_agent_may_have_many_clients(
    client, admin_headers, register_chain, mapping_on
) -> None:
    await register_chain()
    agent = await _agent_id(client, admin_headers, ORCHESTRATOR)
    for name in ("desktop", "cli", "web"):
        assert (await _map(client, admin_headers, agent, name)).status_code == 201
    page = (await client.get(f"/v1/agents/{agent}/clients?limit=2", headers=admin_headers)).json()
    assert len(page["data"]) == 2 and page["page"]["next_cursor"]
    rest = (
        await client.get(
            f"/v1/agents/{agent}/clients?limit=2&cursor={page['page']['next_cursor']}",
            headers=admin_headers,
        )
    ).json()
    assert len(rest["data"]) == 1
    assert {m["client_id"] for m in page["data"] + rest["data"]} == {"desktop", "cli", "web"}


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"client_id": ""},
        {"client_id": "x" * 256},
        {"client_id": "a b"},
        {"client_id": "c", "issuer": "x"},
    ],
)
async def test_an_invalid_mapping_is_a_validation_error(
    client, admin_headers, register_chain, mapping_on, body
) -> None:
    await register_chain()
    agent = await _agent_id(client, admin_headers, ORCHESTRATOR)
    r = await client.post(f"/v1/agents/{agent}/clients", headers=admin_headers, json=body)
    assert r.status_code == 422


async def test_an_unknown_agent_is_not_found(client, admin_headers, mapping_on) -> None:
    unknown = uuid.uuid4()
    assert (await _map(client, admin_headers, str(unknown), "c")).status_code == 404
    listed = await client.get(f"/v1/agents/{unknown}/clients", headers=admin_headers)
    assert listed.status_code == 404
    removed = await client.delete(f"/v1/agents/{unknown}/clients/c", headers=admin_headers)
    assert removed.status_code == 404


async def test_removing_a_mapping_that_never_existed_is_not_found(
    client, admin_headers, register_chain, mapping_on
) -> None:
    await register_chain()
    agent = await _agent_id(client, admin_headers, ORCHESTRATOR)
    r = await client.delete(f"/v1/agents/{agent}/clients/never", headers=admin_headers)
    assert r.status_code == 404


@pytest.mark.parametrize("bearer", ["consent-only", "wrong"])
async def test_only_an_admin_may_map(
    client, register_chain, admin_headers, mapping_on, flags, bearer
):
    flags(consent_token="consent-only")
    await register_chain()
    agent = await _agent_id(client, admin_headers, ORCHESTRATOR)
    headers = {"Authorization": f"Bearer {bearer}"}
    assert (await _map(client, headers, agent, "c")).status_code == 401
    assert (await client.get(f"/v1/agents/{agent}/clients", headers=headers)).status_code == 401


# -- consent through a mapping ----------------------------------------------------------------


async def test_a_mapped_client_gets_its_agents_scope_without_naming_it(
    client, admin_headers, register_chain, mapping_on, db_session
) -> None:
    await register_chain()
    await _map(client, admin_headers, await _agent_id(client, admin_headers, ORCHESTRATOR), "desk")

    token = mapping_on.mint_access_token(aud=CONTROL_PLANE, azp="desk")
    r = await _consent(client, admin_headers, token)

    assert r.status_code == 201, r.text
    assert r.json()["scope"] == ORCHESTRATOR
    assert r.json()["client_id"] == "desk"
    row = (await db_session.execute(select(Session))).scalar_one()
    assert row.client_id == "desk"


async def test_a_client_id_claim_is_used_when_there_is_no_azp(
    client, admin_headers, register_chain, mapping_on
) -> None:
    await register_chain()
    await _map(client, admin_headers, await _agent_id(client, admin_headers, ORCHESTRATOR), "cli")
    token = mapping_on.mint_access_token(aud=CONTROL_PLANE, azp=None, extra={"client_id": "cli"})
    assert (await _consent(client, admin_headers, token)).status_code == 201


async def test_naming_another_scope_than_the_mapped_agents_is_refused(
    client, admin_headers, register_chain, mapping_on
) -> None:
    await register_chain()
    await _map(client, admin_headers, await _agent_id(client, admin_headers, ORCHESTRATOR), "desk")
    token = mapping_on.mint_access_token(aud=CONTROL_PLANE, azp="desk")
    r = await _consent(client, admin_headers, token, scope=KB_SEARCH)
    assert r.status_code == 422


@pytest.mark.parametrize("azp", ["nobody-mapped-me", None])
async def test_an_unmapped_client_is_identified_but_not_authorized(
    client, admin_headers, register_chain, mapping_on, db_session, metrics_registry, azp
) -> None:
    await register_chain()
    token = mapping_on.mint_access_token(aud=CONTROL_PLANE, azp=azp)
    r = await _consent(client, admin_headers, token, scope=ORCHESTRATOR)

    assert r.status_code == 403
    error = r.json()["error"]
    assert error["code"] == "client_not_authorized"
    assert error["details"]["reason"] == "CLIENT_NOT_AUTHORIZED"
    assert error["details"]["recoverable"] is False
    assert error["details"]["next"] == "cold_start"
    assert error["details"]["client_id"] == azp
    assert "sandbox" not in error["details"]
    assert (await db_session.execute(select(Session))).first() is None
    assert (
        metrics_registry.registry.get_sample_value(
            "agentic_auth_consent_refusals_total", {"reason": "client_not_authorized"}
        )
        == 1
    )


async def test_a_mapped_agent_without_a_pinned_manifest_points_at_its_sandbox(
    client, admin_headers, mapping_on, flags
) -> None:
    """An agent whose manifest was rejected exists but has no compiled scope: mapped, and
    still no authority. With the sandbox on, the refusal names its route."""
    from tests.fixtures.manifests import overbroad_manifest

    flags(sandbox_enabled=True)
    manifest = overbroad_manifest()
    name = manifest["metadata"]["agent"]
    rejected = await client.post(
        "/v1/agents", headers=admin_headers, json={"name": name, "manifest": manifest}
    )
    assert rejected.status_code == 422
    agent = await _agent_id(client, admin_headers, name)
    assert (await _map(client, admin_headers, agent, "new-client")).status_code == 201

    token = mapping_on.mint_access_token(aud=CONTROL_PLANE, azp="new-client")
    r = await _consent(client, admin_headers, token)

    assert r.status_code == 403
    details = r.json()["error"]["details"]
    assert details["reason"] == "CLIENT_NOT_AUTHORIZED"
    assert details["next"] == "cold_start"
    assert details["sandbox"] == f"/v1/agents/{agent}/sandbox"


async def test_a_removed_mapping_authorizes_nothing_new(
    client, admin_headers, register_chain, mapping_on
) -> None:
    await register_chain()
    agent = await _agent_id(client, admin_headers, ORCHESTRATOR)
    await _map(client, admin_headers, agent, "desk")
    await client.delete(f"/v1/agents/{agent}/clients/desk", headers=admin_headers)

    token = mapping_on.mint_access_token(aud=CONTROL_PLANE, azp="desk")
    assert (await _consent(client, admin_headers, token)).status_code == 403


async def test_decisions_in_a_mapped_session_record_the_client(
    client, admin_headers, register_chain, mapping_on, db_session
) -> None:
    from tests.fixtures.hops import hop

    await register_chain()
    await _map(client, admin_headers, await _agent_id(client, admin_headers, ORCHESTRATOR), "desk")
    session = (
        await _consent(
            client, admin_headers, mapping_on.mint_access_token(aud=CONTROL_PLANE, azp="desk")
        )
    ).json()
    await hop(
        client, session["root_grant"], target=f"agent://{KB_SEARCH}", data_class="kb.internal"
    )

    row = (await db_session.execute(select(AuditDecision))).scalars().first()
    assert row.client_id == "desk"
    assert row.principal_source == "verified"
