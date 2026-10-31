"""Sandboxed observation (US6; FR-032, FR-033; SC-013, SC-015).

Two properties: a run records everything and performs nothing, and it ends when the
deadline says so whether or not the agent stopped.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from agentic_auth.models.sandbox_run import STATUS_DEADLINE_EXCEEDED, STATUS_RUNNING
from agentic_auth.repositories import sandbox_runs as runs_repo
from tests.fixtures.mock_tools.server import build_mock_tools

KB = "mcp://kb.internal/search"
TERMINATE = "mcp://accounts.internal/terminate_account"


@pytest.fixture
async def enabled(flags):
    flags(sandbox_enabled=True)


@pytest.fixture
async def agent(client, admin_headers):
    """An agent with NO manifest — the whole premise of cold start."""
    response = await client.post(
        "/v1/agents", headers=admin_headers, json={"name": "cold-start-agent"}
    )
    assert response.status_code in (201, 409), response.text
    listing = (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    return next(a for a in listing if a["name"] == "cold-start-agent")


async def _age_past_deadline(db_session, run_id: str) -> None:
    """Simulate elapsed time by moving the whole run into the past.

    Moving only ``deadline_at`` back would violate ``deadline_at > started_at`` — the
    constraint is right, and a test that worked around it would be asserting against a
    state the database cannot hold.
    """
    run = await runs_repo.get(db_session, uuid.UUID(run_id))
    assert run is not None
    now = datetime.now(UTC)
    run.started_at = now - timedelta(seconds=30)
    run.deadline_at = now - timedelta(seconds=1)
    await db_session.commit()


async def _start(client, admin_headers, agent, **body):
    return await client.post(
        f"/v1/agents/{agent['id']}/sandbox",
        headers=admin_headers,
        json={"scope": "observe-only", **body},
    )


# -- the run records and performs nothing (FR-032, SC-015) ----------------------------


async def test_a_run_opens_against_an_agent_with_no_manifest(
    client, admin_headers, enabled, agent
) -> None:
    response = await _start(client, admin_headers, agent)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == STATUS_RUNNING
    assert body["ended_at"] is None


async def test_the_mock_tools_record_every_attempt_and_perform_nothing(enabled) -> None:
    """The sandbox's safety claim, stated as a property of the tools themselves rather
    than as a hope about isolation (research.md R11)."""
    app, recorder = build_mock_tools([KB, TERMINATE])

    import httpx
    from httpx import ASGITransport

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://tools"
    ) as tools:
        await tools.post("/search", json={"q": "refund"})
        destructive = await tools.post("/terminate_account", json={"account_id": "acc-42"})

    assert destructive.status_code == 200, "every attempt is ALLOWED, and recorded"
    assert recorder.tools == [KB, TERMINATE]
    assert recorder.performed == [], "nothing real may happen in a sandbox"


async def test_a_tool_not_listed_is_unreachable(enabled) -> None:
    """What bounds the risk of observing an unknown agent: the route table, not a
    promise about the network."""
    app, _ = build_mock_tools([KB])

    import httpx
    from httpx import ASGITransport

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://tools"
    ) as tools:
        response = await tools.post("/terminate_account", json={})

    assert response.status_code == 404


# -- one run at a time (spec story 6, the 409) ------------------------------------------


async def test_a_second_concurrent_run_is_refused(client, admin_headers, enabled, agent) -> None:
    """Two traces racing to become one proposal is a correctness problem — you would not
    know which observation the manifest came from."""
    first = await _start(client, admin_headers, agent)
    second = await _start(client, admin_headers, agent)

    assert first.status_code == 201
    assert second.status_code == 409


# -- the deadline ends it (FR-033) --------------------------------------------------------


async def test_the_deadline_ends_a_run_whose_agent_never_stopped(
    client, admin_headers, enabled, agent, db_session
) -> None:
    started = (await _start(client, admin_headers, agent, deadline_seconds=10)).json()

    await _age_past_deadline(db_session, started["id"])

    read = await client.get(
        f"/v1/agents/{agent['id']}/sandbox/{started['id']}", headers=admin_headers
    )

    assert read.json()["status"] == STATUS_DEADLINE_EXCEEDED
    assert read.json()["ended_at"] is not None


async def test_an_expired_run_frees_the_agent_for_another(
    client, admin_headers, enabled, agent, db_session
) -> None:
    started = (await _start(client, admin_headers, agent, deadline_seconds=10)).json()
    await _age_past_deadline(db_session, started["id"])
    await client.get(f"/v1/agents/{agent['id']}/sandbox/{started['id']}", headers=admin_headers)

    again = await _start(client, admin_headers, agent)

    assert again.status_code == 201


async def test_a_deadline_outside_the_bounds_is_refused(
    client, admin_headers, enabled, agent
) -> None:
    too_short = await _start(client, admin_headers, agent, deadline_seconds=1)
    too_long = await _start(client, admin_headers, agent, deadline_seconds=99_999)

    assert too_short.status_code == 422
    assert too_long.status_code == 422


# -- listing and reading -------------------------------------------------------------------


async def test_runs_are_listed_newest_first(
    client, admin_headers, enabled, agent, db_session
) -> None:
    first = (await _start(client, admin_headers, agent)).json()
    await _age_past_deadline(db_session, first["id"])
    await client.get(f"/v1/agents/{agent['id']}/sandbox/{first['id']}", headers=admin_headers)
    second = (await _start(client, admin_headers, agent)).json()

    listing = await client.get(f"/v1/agents/{agent['id']}/sandbox", headers=admin_headers)

    ids = [r["id"] for r in listing.json()["data"]]
    assert ids[0] == second["id"]
    assert set(ids) == {first["id"], second["id"]}


async def test_an_unknown_run_is_not_found(client, admin_headers, enabled, agent) -> None:
    response = await client.get(
        f"/v1/agents/{agent['id']}/sandbox/{uuid.uuid4()}", headers=admin_headers
    )

    assert response.status_code == 404


# -- the flag (research.md R15) ---------------------------------------------------------------


async def test_the_routes_are_absent_when_the_sandbox_is_disabled(
    client, admin_headers, flags, agent
) -> None:
    flags(sandbox_enabled=False)

    response = await _start(client, admin_headers, agent)

    assert response.status_code == 404


async def test_the_routes_require_admin(client, enabled, agent) -> None:
    response = await client.post(
        f"/v1/agents/{agent['id']}/sandbox", json={"scope": "observe-only"}
    )

    assert response.status_code == 401
