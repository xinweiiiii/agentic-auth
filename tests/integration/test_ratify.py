"""A human makes the proposal real, or it never becomes anything (US6; SC-014).

The property this file exists for: **a proposal governs nothing until someone ratifies
it** (FR-036, FR-037). Everything else here — editing, double-ratification, version
one — hangs off that.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from agentic_auth.repositories import sandbox_runs as runs_repo
from agentic_auth.services import policy_loader

AGENT = "cold-start-agent"
KB = "mcp://kb.internal/search"


@pytest.fixture
async def enabled(flags):
    flags(sandbox_enabled=True)


@pytest.fixture
async def agent(client, admin_headers):
    await client.post("/v1/agents", headers=admin_headers, json={"name": AGENT})
    listing = (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    return next(a for a in listing if a["name"] == AGENT)


async def _completed_run(client, admin_headers, agent, db_session, *, trace=None):
    """A run that has ended, so a proposal can be derived from it."""
    started = (
        await client.post(
            f"/v1/agents/{agent['id']}/sandbox",
            headers=admin_headers,
            json={"scope": "observe-only"},
        )
    ).json()
    run = await runs_repo.get(db_session, uuid.UUID(started["id"]))
    assert run is not None
    now = datetime.now(UTC)
    run.started_at = now - timedelta(seconds=30)
    run.deadline_at = now - timedelta(seconds=1)
    if trace is not None:
        run.trace = trace
    await db_session.commit()
    await client.get(f"/v1/agents/{agent['id']}/sandbox/{started['id']}", headers=admin_headers)
    return started["id"]


def _trace_with(agent_name: str, tool: str) -> dict:
    now = datetime.now(UTC).isoformat()
    return {
        "schema_version": 1,
        "run": {
            "started_at": now,
            "finished_at": now,
            "command": None,
            "event_files": [],
            "exit_code": 0,
        },
        "edges": [
            {
                "from": agent_name,
                "to": tool,
                "kind": "tool",
                "count": 1,
                "outcomes": {"allow": 1, "deny": 0, "observed": 0},
            }
        ],
        "unattributed": {"count": 0, "by_reason": {}},
        "recorder_errors": 0,
        "events_total": 1,
    }


# -- the proposal is inert (FR-036, SC-014) --------------------------------------------


async def test_a_proposal_is_derived_from_a_completed_run(
    client, admin_headers, enabled, agent, db_session
) -> None:
    await _completed_run(client, admin_headers, agent, db_session, trace=_trace_with(AGENT, KB))

    proposal = await client.get(
        f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers
    )

    assert proposal.status_code == 200, proposal.text
    body = proposal.json()
    assert body["status"] == "proposed"
    assert [t["ref"] for t in body["doc"]["spec"]["tools"]] == [KB]


async def test_the_proposal_governs_nothing_before_ratification(
    client, admin_headers, enabled, agent, db_session
) -> None:
    """The property that matters. A proposal is never compiled, so there is no policy
    version to pin and no session can exist against it."""
    await _completed_run(client, admin_headers, agent, db_session, trace=_trace_with(AGENT, KB))
    await client.get(f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers)

    consent = await client.post(
        "/v1/consent", headers=admin_headers, json={"scope": AGENT, "user_sub": "user:alice"}
    )

    assert consent.status_code == 404
    assert await policy_loader.latest_version(db_session, AGENT) is None


async def test_an_empty_run_is_marked_rather_than_looking_complete(
    client, admin_headers, enabled, agent, db_session
) -> None:
    await _completed_run(client, admin_headers, agent, db_session)

    proposal = (
        await client.get(f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers)
    ).json()

    assert proposal["covers_no_behaviour"] is True


async def test_reading_the_proposal_twice_returns_the_same_one(
    client, admin_headers, enabled, agent, db_session
) -> None:
    """One proposal per run is a database fact. Re-deriving would produce a second
    candidate from the same evidence, and nobody could say which was ratified."""
    await _completed_run(client, admin_headers, agent, db_session, trace=_trace_with(AGENT, KB))

    first = (
        await client.get(f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers)
    ).json()
    second = (
        await client.get(f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers)
    ).json()

    assert first["manifest_id"] == second["manifest_id"]


# -- ratification (FR-037, FR-038) --------------------------------------------------------


async def test_ratification_pins_version_one(
    client, admin_headers, enabled, agent, db_session
) -> None:
    run_id = await _completed_run(
        client, admin_headers, agent, db_session, trace=_trace_with(AGENT, KB)
    )
    await client.get(f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers)

    ratified = await client.post(
        f"/v1/agents/{agent['id']}/proposed-manifest/ratify",
        headers=admin_headers,
        json={"run_id": run_id},
    )

    assert ratified.status_code == 201, ratified.text
    body = ratified.json()
    assert body["version"] == 1
    assert body["status"] == "reconciled"
    assert body["ratified_by"] == "admin"
    assert body["ratified_at"] is not None


async def test_a_proposal_is_ratifiable_once(
    client, admin_headers, enabled, agent, db_session
) -> None:
    run_id = await _completed_run(
        client, admin_headers, agent, db_session, trace=_trace_with(AGENT, KB)
    )
    await client.get(f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers)

    first = await client.post(
        f"/v1/agents/{agent['id']}/proposed-manifest/ratify",
        headers=admin_headers,
        json={"run_id": run_id},
    )
    second = await client.post(
        f"/v1/agents/{agent['id']}/proposed-manifest/ratify",
        headers=admin_headers,
        json={"run_id": run_id},
    )

    assert first.status_code == 201
    assert second.status_code == 409


async def test_ratifying_an_unknown_run_is_not_found(client, admin_headers, enabled, agent) -> None:
    response = await client.post(
        f"/v1/agents/{agent['id']}/proposed-manifest/ratify",
        headers=admin_headers,
        json={"run_id": str(uuid.uuid4())},
    )

    assert response.status_code == 404


# -- editing before ratifying (FR-039) -----------------------------------------------------


async def test_an_edited_document_is_what_gets_pinned(
    client, admin_headers, enabled, agent, db_session
) -> None:
    """What the administrator approved, not what was proposed. A human knows things the
    run did not show."""
    run_id = await _completed_run(
        client, admin_headers, agent, db_session, trace=_trace_with(AGENT, KB)
    )
    proposal = (
        await client.get(f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers)
    ).json()

    edited = dict(proposal["doc"])
    edited["spec"] = dict(edited["spec"])
    edited["spec"]["hop_budget"] = 4

    ratified = await client.post(
        f"/v1/agents/{agent['id']}/proposed-manifest/ratify",
        headers=admin_headers,
        json={"run_id": run_id, "doc": edited},
    )
    assert ratified.status_code == 201, ratified.text

    from agentic_auth.repositories import manifests as manifests_repo

    row = await manifests_repo.get_latest(db_session, uuid.UUID(agent["id"]))
    assert row is not None
    assert row.doc["spec"]["hop_budget"] == 4


async def test_provenance_survives_an_edit(
    client, admin_headers, enabled, agent, db_session
) -> None:
    """The record of which entries were observed must outlive ratification, or nobody
    can later tell evidence from a person's guess."""
    run_id = await _completed_run(
        client, admin_headers, agent, db_session, trace=_trace_with(AGENT, KB)
    )
    proposal = (
        await client.get(f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers)
    ).json()

    edited = dict(proposal["doc"])
    edited.pop("x-proposal", None)  # an edit that tries to erase the provenance
    await client.post(
        f"/v1/agents/{agent['id']}/proposed-manifest/ratify",
        headers=admin_headers,
        json={"run_id": run_id, "doc": edited},
    )

    from agentic_auth.repositories import manifests as manifests_repo

    row = await manifests_repo.get_latest(db_session, uuid.UUID(agent["id"]))
    assert row is not None
    assert row.doc["x-proposal"]["observed"]["tools"] == [KB]


async def test_a_document_for_another_agent_is_refused(
    client, admin_headers, enabled, agent, db_session
) -> None:
    """Editing is allowed; substituting is not."""
    run_id = await _completed_run(
        client, admin_headers, agent, db_session, trace=_trace_with(AGENT, KB)
    )
    proposal = (
        await client.get(f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers)
    ).json()

    impostor = dict(proposal["doc"])
    impostor["metadata"] = {"agent": "someone-else"}

    response = await client.post(
        f"/v1/agents/{agent['id']}/proposed-manifest/ratify",
        headers=admin_headers,
        json={"run_id": run_id, "doc": impostor},
    )

    assert response.status_code == 403


# -- the flag ---------------------------------------------------------------------------------


async def test_the_proposal_routes_are_absent_when_disabled(
    client, admin_headers, flags, agent
) -> None:
    flags(sandbox_enabled=False)

    response = await client.get(
        f"/v1/agents/{agent['id']}/proposed-manifest", headers=admin_headers
    )

    assert response.status_code == 404
