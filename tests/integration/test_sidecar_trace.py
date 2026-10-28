"""The sidecar and SDK record one attributed edge event per call (T042, US3 AS6/AS8)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.sdk import AgenticAuthClient, HopContext, PolicyDenied
from tests.conftest import ADMIN_TOKEN
from tests.fixtures.chains import ORCHESTRATOR, SUMMARIZER

KB_TOOL = "mcp://kb.internal/search"
DENIED = {"X-Agentic-Target": f"agent://{SUMMARIZER}", "X-Agentic-Data-Class": "account.read"}


def events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def rooted(register_chain, consent):
    await register_chain()
    return await consent()


async def test_an_allowed_call_is_attributed_to_the_verified_holder(
    sidecar_stack, rooted, tmp_path
) -> None:
    """Hop 1 is presented by user:alice, but the agent acting is the root grant's holder."""
    path = tmp_path / "events.jsonl"
    sidecar = await sidecar_stack.client(trace_path=str(path))

    r = await sidecar.get("/kb/search", headers=bearer(rooted["root_grant"]))

    assert r.status_code == 200
    [event] = events(path)
    assert event["source"] == "sidecar"
    assert (event["outcome"], event["acting_agent"]) == ("allow", ORCHESTRATOR)
    assert (event["target"], event["kind"], event["reason"]) == (KB_TOOL, "tool", None)


async def test_an_observed_would_be_deny_is_recorded_as_observed(
    sidecar_stack, rooted, tmp_path
) -> None:
    path = tmp_path / "events.jsonl"
    sidecar = await sidecar_stack.client(observe_mode=True, trace_path=str(path))

    await sidecar.get("/bare", headers={**bearer(rooted["root_grant"]), **DENIED})

    [event] = events(path)
    assert (event["outcome"], event["reason"]) == ("observed", "EDGE_NOT_IN_DAG")
    assert (event["acting_agent"], event["target"], event["kind"]) == (
        ORCHESTRATOR,
        f"agent://{SUMMARIZER}",
        "delegation",
    )


async def test_a_call_refused_at_runtime_is_still_an_observed_edge(
    sidecar_stack, rooted, tmp_path
) -> None:
    path = tmp_path / "events.jsonl"
    sidecar = await sidecar_stack.client(trace_path=str(path))

    r = await sidecar.get("/bare", headers={**bearer(rooted["root_grant"]), **DENIED})

    assert r.status_code == 403
    [event] = events(path)
    assert (event["outcome"], event["acting_agent"], event["reason"]) == (
        "deny",
        ORCHESTRATOR,
        "EDGE_NOT_IN_DAG",
    )


async def test_an_unreachable_decision_service_leaves_the_call_unattributed(
    sidecar_stack, rooted, tmp_path
) -> None:
    path = tmp_path / "events.jsonl"
    sidecar = await sidecar_stack.client(trace_path=str(path))
    sidecar_stack.router.pdp_down = True

    await sidecar.get("/kb/search", headers=bearer(rooted["root_grant"]))

    [event] = events(path)
    assert (event["outcome"], event["acting_agent"], event["reason"]) == (
        "blocked_infra",
        None,
        "PDP_UNAVAILABLE",
    )


async def test_a_call_blocked_before_any_decision_is_recorded_locally(
    sidecar_stack, rooted, tmp_path
) -> None:
    path = tmp_path / "events.jsonl"
    sidecar = await sidecar_stack.client(trace_path=str(path))

    await sidecar.get("/nope/thing", headers=bearer(rooted["root_grant"]))

    [event] = events(path)
    assert event == {
        **event,
        "outcome": "blocked_local",
        "acting_agent": None,
        "target": None,
        "kind": None,
        "reason": "UPSTREAM_NOT_MAPPED",
    }


async def test_exactly_one_event_per_call(sidecar_stack, rooted, tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    sidecar = await sidecar_stack.client(trace_path=str(path))
    headers = bearer(rooted["root_grant"])

    await sidecar.get("/kb/search", headers=headers)
    await sidecar.get("/nope", headers=headers)
    await sidecar.get("/bare", headers={**headers, **DENIED})

    assert [e["outcome"] for e in events(path)] == ["allow", "blocked_local", "deny"]


async def test_a_recorder_that_cannot_write_changes_no_response(
    sidecar_stack, rooted, tmp_path
) -> None:
    broken = await sidecar_stack.client(trace_path=str(tmp_path))  # a directory: every write fails
    plain = await sidecar_stack.client()
    headers = bearer(rooted["root_grant"])

    refusals = [await client.get("/nope", headers=headers) for client in (broken, plain)]
    assert refusals[0].status_code == refusals[1].status_code == 403
    assert refusals[0].json() == refusals[1].json()

    allowed = await broken.get("/kb/search", headers=headers)
    assert allowed.status_code == 200
    assert sidecar_stack.recorder.count == 1


async def test_the_sdk_records_the_same_shape(client, rooted, tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    sdk = AgenticAuthClient(
        base_url="http://test", admin_token=ADMIN_TOKEN, client=client, trace_path=str(path)
    )
    ctx = HopContext(session_id=rooted["session_id"], token=rooted["root_grant"])

    await sdk.authorize(ctx, target=KB_TOOL, data_class="kb.public")
    with pytest.raises(PolicyDenied):
        await sdk.authorize(ctx, target=f"agent://{SUMMARIZER}", data_class="account.read")

    allowed, denied = events(path)
    assert {allowed["source"], denied["source"]} == {"sdk"}
    assert (allowed["outcome"], allowed["acting_agent"], allowed["target"]) == (
        "allow",
        ORCHESTRATOR,
        KB_TOOL,
    )
    assert (denied["outcome"], denied["acting_agent"], denied["reason"]) == (
        "deny",
        ORCHESTRATOR,
        "EDGE_NOT_IN_DAG",
    )
