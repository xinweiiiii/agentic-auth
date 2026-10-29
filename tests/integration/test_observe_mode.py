"""See what would be blocked, before blocking it.

The point of the mode is that the report is a *prediction*: the same call, in the
same policy, produces the same decision either way — only the consequence differs.
"""

from __future__ import annotations

import base64
import json

from tests.fixtures.chains import SUMMARIZER

USER = "user:alice"

# A hop the policy refuses: orchestrator -> summarizer skips the declared kb-search edge.
DENIED = {
    "X-Agentic-Target": f"agent://{SUMMARIZER}",
    "X-Agentic-Data-Class": "account.read",
}


def claims(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


async def _rooted(register_chain, consent):
    await register_chain()
    return await consent()


async def _decisions(client, admin_headers, **params):
    r = await client.get("/v1/decisions", headers=admin_headers, params=params)
    assert r.status_code == 200, r.text
    return r.json()["data"]


async def test_observe_mode_lets_a_denied_call_through(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client(observe_mode=True)

    r = await sidecar.get(
        "/bare", headers={"Authorization": f"Bearer {session['root_grant']}", **DENIED}
    )

    assert r.status_code == 200
    assert sidecar_stack.recorder.count == 1


async def test_an_observed_call_carries_its_original_token(
    sidecar_stack, register_chain, consent
) -> None:
    """No exchange happened — the hop was denied, so there is no narrowed token to send."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client(observe_mode=True)

    await sidecar.get(
        "/bare", headers={"Authorization": f"Bearer {session['root_grant']}", **DENIED}
    )

    assert sidecar_stack.recorder.last["token"] == session["root_grant"]


async def test_the_deny_is_recorded_as_unenforced(
    sidecar_stack, register_chain, consent, client, admin_headers
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client(observe_mode=True)

    await sidecar.get(
        "/bare", headers={"Authorization": f"Bearer {session['root_grant']}", **DENIED}
    )

    rows = await _decisions(client, admin_headers, session_id=session["session_id"])
    assert len(rows) == 1
    assert rows[0]["outcome"] == "deny"
    assert rows[0]["deny_reason"] == "EDGE_NOT_IN_DAG"
    assert rows[0]["enforced"] is False


async def test_the_same_call_is_blocked_with_enforcement_on(
    sidecar_stack, register_chain, consent, client, admin_headers
) -> None:
    """The report predicted exactly this."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client(observe_mode=False)

    r = await sidecar.get(
        "/bare", headers={"Authorization": f"Bearer {session['root_grant']}", **DENIED}
    )

    assert r.status_code == 403
    assert sidecar_stack.recorder.count == 0

    rows = await _decisions(client, admin_headers, session_id=session["session_id"])
    assert rows[0]["deny_reason"] == "EDGE_NOT_IN_DAG"  # same reason
    assert rows[0]["enforced"] is True  # different consequence


async def test_allows_behave_identically_in_both_modes(
    sidecar_stack, register_chain, consent, client, admin_headers
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client(observe_mode=True)

    r = await sidecar.get(
        "/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )

    assert r.status_code == 200
    # Still narrowed: observe mode weakens denials, never allows.
    arrived = sidecar_stack.recorder.last["token"]
    assert arrived != session["root_grant"]
    assert claims(arrived)["aud"] == "mcp://kb.internal/search"

    rows = await _decisions(client, admin_headers, session_id=session["session_id"])
    assert all(row["enforced"] is True for row in rows)


async def test_repeated_denials_are_recorded_individually(
    sidecar_stack, register_chain, consent, client, admin_headers
) -> None:
    """The report must reflect real frequency, not a single sample."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client(observe_mode=True)

    for _ in range(3):
        await sidecar.get(
            "/bare", headers={"Authorization": f"Bearer {session['root_grant']}", **DENIED}
        )

    rows = await _decisions(client, admin_headers, session_id=session["session_id"], outcome="deny")
    assert len(rows) == 3


async def test_the_report_filters_to_would_be_denials(
    sidecar_stack, register_chain, consent, client, admin_headers
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client(observe_mode=True)

    await sidecar.get("/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"})
    await sidecar.get(
        "/bare", headers={"Authorization": f"Bearer {session['root_grant']}", **DENIED}
    )

    report = await _decisions(client, admin_headers, outcome="deny", enforced=False)
    assert len(report) == 1
    assert report[0]["target"] == f"agent://{SUMMARIZER}"
    assert report[0]["deny_reason"] == "EDGE_NOT_IN_DAG"


async def test_the_report_requires_admin_auth(client) -> None:
    r = await client.get("/v1/decisions")
    assert r.status_code == 401


async def test_the_report_is_paginated(
    sidecar_stack, register_chain, consent, client, admin_headers
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client(observe_mode=True)
    for _ in range(3):
        await sidecar.get(
            "/bare", headers={"Authorization": f"Bearer {session['root_grant']}", **DENIED}
        )

    first = await client.get("/v1/decisions", headers=admin_headers, params={"limit": 2})
    body = first.json()
    assert len(body["data"]) == 2
    assert body["page"]["next_cursor"]

    second = await client.get(
        "/v1/decisions",
        headers=admin_headers,
        params={"limit": 2, "cursor": body["page"]["next_cursor"]},
    )
    ids = {r["id"] for r in body["data"]} | {r["id"] for r in second.json()["data"]}
    assert len(ids) == 3  # no row dropped or repeated across the page boundary
