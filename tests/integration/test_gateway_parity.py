"""The gateway decides exactly what the sidecar decides (FR-002, SC-001).

This is the test that makes "one policy, deployed two ways" checkable. It drives the same
chain through both enforcement points and compares every decision, refusal reason and
narrowed authority.

``guarantee_level`` and the enforcement point are deliberately excluded from the
comparison — they are *expected* to differ, and that is the entire purpose of the field
(contracts/conformance.md §3).
"""

from __future__ import annotations

import pytest

from agentic_auth.sidecar.config import Upstream
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    USER,
    bank_docs,
)
from tests.fixtures.hops import hop, register_agents

SIDECAR_MAP = {
    "/kb": Upstream(url="http://upstream.test", target=KB_SEARCH_TOOL, data_class="kb.internal"),
    "/accounts": Upstream(
        url="http://upstream.test", target=TERMINATE_ACCOUNT, data_class="account.write"
    ),
    "/nowhere": Upstream(
        url="http://upstream.test", target="mcp://kb.internal/absent", data_class="kb.internal"
    ),
}
GATEWAY_TABLE = {(None, prefix): upstream for prefix, upstream in SIDECAR_MAP.items()}


@pytest.fixture
async def support_token(client, admin_headers, consent):
    """A token held by support-agent, three hops in, in an untainted context."""

    async def _setup(**kwargs):
        await register_agents(client, admin_headers, bank_docs(widened=True, **kwargs))
        session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
        _, t1 = await hop(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
        _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
        return t2

    return _setup


async def _raw_get(test_client, path: str, token: str) -> dict:
    """Call the ASGI app with an unnormalised path, bypassing httpx's URL resolution."""
    import json as _json

    received: dict = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            received["status"] = message["status"]
        elif message["type"] == "http.response.body":
            received.setdefault("body", b"")
            received["body"] += message.get("body", b"")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"test"), (b"authorization", f"Bearer {token}".encode())],
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
    }
    await test_client._transport.app(scope, receive, send)
    body = received.get("body", b"")
    parsed = _json.loads(body) if body else {}
    error = parsed.get("error", {})
    return {
        "status": received.get("status"),
        "code": error.get("code"),
        "reason": (error.get("details") or {}).get("reason"),
    }


def _envelope(response) -> dict:
    """The parts of a refusal both enforcement points must agree on."""
    body = response.json()
    error = body.get("error", {})
    details = error.get("details", {})
    return {
        "status": response.status_code,
        "code": error.get("code"),
        "reason": details.get("reason"),
        "recoverable": details.get("recoverable"),
    }


async def test_an_allowed_call_agrees(sidecar_stack, gateway_stack, support_token) -> None:
    token = await support_token()
    headers = {"Authorization": f"Bearer {token}"}

    sidecar = await sidecar_stack.client(upstream_map=SIDECAR_MAP)
    gateway = await gateway_stack.client(route_table=GATEWAY_TABLE)

    via_sidecar = await sidecar.get("/kb/search?q=refund", headers=headers)
    # A fresh token: the first call spends its decision, and the point of the comparison
    # is the decision, not the replay guard.
    token2 = await support_token()
    via_gateway = await gateway.get(
        "/kb/search?q=refund", headers={"Authorization": f"Bearer {token2}"}
    )

    assert via_sidecar.status_code == 200
    assert via_gateway.status_code == via_sidecar.status_code


async def test_a_tainted_privileged_call_is_refused_identically(
    sidecar_stack, gateway_stack, support_token
) -> None:
    """The PRD §2.2 shape: read the untrusted KB, then attempt terminate_account. Both
    enforcement points must refuse with TAINTED_INTO_PRIVILEGED, not merely refuse."""
    params = {"account_id": "acc-42"}

    token_a = await support_token()
    sidecar = await sidecar_stack.client(upstream_map=SIDECAR_MAP)
    ha = {"Authorization": f"Bearer {token_a}"}
    await sidecar.get("/kb/search?q=refund", headers=ha)
    sidecar_refusal = await sidecar.post("/accounts/terminate", headers=ha, json=params)

    token_b = await support_token()
    gateway = await gateway_stack.client(route_table=GATEWAY_TABLE)
    hb = {"Authorization": f"Bearer {token_b}"}
    await gateway.get("/kb/search?q=refund", headers=hb)
    gateway_refusal = await gateway.post("/accounts/terminate", headers=hb, json=params)

    assert _envelope(sidecar_refusal)["reason"] == "TAINTED_INTO_PRIVILEGED"
    assert _envelope(gateway_refusal) == _envelope(sidecar_refusal)


async def test_an_undeclared_target_is_refused_identically(
    sidecar_stack, gateway_stack, support_token
) -> None:
    token_a = await support_token()
    sidecar = await sidecar_stack.client(upstream_map=SIDECAR_MAP)
    a = await sidecar.get("/nowhere/x", headers={"Authorization": f"Bearer {token_a}"})

    token_b = await support_token()
    gateway = await gateway_stack.client(route_table=GATEWAY_TABLE)
    b = await gateway.get("/nowhere/x", headers={"Authorization": f"Bearer {token_b}"})

    assert _envelope(a)["reason"] == "OUT_OF_SCOPE"
    assert _envelope(b) == _envelope(a)


async def test_an_unmapped_path_is_refused_identically(
    sidecar_stack, gateway_stack, support_token
) -> None:
    sidecar = await sidecar_stack.client(upstream_map=SIDECAR_MAP)
    gateway = await gateway_stack.client(route_table=GATEWAY_TABLE)

    ha = {"Authorization": f"Bearer {await support_token()}"}
    hb = {"Authorization": f"Bearer {await support_token()}"}
    a = await sidecar.get("/unmapped/x", headers=ha)
    b = await gateway.get("/unmapped/x", headers=hb)

    assert _envelope(a) == _envelope(b)


async def test_a_missing_bearer_is_refused_identically(sidecar_stack, gateway_stack) -> None:
    sidecar = await sidecar_stack.client(upstream_map=SIDECAR_MAP)
    gateway = await gateway_stack.client(route_table=GATEWAY_TABLE)

    a = await sidecar.get("/kb/search")
    b = await gateway.get("/kb/search")

    assert a.status_code == 401
    assert _envelope(a) == _envelope(b)


async def test_traversal_is_refused_identically(
    sidecar_stack, gateway_stack, support_token
) -> None:
    """`/kb/../accounts/terminate` would be authorized as the `/kb` target and delivered
    to `/accounts` — the matched prefix would be a lie. Both points must refuse.

    Driven against the ASGI apps directly, because httpx resolves dot segments
    client-side per RFC 3986: a request made through the test client never carries one,
    so routing this through it would silently test nothing.
    """
    token = await support_token()

    sidecar = await sidecar_stack.client(upstream_map=SIDECAR_MAP)
    gateway = await gateway_stack.client(route_table=GATEWAY_TABLE)

    a = await _raw_get(sidecar, "/kb/../accounts/terminate", token)
    b = await _raw_get(gateway, "/kb/../accounts/terminate", token)

    assert a["status"] == 403, a
    assert a == b


async def test_the_audit_row_records_the_guarantee_level(
    gateway_stack, support_token, client, admin_headers
) -> None:
    """The one thing that SHOULD differ is recorded, not inferred (FR-017)."""
    token = await support_token()
    gateway = await gateway_stack.client(route_table=GATEWAY_TABLE)
    await gateway.get("/kb/search?q=refund", headers={"Authorization": f"Bearer {token}"})

    page = await client.get("/v1/audit/decisions", headers=admin_headers)
    rows = page.json()["data"]

    assert rows, "the gateway's decision should have been recorded"
    assert all(row["guarantee_level"] == "full" for row in rows)
