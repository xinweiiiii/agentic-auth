"""Drive hops through the in-process control plane the way the sidecar and the SDK do.

Decide, then exchange against the recorded decision — since Phase 3 that is the only way a
token is ever issued. The caller and session for each request are read off the token being
presented, exactly as ``agentic_auth.sdk.context.HopContext`` does, so a test cannot accidentally
present one identity while holding another's token.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx

from agentic_auth.schemas.token import GRANT_TYPE, JWT_TOKEN_TYPE
from tests.fixtures.bank import USER, leaf_first


def claims(token: str) -> dict[str, Any]:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


def caller_of(token: str) -> str:
    """Who holds this token: the agent it was issued to, or the human at the root."""
    c = claims(token)
    return c["aud"] if c.get("act") else c["sub"]


async def register_agents(
    client: httpx.AsyncClient, admin_headers: dict[str, str], docs: dict[str, dict[str, Any]]
) -> None:
    for name in leaf_first(docs):
        r = await client.post(
            "/v1/agents", headers=admin_headers, json={"name": name, "manifest": docs[name]}
        )
        assert r.status_code == 201, (name, r.status_code, r.text)


async def consent_session(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    scope: str,
    user_sub: str = USER,
) -> dict[str, Any]:
    r = await client.post(
        "/v1/consent", headers=admin_headers, json={"scope": scope, "user_sub": user_sub}
    )
    assert r.status_code == 201, (r.status_code, r.text)
    return r.json()


async def authorize(
    client: httpx.AsyncClient,
    token: str,
    *,
    target: str,
    data_class: str,
    enforced: bool = True,
    guarantee: str = "full",
) -> httpx.Response:
    c = claims(token)
    return await client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "session_id": c["session_id"],
            "caller": caller_of(token),
            "target": target,
            "data_class": data_class,
            "enforced": enforced,
            # Phase 5. Mandatory with no default on the request, so a test that
            # omitted it would get a 422 rather than a silent claim of full guarantee.
            # These helpers stand in for an in-path enforcement point, which is `full`.
            "guarantee": guarantee,
        },
    )


async def exchange(
    client: httpx.AsyncClient,
    token: str,
    *,
    resource: str,
    scope: str,
    action_id: object | None = None,
    **extra: str,
) -> httpx.Response:
    data = {
        "grant_type": GRANT_TYPE,
        "subject_token": token,
        "subject_token_type": JWT_TOKEN_TYPE,
        "resource": resource,
        "scope": scope,
        **extra,
    }
    if action_id is not None:
        data["action_id"] = str(action_id)
    return await client.post("/v1/token/exchange", data=data)


async def hop(
    client: httpx.AsyncClient, token: str, *, target: str, data_class: str
) -> tuple[dict[str, Any], str | None]:
    """One full hop. Returns ``(decision, narrowed_token)``; the token is ``None`` on a deny."""
    decision = (await authorize(client, token, target=target, data_class=data_class)).json()
    if decision["outcome"] != "allow":
        return decision, None
    r = await exchange(
        client, token, resource=target, scope=data_class, action_id=decision["action_id"]
    )
    assert r.status_code == 200, r.text
    return decision, r.json()["access_token"]


async def run_calls(
    client: httpx.AsyncClient, root_grant: str, calls: list[tuple[str, str, str]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Walk ``calls`` in order, stopping after the first deny.

    Returns ``(decisions, presented_tokens)`` — the token presented at each decided hop.
    Each call's caller is asserted against the token actually held, so a fixture whose call
    plan disagrees with the chain fails loudly instead of testing the wrong thing.
    """
    token = root_grant
    decisions: list[dict[str, Any]] = []
    presented: list[str] = []
    for caller, target, data_class in calls:
        assert caller_of(token) == caller, (
            f"call plan expects {caller}, token held by {caller_of(token)}"
        )
        presented.append(token)
        decision, narrowed = await hop(client, token, target=target, data_class=data_class)
        decisions.append(decision)
        if narrowed is None:
            break
        token = narrowed
    return decisions, presented
