"""The sidecar swaps the token and forwards.

The upstream fixture records what it actually received, so these tests assert the
narrowed token arrived and the presented one did not.
"""

from __future__ import annotations

import base64
import json

from tests.fixtures.chains import KB_SEARCH

USER = "user:alice"


def claims(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


async def _rooted(register_chain, consent):
    await register_chain()
    return await consent()


async def test_the_narrowed_token_reaches_the_upstream_not_the_presented_one(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get(
        "/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )

    assert r.status_code == 200, r.text
    assert sidecar_stack.recorder.count == 1

    arrived = sidecar_stack.recorder.last["token"]
    assert arrived != session["root_grant"]

    c = claims(arrived)
    assert c["aud"] == "mcp://kb.internal/search"  # narrowed to exactly this target
    assert c["scope"] == "kb.public"
    assert c["sub"] == USER
    assert c["hop"] == claims(session["root_grant"])["hop"] + 1


async def test_the_upstream_path_and_query_are_preserved(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    await sidecar.get(
        "/kb/search?q=hello&n=2", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )

    received = sidecar_stack.recorder.last
    assert received["path"] == "/search"
    assert "q=hello" in received["query"]


async def test_a_request_body_is_forwarded(sidecar_stack, register_chain, consent) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    await sidecar.post(
        "/kb/search",
        headers={"Authorization": f"Bearer {session['root_grant']}"},
        json={"query": "anything"},
    )

    assert json.loads(sidecar_stack.recorder.last["body"]) == {"query": "anything"}


async def test_a_delegation_hop_is_narrowed_to_the_target_agent(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get("/delegate", headers={"Authorization": f"Bearer {session['root_grant']}"})

    assert r.status_code == 200
    c = claims(sidecar_stack.recorder.last["token"])
    assert c["aud"] == f"agent://{KB_SEARCH}"
    assert c["act"] == {"sub": "agent://orchestrator"}


async def test_an_unmapped_path_is_blocked_and_delivers_nothing(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get(
        "/unmapped/thing", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )

    assert r.status_code == 403
    assert r.json()["error"]["details"]["reason"] == "UPSTREAM_NOT_MAPPED"
    assert sidecar_stack.recorder.count == 0


async def test_a_route_with_no_target_or_data_class_is_blocked_rather_than_guessed(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get("/bare", headers={"Authorization": f"Bearer {session['root_grant']}"})

    assert r.status_code == 403
    assert r.json()["error"]["details"]["reason"] == "TARGET_NOT_RESOLVED"
    assert sidecar_stack.recorder.count == 0


async def test_headers_can_supply_the_target_for_an_sdk_aware_agent(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get(
        "/bare",
        headers={
            "Authorization": f"Bearer {session['root_grant']}",
            "X-Agentic-Target": "mcp://kb.internal/search",
            "X-Agentic-Data-Class": "kb.public",
        },
    )

    assert r.status_code == 200
    assert claims(sidecar_stack.recorder.last["token"])["aud"] == "mcp://kb.internal/search"


async def test_a_policy_deny_returns_a_structured_body_and_delivers_nothing(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get(
        "/bare",
        headers={
            "Authorization": f"Bearer {session['root_grant']}",
            "X-Agentic-Target": "agent://summarizer",  # not a declared edge from the root
            "X-Agentic-Data-Class": "account.read",
        },
    )

    assert r.status_code == 403
    details = r.json()["error"]["details"]
    assert details["reason"] == "EDGE_NOT_IN_DAG"
    assert details["recoverable"] is False
    assert details["target"] == "agent://summarizer"
    assert details["hop"] == 1
    assert sidecar_stack.recorder.count == 0


async def test_a_missing_token_is_rejected_without_calling_upstream(
    sidecar_stack, register_chain, consent
) -> None:
    await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get("/kb/search")

    assert r.status_code == 401
    assert sidecar_stack.recorder.count == 0


async def test_a_tampered_token_is_rejected_by_the_pdp_not_the_sidecar(
    sidecar_stack, register_chain, consent
) -> None:
    """The sidecar reads unverified claims only to build the request; the PDP is what
    verifies. A lie there buys a rejection, never a pass."""
    from tests.fixtures.tokens import tampered

    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get(
        "/kb/search",
        headers={
            "Authorization": f"Bearer {tampered(session['root_grant'], scope='account.write')}"
        },
    )

    assert r.status_code == 401
    assert sidecar_stack.recorder.count == 0


async def test_a_second_call_with_the_same_token_is_a_new_recorded_decision(
    sidecar_stack, register_chain, consent
) -> None:
    """Phase 4: the single-use guard is per recorded DECISION, not per
    token, so an agent can make more than one call at a hop. Each call is decided,
    recorded and narrowed on its own. Phase 2 blocked the second call with 401 here."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()
    headers = {"Authorization": f"Bearer {session['root_grant']}"}

    assert (await sidecar.get("/kb/search", headers=headers)).status_code == 200
    second = await sidecar.get("/kb/search", headers=headers)

    assert second.status_code == 200
    assert sidecar_stack.recorder.count == 2
    first_token, second_token = sidecar_stack.recorder.tokens()
    assert first_token != second_token  # two decisions, two narrowed tokens


async def test_the_sidecar_pools_one_http_client_for_the_process(sidecar_stack) -> None:
    """A per-request client would spend the whole per-hop latency budget on connection
    setup. One pooled client is built at startup and reused."""
    import httpx

    from app.sidecar.app import build_app
    from app.sidecar.config import SidecarConfig, Upstream

    calls: list[httpx.AsyncClient] = []

    class _Counting(httpx.AsyncClient):
        def __init__(self, *a, **k) -> None:
            super().__init__(*a, **k)
            calls.append(self)

    config = SidecarConfig(
        pdp_url="http://pdp.test",
        upstream_map={"/kb": Upstream("http://u", "mcp://kb.internal/search", "kb.public")},
    ).validate()

    injected = _Counting()
    try:
        app = build_app(config, client=injected)
        # The app closes over exactly one client; nothing per-request constructs another.
        assert len(calls) == 1
        assert app is not None
    finally:
        await injected.aclose()


async def test_a_path_escaping_its_prefix_is_blocked(
    sidecar_stack, register_chain, consent
) -> None:
    """The prefix decides which policy target the call is authorized against, and the
    same prefix is stripped to build the upstream URL. A dot segment makes those two
    disagree: `/kb/../admin` is authorized as the `/kb` target and delivered to `/admin`,
    carrying a correctly-narrowed token to a path nobody authorized.

    The request is sent percent-encoded because httpx resolves dot segments client-side.
    uvicorn does not — it percent-decodes `scope["path"]` and normalises nothing — so
    this is the shape that actually arrives in production, and the only one that reaches
    the guard through this transport.
    """
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get(
        "/kb%2f..%2fadmin", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )

    assert r.status_code == 403
    assert r.json()["error"]["details"]["reason"] == "UPSTREAM_NOT_MAPPED"
    assert sidecar_stack.recorder.count == 0


async def test_a_dotted_filename_is_not_mistaken_for_traversal(
    sidecar_stack, register_chain, consent
) -> None:
    """`..` between other characters is an ordinary path segment, not an escape."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get("/kb/a..b", headers={"Authorization": f"Bearer {session['root_grant']}"})

    assert r.status_code == 200
    assert sidecar_stack.recorder.last["path"] == "/a..b"
