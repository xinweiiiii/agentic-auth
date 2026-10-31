"""Fail closed on every failure class.

Each test breaks one thing and asserts the same two facts: the agent got a
refusal, and the upstream received **zero** requests. Not a timeout that eventually
forwards, not a degraded pass-through.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route


async def _rooted(register_chain, consent):
    await register_chain()
    return await consent()


async def _call(sidecar, session):
    return await sidecar.get(
        "/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )


# -- the dependency is unreachable ------------------------------------------


async def test_pdp_unreachable_blocks_the_call(sidecar_stack, register_chain, consent) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()
    sidecar_stack.router.pdp_down = True

    r = await _call(sidecar, session)

    assert r.status_code == 503
    assert r.json()["error"]["details"]["reason"] == "PDP_UNAVAILABLE"
    assert sidecar_stack.recorder.count == 0


async def test_upstream_unreachable_is_a_bad_gateway_not_a_silent_success(
    sidecar_stack, register_chain, consent
) -> None:
    """Distinct from a policy failure: the hop was allowed, the upstream simply is not there."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()
    sidecar_stack.router.upstream_down = True

    r = await _call(sidecar, session)

    assert r.status_code == 502
    assert sidecar_stack.recorder.count == 0


# -- the dependency answers, but unusably ------------------------------------


def _broken_control_plane(*, authorize_response, exchange_response) -> Starlette:
    async def authorize(_request):
        return authorize_response()

    async def exchange(_request):
        return exchange_response()

    return Starlette(
        routes=[
            Route("/v1/authorize", authorize, methods=["POST"]),
            Route("/v1/token/exchange", exchange, methods=["POST"]),
        ]
    )


@pytest.fixture
def broken_sidecar():
    """A sidecar pointed at a control plane that misbehaves in a specified way."""
    from agentic_auth.sidecar.app import build_app
    from agentic_auth.sidecar.config import SidecarConfig, Upstream
    from tests.fixtures.upstream.server import build_upstream

    created: list[httpx.AsyncClient] = []

    def _make(*, authorize_response, exchange_response):
        upstream_app, recorder = build_upstream()
        control = _broken_control_plane(
            authorize_response=authorize_response, exchange_response=exchange_response
        )

        class _Router(httpx.AsyncBaseTransport):
            def __init__(self) -> None:
                self.control = ASGITransport(app=control)
                self.upstream = ASGITransport(app=upstream_app)

            async def handle_async_request(self, request):
                if request.url.host == "pdp.test":
                    return await self.control.handle_async_request(request)
                return await self.upstream.handle_async_request(request)

        config = SidecarConfig(
            pdp_url="http://pdp.test",
            upstream_map={
                "/kb": Upstream(
                    url="http://upstream.test",
                    target="mcp://kb.internal/search",
                    data_class="kb.public",
                )
            },
        ).validate()
        app = build_app(config, client=httpx.AsyncClient(transport=_Router()))
        c = httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://sidecar")
        created.append(c)
        return c, recorder

    yield _make


ALLOW = lambda: JSONResponse(  # noqa: E731
    {
        "outcome": "allow",
        "hop": 1,
        "policy_version": 1,
        "session_id": "s",
        # A recorded allow — these tests break the EXCHANGE, so the decision must be one the
        # sidecar would otherwise act on (Phase 3 blocks unrecorded allows before exchanging).
        "action_id": "7c1e0000-0000-4000-8000-000000000001",
        "recorded": True,
    }
)


def _shaped_token() -> str:
    """A token the sidecar can read a session and subject off, but that no verifier
    would accept. Enough to reach the control plane, which is what these tests break."""
    import base64
    import json as _json

    def seg(d: dict) -> str:
        return base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{seg({'alg': 'EdDSA'})}.{seg({'sub': 'user:alice', 'session_id': 's'})}.sig"


SHAPED = {"Authorization": f"Bearer {_shaped_token()}"}


async def test_pdp_returning_five_hundred_blocks_the_call(broken_sidecar) -> None:
    sidecar, recorder = broken_sidecar(
        authorize_response=lambda: PlainTextResponse("boom", status_code=500),
        exchange_response=lambda: JSONResponse({"access_token": "should-never-be-used"}),
    )

    r = await sidecar.get("/kb/search", headers=SHAPED)

    assert r.status_code == 503
    assert r.json()["error"]["details"]["reason"] == "PDP_UNAVAILABLE"
    assert recorder.count == 0


async def test_pdp_returning_an_unparseable_body_blocks_the_call(broken_sidecar) -> None:
    sidecar, recorder = broken_sidecar(
        authorize_response=lambda: PlainTextResponse("not json", status_code=200),
        exchange_response=lambda: JSONResponse({"access_token": "should-never-be-used"}),
    )

    r = await sidecar.get("/kb/search", headers=SHAPED)

    assert r.status_code == 503
    assert r.json()["error"]["details"]["reason"] == "PDP_UNAVAILABLE"
    assert recorder.count == 0


async def test_pdp_body_missing_the_outcome_blocks_the_call(broken_sidecar) -> None:
    sidecar, recorder = broken_sidecar(
        authorize_response=lambda: JSONResponse({"policy_version": 1}),
        exchange_response=lambda: JSONResponse({"access_token": "should-never-be-used"}),
    )

    r = await sidecar.get("/kb/search", headers=SHAPED)

    assert r.status_code == 503
    assert recorder.count == 0


async def test_exchange_refusing_the_subject_token_blocks_the_allowed_hop(
    broken_sidecar,
) -> None:
    """The hop was allowed, but no narrowed token exists — so nothing is forwarded.
    The presented token is never sent as a fallback."""
    sidecar, recorder = broken_sidecar(
        authorize_response=ALLOW,
        exchange_response=lambda: JSONResponse({"error": "invalid_grant"}, status_code=400),
    )

    r = await sidecar.get("/kb/search", headers=SHAPED)

    # 401: the token was refused, not the service unavailable.
    assert r.status_code == 401
    assert recorder.count == 0


async def test_exchange_returning_a_server_error_blocks_the_allowed_hop(
    broken_sidecar,
) -> None:
    sidecar, recorder = broken_sidecar(
        authorize_response=ALLOW,
        exchange_response=lambda: PlainTextResponse("boom", status_code=500),
    )

    r = await sidecar.get("/kb/search", headers=SHAPED)

    assert r.status_code == 503
    assert r.json()["error"]["details"]["reason"] == "TOKEN_SERVICE_UNAVAILABLE"
    assert recorder.count == 0


async def test_exchange_returning_no_token_blocks_the_call(broken_sidecar) -> None:
    sidecar, recorder = broken_sidecar(
        authorize_response=ALLOW,
        exchange_response=lambda: JSONResponse({"token_type": "Bearer", "expires_in": 60}),
    )

    r = await sidecar.get("/kb/search", headers=SHAPED)

    assert r.status_code == 503
    assert r.json()["error"]["details"]["reason"] == "TOKEN_SERVICE_UNAVAILABLE"
    assert recorder.count == 0


async def test_exchange_returning_an_empty_token_blocks_the_call(broken_sidecar) -> None:
    sidecar, recorder = broken_sidecar(
        authorize_response=ALLOW,
        exchange_response=lambda: JSONResponse({"access_token": ""}),
    )

    r = await sidecar.get("/kb/search", headers=SHAPED)

    assert r.status_code == 503
    assert recorder.count == 0


async def test_exchange_returning_unparseable_json_blocks_the_call(broken_sidecar) -> None:
    sidecar, recorder = broken_sidecar(
        authorize_response=ALLOW,
        exchange_response=lambda: PlainTextResponse("<html>oops</html>", status_code=200),
    )

    r = await sidecar.get("/kb/search", headers=SHAPED)

    assert r.status_code == 503
    assert recorder.count == 0


# -- the structural guarantee ------------------------------------------------


def test_the_module_has_no_bare_except_or_default_allow() -> None:
    """Forwarding must stay reachable from exactly one place.

    A grep-shaped test, deliberately: the property being protected is textual, and the
    next person to add an `except` here needs to be told why they cannot.
    """
    import ast
    import inspect

    from agentic_auth.sidecar import enforce as module

    source = inspect.getsource(module)
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            assert node.type is not None, "bare `except` in enforce.py"
            assert not all(isinstance(s, ast.Pass) for s in node.body), (
                "`except: pass` in enforce.py"
            )

    # Allow is constructed exactly once — the single success path.
    allow_constructions = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "Allow"
    ]
    assert len(allow_constructions) == 1, (
        f"Allow is constructed {len(allow_constructions)} times; forwarding must have "
        "exactly one entry point"
    )


async def test_a_token_with_no_readable_session_is_rejected_before_any_call(
    broken_sidecar,
) -> None:
    """The sidecar cannot even build a decision request, so it refuses. Fail closed
    applies before the first outbound call too, not only after one fails."""
    sidecar, recorder = broken_sidecar(
        authorize_response=ALLOW,
        exchange_response=lambda: JSONResponse({"access_token": "should-never-be-used"}),
    )

    r = await sidecar.get("/kb/search", headers={"Authorization": "Bearer garbage"})

    assert r.status_code == 401
    assert recorder.count == 0
