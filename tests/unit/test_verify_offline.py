"""Verification is offline after bootstrap, and fast."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.schemas.authorize import Taint
from app.services.tokens.act_chain import nest
from app.services.tokens.jwt_profile import JwtTokenProfile
from app.services.tokens.keys import load_or_generate
from app.verify import HttpAnchors, HttpJwks, InMemoryReplay, Verifier
from tests.fixtures.identity import agent_keypair, identity_assertion

USER = "user:alice"
SUPPORT = "support-agent"
READ_BALANCE = "mcp://accounts.internal/read_balance"
AGENT_ID = "3f2a0000-0000-4000-8000-000000000001"


class FakeControlPlane:
    """Answers the three bootstrap requests; can be cut, and can revoke."""

    def __init__(self, issuer: JwtTokenProfile, key) -> None:
        self.issuer = issuer
        self.key = key
        self.cut = False
        self.revoked = False
        self.requests = 0

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            if self.cut:
                raise httpx.ConnectError("cut")
            self.requests += 1
            path = request.url.path
            if path == "/.well-known/jwks.json":
                return httpx.Response(200, json=self.issuer.jwks())
            if path == f"/v1/identity/agents/{SUPPORT}":
                return httpx.Response(
                    200,
                    json={
                        "agent": SUPPORT,
                        "status": "revoked" if self.revoked else "enrolled",
                        "trust_anchor_version": 1,
                        "jwks": {"keys": [self.key.jwk()]},
                        "principal_ref": "https://idp.example#alice",
                        "manifest_version": 1,
                        "revoked": self.revoked,
                        "revoked_at": datetime.now(UTC).isoformat() if self.revoked else None,
                        "as_of": datetime.now(UTC).isoformat(),
                    },
                )
            if path == "/v1/identity/revocations":
                items = (
                    [
                        {
                            "agent": SUPPORT,
                            "trust_anchor_version": 1,
                            "revoked_at": datetime.now(UTC).isoformat(),
                        }
                    ]
                    if self.revoked
                    else []
                )
                return httpx.Response(
                    200,
                    json={
                        "as_of": datetime.now(UTC).isoformat(),
                        "items": items,
                        "page": {"next_cursor": None, "limit": 100},
                    },
                )
            return httpx.Response(404, json={"error": "nope"})

        return httpx.MockTransport(handle)


@pytest.fixture
def issuer() -> JwtTokenProfile:
    return JwtTokenProfile(load_or_generate(), issuer="agentic-auth", ttl_seconds=60)


@pytest.fixture
def key():
    return agent_keypair(SUPPORT)


async def _verifier(plane: FakeControlPlane, *, freshness: int = 30) -> Verifier:
    http = httpx.AsyncClient(transport=plane.transport(), base_url="http://cp")
    anchors = HttpAnchors(
        base_url="http://cp", token="t", agents=[SUPPORT], freshness_seconds=freshness, client=http
    )
    v = Verifier(
        issuer_jwks=HttpJwks("http://cp/.well-known/jwks.json", client=http),
        anchors=anchors,
        replay=InMemoryReplay(),
        freshness_seconds=freshness,
    )
    await v.bootstrap()
    await v.close()
    return v


def _grant(issuer) -> str:
    return issuer.mint_hop_token(
        sub=USER,
        target=READ_BALANCE,
        data_class="account.read",
        session_id="s1",
        policy_version=1,
        hop=2,
        act=nest(None, f"agent://{SUPPORT}"),
        action_id="7c1e0000-0000-4000-8000-000000000001",
        taint=Taint.TRUSTED_INTERNAL,
    )


async def test_every_verification_completes_with_the_network_cut(issuer, key) -> None:
    plane = FakeControlPlane(issuer, key)
    v = await _verifier(plane)
    plane.cut = True
    seen = plane.requests

    grant = _grant(issuer)
    headers = {
        "Authorization": f"Bearer {grant}",
        "Agent-Identity": identity_assertion(key, grant, READ_BALANCE),
    }
    outcomes = [v.admit(headers, target=READ_BALANCE).ok for _ in range(1000)]
    assert all(outcomes)
    assert plane.requests == seen  # not one request left the process


async def test_p95_added_latency_is_under_ten_milliseconds(issuer, key) -> None:
    plane = FakeControlPlane(issuer, key)
    v = await _verifier(plane)
    plane.cut = True
    grant = _grant(issuer)
    headers = {
        "Authorization": f"Bearer {grant}",
        "Agent-Identity": identity_assertion(key, grant, READ_BALANCE),
    }
    samples: list[float] = []
    for _ in range(300):
        started = time.perf_counter()
        assert v.admit(headers, target=READ_BALANCE).ok
        samples.append(time.perf_counter() - started)
    samples.sort()
    p95 = samples[int(len(samples) * 0.95)]
    print(f"\nverifier p95 = {p95 * 1000:.3f} ms")
    assert p95 < 0.010


async def test_a_never_bootstrapped_verifier_refuses_everything(issuer, key) -> None:
    plane = FakeControlPlane(issuer, key)
    http = httpx.AsyncClient(transport=plane.transport(), base_url="http://cp")
    v = Verifier(
        issuer_jwks=HttpJwks("http://cp/.well-known/jwks.json", client=http),
        anchors=HttpAnchors(base_url="http://cp", token="t", agents=[SUPPORT], client=http),
        replay=InMemoryReplay(),
    )
    grant = _grant(issuer)
    a = v.admit({"Authorization": f"Bearer {grant}"}, target=READ_BALANCE)
    assert not a.ok and a.reason == "GRANT_INVALID"  # no issuer keys at all


async def test_bootstrap_fails_loudly_when_the_control_plane_is_unreachable(issuer, key) -> None:
    plane = FakeControlPlane(issuer, key)
    plane.cut = True
    with pytest.raises(httpx.ConnectError):
        await _verifier(plane)


async def test_a_stale_view_refuses_and_a_refresh_restores(issuer, key) -> None:
    plane = FakeControlPlane(issuer, key)
    v = await _verifier(plane, freshness=1)
    grant = _grant(issuer)
    headers = {
        "Authorization": f"Bearer {grant}",
        "Agent-Identity": identity_assertion(key, grant, READ_BALANCE),
    }
    assert v.admit(headers, target=READ_BALANCE).ok

    anchors = v.anchors
    assert isinstance(anchors, HttpAnchors)
    anchors._as_of = datetime.now(UTC) - timedelta(seconds=5)  # ageing past the window
    a = v.admit(headers, target=READ_BALANCE)
    assert not a.ok and a.reason == "IDENTITY_STALE"

    plane.cut = True
    assert await anchors.refresh() is False  # cannot refresh: stays stale
    assert v.admit(headers, target=READ_BALANCE).reason == "IDENTITY_STALE"
    plane.cut = False
    assert await anchors.refresh() is True
    assert v.admit(headers, target=READ_BALANCE).ok


async def test_a_revocation_is_picked_up_on_refresh(issuer, key) -> None:
    plane = FakeControlPlane(issuer, key)
    v = await _verifier(plane)
    grant = _grant(issuer)
    headers = {
        "Authorization": f"Bearer {grant}",
        "Agent-Identity": identity_assertion(key, grant, READ_BALANCE),
    }
    assert v.admit(headers, target=READ_BALANCE).ok
    plane.revoked = True
    assert isinstance(v.anchors, HttpAnchors)
    await v.anchors.refresh()
    a = v.admit(headers, target=READ_BALANCE)
    assert not a.ok and a.reason == "IDENTITY_REVOKED"


def test_static_anchors_accept_the_identity_read_shape(issuer, key) -> None:
    from app.verify import StaticAnchors

    read = json.loads(
        json.dumps(
            {
                "agent": SUPPORT,
                "status": "enrolled",
                "trust_anchor_version": 2,
                "jwks": {"keys": [key.jwk()]},
                "principal_ref": "x",
                "manifest_version": 1,
                "revoked": False,
                "revoked_at": None,
                "as_of": datetime.now(UTC).isoformat(),
            }
        )
    )
    anchors = StaticAnchors([read])
    anchor = anchors.current(SUPPORT)
    assert anchor is not None and anchor.live and anchor.trust_anchor_version == 2


async def test_a_missing_route_fails_the_bootstrap_but_an_unregistered_agent_does_not(
    issuer, key
) -> None:
    """404 means two different things: the envelope says 'no such agent'; a bare framework
    404 says 'no such route'. Only the first may be skipped."""

    def build(body: dict) -> HttpAnchors:
        transport = httpx.MockTransport(
            lambda request: (
                httpx.Response(200, json={"keys": []})
                if request.url.path == "/v1/identity/revocations"
                else httpx.Response(404, json=body)
            )
        )
        http = httpx.AsyncClient(transport=transport, base_url="http://cp")
        return HttpAnchors(base_url="http://cp", token="t", agents=[SUPPORT], client=http)

    unregistered = build({"error": {"code": "not_found", "message": "agent 'x' not found"}})
    assert await unregistered.refresh() is True
    assert unregistered.current(SUPPORT) is None  # unknown, and bootstrap succeeded

    no_route = build({"detail": "Not Found"})
    with pytest.raises(httpx.HTTPStatusError):
        await no_route.bootstrap()
