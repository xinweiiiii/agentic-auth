"""Verified consent in an embedded control plane (feature 011, research R12).

The built-in test IdP mints what an MCP client's login would produce, so verified consent
works with no infrastructure. Every session it roots says ``embedded-test``: a test
principal must never pass for a verified one in an exported record.
"""

from __future__ import annotations

from agentic_auth.embedded import BASE_URL as BASE
from agentic_auth.embedded import EmbeddedControlPlane
from agentic_auth.embedded import idp as embedded_idp
from tests.fixtures.chains import ORCHESTRATOR, chain_docs
from tests.fixtures.discovery.server import RESOURCES


async def test_a_session_rooted_by_the_test_idp_is_labelled_embedded_test() -> None:
    async with EmbeddedControlPlane.open(
        chain_docs(), capabilities=RESOURCES, verified_consent_enabled=True
    ) as cp:
        token = cp.idp.mint_access_token(sub="alice")
        r = await cp.http.post(
            f"{BASE}/v1/consent",
            headers={"Authorization": f"Bearer {cp.admin_token}"},
            json={"scope": ORCHESTRATOR, "subject_token": token},
        )

    assert r.status_code == 201, r.text
    assert r.json()["user_sub"] == f"{embedded_idp.ISSUER}#alice"
    assert r.json()["principal_source"] == "embedded-test"


async def test_the_test_idp_publishes_discovery_with_no_login_endpoint() -> None:
    async with EmbeddedControlPlane.open(chain_docs(), capabilities=RESOURCES) as cp:
        r = await cp.http.get(f"{embedded_idp.ISSUER}/.well-known/oauth-authorization-server")
    assert r.json()["issuer"] == embedded_idp.ISSUER
    assert "authorization_endpoint" not in r.json()
