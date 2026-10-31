"""Two embedded instances in one process share nothing (FR-016).

The control plane's collaborators are process-wide by default; an embedded instance swaps in
its own through agentic_auth/runtime.py. If that ever leaks, two parallel tests would sign
with one key or read one audit log — so each kind of state is checked separately.
"""

from __future__ import annotations

import asyncio

from agentic_auth.embedded import EmbeddedControlPlane
from tests.fixtures.chains import KB_SEARCH, ORCHESTRATOR, chain_docs
from tests.fixtures.discovery.server import RESOURCES

USER = "user:alice"


async def _start() -> EmbeddedControlPlane:
    return await EmbeddedControlPlane.start(chain_docs(), capabilities=RESOURCES)


async def test_instances_share_no_key_session_or_audit_row() -> None:
    a, b = await asyncio.gather(_start(), _start())
    try:
        assert a.jwks()["keys"][0]["kid"] != b.jwks()["keys"][0]["kid"]

        session = await a.client().consent(scope=ORCHESTRATOR, user_sub=USER)
        grant, _ = await a.client().hop(
            session.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal"
        )

        # B has never heard of A's session or its decision.
        b_rows = (await b.client().audit.decisions())["data"]
        assert b_rows == []
        a_rows = (await a.client().audit.decisions())["data"]
        assert [r["id"] for r in a_rows] == [grant.action_id]

        # A grant A issued does not verify at a resource that trusts B.
        verifier_b = await b.verifier(identity_required=False)
        try:
            assert not verifier_b.admit(grant.headers(), target=f"agent://{KB_SEARCH}").ok
        finally:
            await verifier_b.close()
        verifier_a = await a.verifier(identity_required=False)
        try:
            assert verifier_a.admit(grant.headers(), target=f"agent://{KB_SEARCH}").ok
        finally:
            await verifier_a.close()
    finally:
        await asyncio.gather(a.aclose(), b.aclose())


async def test_concurrent_traffic_on_two_instances_stays_separate() -> None:
    a, b = await asyncio.gather(_start(), _start())
    try:

        async def traffic(cp: EmbeddedControlPlane, n: int) -> None:
            client = cp.client()
            for _ in range(n):
                s = await client.consent(scope=ORCHESTRATOR, user_sub=USER)
                await client.hop(
                    s.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal"
                )

        await asyncio.gather(traffic(a, 5), traffic(b, 3))
        assert len((await a.client().audit.decisions())["data"]) == 5
        assert len((await b.client().audit.decisions())["data"]) == 3
    finally:
        await asyncio.gather(a.aclose(), b.aclose())


async def test_the_process_default_is_untouched_by_an_instance(cp) -> None:
    """Outside an instance's requests, the accessors still return the process's own."""
    from agentic_auth.config import get_settings
    from agentic_auth.services.tokens.keys import get_issuer_key

    assert get_settings().admin_token != cp._runtime.settings.admin_token
    assert get_issuer_key().kid != cp.jwks()["keys"][0]["kid"]
