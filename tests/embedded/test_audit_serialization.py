"""Concurrent hops on one embedded instance keep the audit log whole.

SQLite has neither PostgreSQL's isolation nor a non-key identity column, so the embedded
store serialises transactions (BEGIN IMMEDIATE) and numbers audit rows itself. If either
slipped, concurrent writers would collide on ``seq`` or record a chain against a parent read
before another writer's commit. Fifty concurrent chains must all come back complete.
"""

from __future__ import annotations

import asyncio

from agentic_auth.embedded import EmbeddedControlPlane
from tests.fixtures.chains import KB_SEARCH, ORCHESTRATOR, SUMMARIZER, chain_docs
from tests.fixtures.discovery.server import RESOURCES


async def test_fifty_concurrent_chains_are_all_recorded_complete() -> None:
    async with EmbeddedControlPlane.open(chain_docs(), capabilities=RESOURCES) as cp:
        client = cp.client()

        async def chain(i: int) -> str:
            session = await client.consent(scope=ORCHESTRATOR, user_sub=f"user:{i}")
            _, ctx = await client.hop(
                session.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal"
            )
            grant, _ = await client.hop(
                ctx, target=f"agent://{SUMMARIZER}", data_class="account.read"
            )
            assert grant.action_id is not None
            return grant.action_id

        action_ids = await asyncio.gather(*(chain(i) for i in range(50)))

        for action_id in action_ids:
            recorded = await client.audit.chain(action_id)
            assert recorded["complete"], recorded["break"]
            assert len(recorded["chain"]) == 2

        page = await client.audit.decisions(limit=100)
        assert len(page["data"]) == 100
        seqs = page["page"]["as_of_seq"]
        assert seqs == 100
