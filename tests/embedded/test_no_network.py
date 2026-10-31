"""The embedded control plane opens no socket, ever (FR-008).

Every socket constructor raises for the duration of the test, so a single real connection
anywhere on the path — discovery, the IdP, the control plane itself — fails it.
"""

from __future__ import annotations

import socket

import pytest

from agentic_auth.embedded import EmbeddedControlPlane
from agentic_auth.sdk import AgentKey
from tests.fixtures.chains import KB_SEARCH, NOTIFIER, ORCHESTRATOR, SUMMARIZER, chain_docs
from tests.fixtures.discovery.server import RESOURCES


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("the embedded control plane tried to open a network connection")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)


async def test_full_lifecycle_without_a_socket(no_network) -> None:
    async with EmbeddedControlPlane.open(chain_docs(), capabilities=RESOURCES) as cp:
        client = cp.client()
        await cp.enroll_test_principal(ORCHESTRATOR, AgentKey.generate())
        session = await client.consent(scope=ORCHESTRATOR, user_sub="user:alice")
        ctx = session.context()
        grant = None
        for target, data_class in (
            (f"agent://{KB_SEARCH}", "kb.internal"),
            (f"agent://{SUMMARIZER}", "account.read"),
            (f"agent://{NOTIFIER}", "account.write"),
        ):
            grant, ctx = await client.hop(ctx, target=target, data_class=data_class)
        assert grant is not None
        chain = await client.audit.chain(grant.action_id)
        assert chain["complete"]
