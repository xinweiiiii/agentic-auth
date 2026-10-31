"""The export bundle carries what a deployment can take over, and nothing it must not."""

from __future__ import annotations

import json

from agentic_auth.embedded import EmbeddedControlPlane
from agentic_auth.sdk import AgentKey
from tests.fixtures.chains import CHAIN_AGENTS, KB_SEARCH, ORCHESTRATOR, chain_docs
from tests.fixtures.discovery.server import RESOURCES


async def test_bundle_is_ordered_complete_and_holds_no_secrets(tmp_path) -> None:
    async with EmbeddedControlPlane.open(chain_docs(), capabilities=RESOURCES) as cp:
        await cp.enroll_test_principal(ORCHESTRATOR, AgentKey.generate())
        client = cp.client()
        session = await client.consent(scope=ORCHESTRATOR, user_sub="user:alice")
        grant, ctx = await client.hop(
            session.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal"
        )
        bundle = await cp.export(tmp_path / "bundle.ndjson")
        secrets = (cp._runtime.settings.admin_token, cp._runtime.issuer_key.private_pem().decode())

    text = bundle.read_text()
    lines = [json.loads(line) for line in text.splitlines()]
    kinds = [line["kind"] for line in lines]

    assert kinds[0] == "header"
    assert lines[0]["source_deployment"] == "embedded"
    # Records grouped in replay order.
    assert kinds[1:] == sorted(kinds[1:], key=["agent", "manifest", "trust_anchor", "audit"].index)
    assert {line["name"] for line in lines if line["kind"] == "agent"} == set(CHAIN_AGENTS)
    assert lines[0]["counts"] == {
        "agent": 4,
        "manifest": 4,
        "trust_anchor": 1,
        "audit": 1,
    }
    (audit,) = [line for line in lines if line["kind"] == "audit"]
    assert audit["id"] == grant.action_id and audit["deployment"] == "embedded"
    # No session rows, no bearer, no signing key.
    assert "session" not in kinds
    for secret in secrets:
        assert secret not in text
