"""The SDK's admin, audit and identity planes — everything a customer runs *around* the
hop path (``examples/e2e-notebook/customer_walkthrough.ipynb`` walks all of it).

The hop path itself is covered by ``test_sdk_client.py``; these are the calls a pipeline,
an auditor and a resource server make.
"""

from __future__ import annotations

import pytest

from agentic_auth.sdk import AgenticAuthClient, ControlPlaneRejected, DenyReason, ManifestRejected
from tests.fixtures.chains import CHAIN_AGENTS, KB_SEARCH, ORCHESTRATOR, chain_docs, manifest_doc

USER = "user:alice"
KB_TOOL = "mcp://kb.internal/search"


@pytest.fixture
async def sdk(client) -> AgenticAuthClient:
    from tests.conftest import ADMIN_TOKEN

    return AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)


@pytest.fixture
async def reader(client, flags) -> AgenticAuthClient:
    """A client holding ONLY the read-only bearers — what an auditor or a resource server
    gets. It must be able to read, and must not be able to register anything."""
    flags(audit_read_token="reader-token")
    return AgenticAuthClient(base_url="http://test", audit_token="reader-token", client=client)


# -- admin plane -----------------------------------------------------------------------


async def test_register_agent_returns_the_compiled_outcome(sdk) -> None:
    docs = chain_docs()
    registered = [
        await sdk.admin.register_agent(name, docs[name]) for name in reversed(CHAIN_AGENTS)
    ]

    assert [r.status for r in registered] == ["reconciled"] * 4
    by_name = dict(zip(reversed(CHAIN_AGENTS), registered, strict=True))
    assert by_name[ORCHESTRATOR].manifest_version == 1
    assert await sdk.admin.agent_id(ORCHESTRATOR) == by_name[ORCHESTRATOR].agent_id


async def test_an_over_broad_declaration_is_rejected_with_a_remedy(sdk, register_chain) -> None:
    await register_chain()
    overbroad = manifest_doc(
        KB_SEARCH,
        hop_budget=4,
        tools=[
            {
                "ref": "mcp://accounts.internal/read_account",
                # The capability source advertises account.read only.
                "data_classes": ["account.read", "account.write"],
                "privileged": False,
            }
        ],
        reads=["account.read"],
        writes=["account.write"],
    )

    with pytest.raises(ManifestRejected) as refused:
        await sdk.admin.submit_manifest(KB_SEARCH, overbroad)

    rejected = refused.value
    assert rejected.status == 422
    assert rejected.needs_review is False
    assert [e["code"] for e in rejected.diff] == ["DECLARED_EXCEEDS_DISCOVERED"]
    assert rejected.remedies() and "account.write" in rejected.remedies()[0]


async def test_discovery_unavailable_is_held_for_review_then_attested(sdk, register_chain) -> None:
    await register_chain()
    unreachable = manifest_doc(
        KB_SEARCH,
        hop_budget=4,
        tools=[{"ref": "mcp://down.internal/x", "data_classes": ["kb.internal"]}],
        reads=["kb.internal"],
    )

    with pytest.raises(ManifestRejected) as held:
        await sdk.admin.submit_manifest(KB_SEARCH, unreachable)
    assert held.value.status == 409
    assert held.value.needs_review is True
    assert [e["code"] for e in held.value.diff] == ["DISCOVERY_UNAVAILABLE"]

    attested = await sdk.admin.submit_manifest(
        KB_SEARCH, unreachable, override_reason="pre-production host, CHG-1"
    )
    # The refused submission was stored too — history is immutable — so the attested
    # version follows it rather than replacing it.
    assert attested.version > 1
    assert attested.status in ("reconciled", "needs_review")


async def test_reads_report_what_was_compiled(sdk, register_chain) -> None:
    await register_chain()

    catalog = await sdk.admin.scope_catalog(ORCHESTRATOR)
    assert catalog["scope"] == ORCHESTRATOR
    assert KB_TOOL in [tool["ref"] for tool in catalog["tools"]]
    assert catalog["hop_budget"] == 4

    stored = await sdk.admin.manifest(ORCHESTRATOR, version=1)
    assert stored["version"] == 1
    assert stored["doc"]["metadata"]["agent"] == ORCHESTRATOR

    report = await sdk.admin.reconciliation(await sdk.admin.agent_id(ORCHESTRATOR))
    assert report["discovery_ok"] is True and report["diff"] == []

    page = await sdk.admin.agents()
    assert {a["name"] for a in page["data"]} == set(CHAIN_AGENTS)


async def test_an_unknown_agent_is_a_rejection_not_an_outage(sdk) -> None:
    with pytest.raises(ControlPlaneRejected) as missing:
        await sdk.admin.manifest("nobody")
    assert missing.value.status == 404

    with pytest.raises(ControlPlaneRejected) as unnamed:
        await sdk.admin.agent_id("nobody")
    assert unnamed.value.status == 404


async def test_the_read_only_bearer_cannot_register(reader) -> None:
    with pytest.raises(ControlPlaneRejected) as refused:
        await reader.admin.register_agent("x", chain_docs()[ORCHESTRATOR])
    assert refused.value.status == 401


# -- audit plane -----------------------------------------------------------------------


async def test_the_audit_plane_reads_history_and_chains(sdk, reader, register_chain) -> None:
    await register_chain()
    session = await sdk.consent(scope=ORCHESTRATOR, user_sub=USER)
    grant = await sdk.authorize(session.context(), target=KB_TOOL, data_class="kb.public")

    # The grant names its own audit row, so a caller never has to search for it.
    assert grant.action_id

    history = await reader.audit.decisions(session_id=session.session_id)
    assert [row["id"] for row in history["data"]] == [grant.action_id]
    assert history["data"][0]["outcome"] == "allow"

    allows = await reader.audit.decisions(outcome="allow", limit=5)
    assert allows["data"]

    chain = await reader.audit.chain(grant.action_id)
    assert chain["root_consent"]["user_sub"] == USER
    assert chain["complete"] is True
    assert [hop["target"] for hop in chain["chain"]] == [KB_TOOL]


async def test_a_refusal_names_the_record_that_explains_it(sdk, reader, register_chain) -> None:
    from agentic_auth.sdk import PolicyDenied

    await register_chain()
    session = await sdk.consent(scope=ORCHESTRATOR, user_sub=USER)

    with pytest.raises(PolicyDenied) as denied:
        await sdk.authorize(
            session.context(), target="mcp://ledger.internal/read_ledger", data_class="ledger.read"
        )

    assert denied.value.reason is DenyReason.OUT_OF_SCOPE
    chain = await reader.audit.chain(denied.value.action_id)
    assert chain["chain"][-1]["decision"] == "deny"
    assert chain["chain"][-1]["deny_reason"] == DenyReason.OUT_OF_SCOPE.value


# -- identity plane and ops ------------------------------------------------------------


async def test_the_identity_plane_serves_what_a_verifier_bootstraps_from(
    sdk, reader, register_chain, principal_assertion_for
) -> None:
    from agentic_auth.sdk import AgentKey

    await register_chain()
    agent_id = await sdk.admin.agent_id(ORCHESTRATOR)
    key = AgentKey.generate()
    outcome = await sdk.enroll(
        agent_id,
        key=key,
        agent_name=ORCHESTRATOR,
        principal_assertion=principal_assertion_for(ORCHESTRATOR),
    )
    assert outcome["status"] == "enrolled"

    identity = await reader.identity.of(ORCHESTRATOR)
    assert identity["revoked"] is False
    assert identity["jwks"]["keys"][0]["kid"] == key.kid
    by_id = await reader.identity.by_id(agent_id)
    # Same material; `as_of` is the moment each view was taken, so it differs by design.
    assert {k: v for k, v in by_id.items() if k != "as_of"} == {
        k: v for k, v in identity.items() if k != "as_of"
    }

    await sdk.revoke(agent_id, reason="drill")
    assert (await reader.identity.of(ORCHESTRATOR))["revoked"] is True
    revocations = await reader.identity.revocations()
    assert [item["agent"] for item in revocations["items"]] == [ORCHESTRATOR]


async def test_ops_endpoints_need_no_credential(client) -> None:
    anonymous = AgenticAuthClient(base_url="http://test", client=client)

    assert (await anonymous.healthz())["status"] == "ok"
    assert (await anonymous.readyz())["status"] == "ready"
    # A resource server must be able to fetch issuer keys with no bearer at all.
    assert (await anonymous.jwks())["keys"]
