"""An embedded instance's export, carried into a deployed control plane (US3-AS3).

The bundle comes from a real ``EmbeddedControlPlane``; the destination is the server harness
on PostgreSQL. Manifests re-register through the admin API (every version, in order) and
decisions land in ``imported_audit`` — never in this deployment's own ``audit_decisions``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select, text

from agentic_auth.cli.audit import import_bundle
from agentic_auth.cli.manifest import replay_bundle
from agentic_auth.config import get_settings
from agentic_auth.embedded import EmbeddedControlPlane
from agentic_auth.models import AuditDecision, ImportedAudit
from agentic_auth.services.bundle_import import read_bundle, registration_plan
from tests.conftest import ADMIN_TOKEN
from tests.fixtures.chains import KB_SEARCH, ORCHESTRATOR, chain_docs, manifest_doc
from tests.fixtures.discovery.server import RESOURCES


@pytest.fixture
async def bundle(tmp_path):
    async with EmbeddedControlPlane.open(chain_docs(), capabilities=RESOURCES) as cp:
        client = cp.client()
        # A second version for one agent, so the replay has history to keep in order.
        docs = chain_docs()
        await client.admin.submit_manifest(
            KB_SEARCH,
            manifest_doc(
                KB_SEARCH,
                hop_budget=4,
                tools=[
                    {
                        "ref": "mcp://kb.internal/search",
                        "data_classes": ["kb.internal", "kb.public"],
                        "privileged": False,
                    }
                ],
                downstream=docs[KB_SEARCH]["spec"]["downstream_agents"],
            ),
        )
        session = await client.consent(scope=ORCHESTRATOR, user_sub="user:alice")
        await client.hop(session.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal")
        return read_bundle(await cp.export(tmp_path / "bundle.ndjson"))


async def test_manifests_replay_every_version_in_order(client, admin_headers, bundle) -> None:
    results = await replay_bundle(
        client, "http://test", ADMIN_TOKEN, registration_plan(bundle), "carried over"
    )
    assert all(status == 201 for _, _, status, _ in results), results
    assert [(name, v) for name, v, _, _ in results if name == KB_SEARCH] == [
        (KB_SEARCH, 1),
        (KB_SEARCH, 2),
    ]
    agents = (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    assert {a["name"] for a in agents} == {a["name"] for a in bundle.agents}
    # Carried over as manifests only: nobody is enrolled until they prove their own key.
    assert {a["status"] for a in agents} == {"registered"}


async def test_decisions_land_apart_from_this_deployments_log(db_session, bundle) -> None:
    url = get_settings().database_url
    first = await import_bundle(url, bundle)
    assert (first.imported, first.already_present) == (len(bundle.audit), 0)

    rows = (await db_session.execute(select(ImportedAudit))).scalars().all()
    assert {str(r.action_id) for r in rows} == {row["id"] for row in bundle.audit}
    assert {r.source_deployment for r in rows} == {"embedded"}
    assert await db_session.scalar(select(func.count()).select_from(AuditDecision)) == 0

    again = await import_bundle(url, bundle)
    assert (again.imported, again.already_present) == (0, len(bundle.audit))


async def test_imported_rows_are_append_only(db_session, bundle) -> None:
    await import_bundle(get_settings().database_url, bundle)
    for statement in (
        "UPDATE imported_audit SET source_deployment = 'server'",
        "DELETE FROM imported_audit",
    ):
        with pytest.raises(Exception, match="append-only"):
            async with db_session.begin_nested():
                await db_session.execute(text(statement))
