"""Features → "Install and run".

The embedded control plane, and moving an embedded instance to a deployment. The PyPI
package, the server image and signed releases are proven elsewhere — see
``test_feature_coverage.py`` for where.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from agentic_auth.embedded import EmbeddedControlPlane
from agentic_auth.sdk import AgentKey
from agentic_auth.services.bundle_import import read_bundle, registration_plan
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    SUPPORT_AGENT,
    USER,
    bank_docs,
)
from tests.fixtures.discovery.server import RESOURCES

pytestmark = pytest.mark.e2e


async def test_the_embedded_control_plane_says_what_it_is(caplog) -> None:
    """Embedded control plane: the real control plane in this process, with no server or
    database. It announces that it is for development and testing only, and labels every
    decision it records `deployment: embedded`."""
    with caplog.at_level(logging.WARNING, logger="agentic_auth.embedded"):
        async with EmbeddedControlPlane.open(capabilities=RESOURCES) as cp:
            await cp.register(bank_docs())
            sdk = cp.client()
            session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
            await sdk.hop(
                session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
            )
            rows = (await sdk.audit.decisions())["data"]

    assert "development and testing only" in caplog.text
    assert [row["deployment"] for row in rows] == ["embedded"]


async def test_an_embedded_instance_exports_everything_a_deployment_needs(tmp_path: Path) -> None:
    """Move to a deployment: the export bundle carries every manifest version and the
    decision history, in the order `manifest register-bundle` registers them (downstream
    agents first). It carries no private keys: agents enroll again with their own."""
    async with EmbeddedControlPlane.open(capabilities=RESOURCES) as cp:
        await cp.register(bank_docs())
        await cp.client().admin.submit_manifest(
            SUPPORT_AGENT, bank_docs(widened=True)[SUPPORT_AGENT]
        )
        await cp.enroll_test_principal(BALANCE_AGENT, AgentKey.generate(), principal=USER)
        sdk = cp.client()
        session = await sdk.consent(scope=BANK_ASSISTANT, user_sub=USER)
        await sdk.hop(
            session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
        )
        path = await cp.export(tmp_path / "bundle.ndjson")

    bundle = read_bundle(path)
    plan = registration_plan(bundle)

    assert bundle.header["source_deployment"] == "embedded"
    order = [name for name, _ in plan]
    assert set(order) == {BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT}
    assert order.index(SUPPORT_AGENT) < order.index(BALANCE_AGENT) < order.index(BANK_ASSISTANT)
    assert [len(versions) for name, versions in plan if name == SUPPORT_AGENT] == [2]
    assert len(bundle.audit) == 1
    assert "PRIVATE KEY" not in path.read_text()
