"""Embedded mode is never silent about what it is (FR-012)."""

from __future__ import annotations

import logging

from agentic_auth.embedded import EmbeddedControlPlane, ManifestRejected
from tests.fixtures.chains import KB_SEARCH, ORCHESTRATOR, chain_docs
from tests.fixtures.discovery.server import RESOURCES

BANNER = (
    "embedded control plane: development and testing only — signing keys and policy "
    "decisions run inside this process (store=:memory:)"
)


async def test_one_warning_banner_on_open(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="agentic_auth.embedded"):
        async with EmbeddedControlPlane.open(capabilities=RESOURCES):
            pass
    messages = [r.getMessage() for r in caplog.records if r.name == "agentic_auth.embedded"]
    assert messages == [BANNER]


async def test_every_decision_is_labelled_embedded() -> None:
    async with EmbeddedControlPlane.open(chain_docs(), capabilities=RESOURCES) as cp:
        client = cp.client()
        session = await client.consent(scope=ORCHESTRATOR, user_sub="user:alice")
        await client.hop(session.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal")
        rows = (await client.audit.decisions())["data"]
        assert rows and {r["deployment"] for r in rows} == {"embedded"}


async def test_an_unreachable_capability_source_needs_an_override() -> None:
    """No documents means no discovery: the server's reconcile-or-override rule applies."""
    async with EmbeddedControlPlane.open() as cp:
        try:
            await cp.register(chain_docs())
        except ManifestRejected as exc:
            assert exc.needs_review
        else:
            raise AssertionError("registered without discovery or an override")
        registered = await cp.register(chain_docs(), override_reason="offline test")
        assert {r.status for r in registered} == {"reconciled"}


async def test_calls_after_close_are_refused() -> None:
    cp = await EmbeddedControlPlane.start(capabilities=RESOURCES)
    await cp.aclose()
    await cp.aclose()  # idempotent
    try:
        cp.client()
    except RuntimeError as exc:
        assert "closed" in str(exc)
    else:
        raise AssertionError("client() after close")
