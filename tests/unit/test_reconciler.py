"""ReconcilerService — the four reconciliation outcomes + actionable-diff guarantee."""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport

from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.schemas.reconciliation import DiffCode
from agentic_auth.services.discovery import DiscoveryClient
from agentic_auth.services.reconciler import ReconcilerService
from tests.fixtures.discovery.server import fake_discovery_app
from tests.fixtures.manifests import (
    base_manifest,
    data_class_conflict_manifest,
    discovery_down_manifest,
    overbroad_manifest,
    unknown_tool_manifest,
)


async def _reconcile(doc: dict):
    manifest = AgentManifest.model_validate(doc)
    http = httpx.AsyncClient(transport=ASGITransport(app=fake_discovery_app))
    reconciler = ReconcilerService()
    try:
        discovered = await DiscoveryClient(client=http).discover(reconciler.authorities(manifest))
    finally:
        await http.aclose()
    return reconciler.reconcile(manifest, discovered)


def _assert_all_actionable(diff) -> None:
    for entry in diff:
        assert entry.tool_ref.strip()
        assert entry.remedy.strip()


async def test_clean_manifest_reconciles() -> None:
    outcome = await _reconcile(base_manifest())
    assert outcome.status == "reconciled"
    assert outcome.diff == []
    assert outcome.discovery_ok is True


async def test_declared_exceeds_discovered() -> None:
    outcome = await _reconcile(overbroad_manifest())
    assert outcome.status == "rejected"
    assert outcome.discovery_ok is True
    offending = [e for e in outcome.diff if e.code == DiffCode.DECLARED_EXCEEDS_DISCOVERED][0]
    assert offending.tool_ref == "mcp://accounts.internal/read_account"
    assert offending.field == "data_classes"
    assert offending.declared == ["account.read", "account.write"]
    assert offending.discovered == ["account.read"]
    _assert_all_actionable(outcome.diff)


async def test_unknown_tool() -> None:
    outcome = await _reconcile(unknown_tool_manifest())
    assert outcome.status == "rejected"
    entry = [e for e in outcome.diff if e.code == DiffCode.UNKNOWN_TOOL][0]
    assert entry.field == "ref"
    assert entry.tool_ref == "mcp://kb.internal/nonexistent"
    assert entry.declared == "mcp://kb.internal/nonexistent"
    assert entry.discovered == ["search"]  # the tools the authority DOES advertise
    _assert_all_actionable(outcome.diff)


async def test_every_failing_tool_gets_its_own_entry() -> None:
    """`continue` (not `break`) — a second bad tool after the first is still reported."""
    doc = unknown_tool_manifest()
    doc["spec"]["tools"].append(
        {"ref": "mcp://kb.internal/alsogone", "data_classes": ["kb.public"]}
    )
    outcome = await _reconcile(doc)
    refs = {e.tool_ref for e in outcome.diff if e.code == DiffCode.UNKNOWN_TOOL}
    assert refs == {"mcp://kb.internal/nonexistent", "mcp://kb.internal/alsogone"}


async def test_declaring_privileged_true_for_unprivileged_tool_is_fine() -> None:
    """`and advertised.privileged` — over-declaring privilege is not a conflict."""
    doc = base_manifest()
    doc["spec"]["tools"][0]["privileged"] = True
    outcome = await _reconcile(doc)
    assert outcome.status == "reconciled"
    assert outcome.diff == []


async def test_multiple_unreachable_tools_all_reported() -> None:
    doc = discovery_down_manifest()
    doc["spec"]["tools"].append({"ref": "mcp://down.internal/other", "data_classes": ["kb.public"]})
    outcome = await _reconcile(doc)
    assert len([e for e in outcome.diff if e.code == DiffCode.DISCOVERY_UNAVAILABLE]) == 2


def test_missing_authority_in_discovered_dict_is_unavailable() -> None:
    from agentic_auth.schemas.manifest import AgentManifest
    from tests.fixtures.manifests import base_manifest as _bm

    manifest = AgentManifest.model_validate(_bm())
    outcome = ReconcilerService().reconcile(manifest, {})
    assert outcome.status == "needs_review"
    assert outcome.discovery_ok is False
    assert "(not attempted)" in outcome.diff[0].remedy


async def test_data_class_conflict_on_privileged_mismatch() -> None:
    outcome = await _reconcile(data_class_conflict_manifest())
    assert outcome.status == "rejected"
    entry = [e for e in outcome.diff if e.code == DiffCode.DATA_CLASS_CONFLICT][0]
    assert entry.field == "privileged"
    assert entry.declared is False
    assert entry.discovered is True
    _assert_all_actionable(outcome.diff)


async def test_discovery_unavailable_flags_needs_review() -> None:
    outcome = await _reconcile(discovery_down_manifest())
    assert outcome.status == "needs_review"
    assert outcome.discovery_ok is False
    entry = outcome.diff[0]
    assert entry.code == DiffCode.DISCOVERY_UNAVAILABLE
    assert entry.field == "ref"
    assert entry.declared == "mcp://down.internal/search"
    assert "503" in entry.remedy
    _assert_all_actionable(outcome.diff)


def test_resource_present_but_none_is_treated_as_unavailable() -> None:
    """Guards the ``or result.resource is None`` branch."""
    from agentic_auth.schemas.manifest import AgentManifest
    from agentic_auth.services.discovery import DiscoveryResult
    from tests.fixtures.manifests import base_manifest

    manifest = AgentManifest.model_validate(base_manifest())
    broken = {"https://kb.internal": DiscoveryResult("https://kb.internal", ok=True, resource=None)}
    outcome = ReconcilerService().reconcile(manifest, broken)
    assert outcome.status == "needs_review"
    assert outcome.diff[0].code == DiffCode.DISCOVERY_UNAVAILABLE


# -- 0.4.0: the resource's authorization server (feature 011, M3, research R9) -------------


def _one_tool(ref: str, data_classes: list[str]) -> dict:
    from tests.fixtures.chains import manifest_doc

    return manifest_doc(
        "as-check-agent",
        hop_budget=2,
        tools=[{"ref": ref, "data_classes": data_classes, "privileged": False}],
    )


@pytest.fixture
def as_check(monkeypatch):
    from agentic_auth.config import get_settings

    monkeypatch.setattr(get_settings(), "as_metadata_enabled", True)


async def test_scopes_the_authorization_server_issues_reconcile(as_check) -> None:
    outcome = await _reconcile(_one_tool("mcp://kb.internal/search", ["kb.public"]))
    assert outcome.status == "reconciled"
    assert outcome.diff == []


async def test_a_scope_the_authorization_server_does_not_issue_is_rejected(as_check) -> None:
    """payments.internal advertises payments.write on refund, but its authorization server
    never issues it: nobody could hold that capability."""
    doc = _one_tool("mcp://payments.internal/refund", ["payments.read", "payments.write"])
    outcome = await _reconcile(doc)

    assert outcome.status == "rejected"
    [entry] = [d for d in outcome.diff if d.code is DiffCode.DECLARED_EXCEEDS_AUTHORIZATION_SERVER]
    assert entry.tool_ref == "mcp://payments.internal/refund"
    assert entry.declared == ["payments.read", "payments.write"]
    assert entry.discovered == ["payments.read"]
    assert "payments.write" in entry.remedy and "https://as.payments.internal" in entry.remedy
    _assert_all_actionable(outcome.diff)


async def test_an_unreachable_authorization_server_blocks_for_review(as_check) -> None:
    outcome = await _reconcile(_one_tool("mcp://asdown.internal/read_notes", ["notes.read"]))
    assert outcome.status == "needs_review"
    assert not outcome.discovery_ok
    [entry] = outcome.diff
    assert entry.code is DiffCode.AUTHORIZATION_SERVER_UNAVAILABLE
    assert "https://down.internal" in entry.remedy


@pytest.mark.parametrize(
    "tool",
    [
        ("mcp://ledger.internal/read_ledger", ["ledger.read"]),  # PRM names no AS
        ("mcp://noscopes.internal/read_wiki", ["wiki.read"]),  # AS has no scopes_supported
    ],
)
async def test_nothing_to_check_against_is_noted_and_never_blocks(as_check, tool) -> None:
    outcome = await _reconcile(_one_tool(*tool))
    assert outcome.status == "reconciled"
    assert [d.code for d in outcome.diff] == [DiffCode.AUTHORIZATION_SERVER_CHECK_SKIPPED]
    _assert_all_actionable(outcome.diff)


async def test_with_the_flag_off_the_authorization_server_is_not_consulted() -> None:
    doc = _one_tool("mcp://payments.internal/refund", ["payments.read", "payments.write"])
    outcome = await _reconcile(doc)
    assert outcome.status == "reconciled"
    assert outcome.diff == []
