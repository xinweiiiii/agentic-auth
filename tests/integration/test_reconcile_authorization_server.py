"""Registration checks each MCP server's authorization server (feature 011, US4, M3)."""

from __future__ import annotations

import pytest

from tests.fixtures.chains import manifest_doc


@pytest.fixture
def m3(flags):
    flags(as_metadata_enabled=True)


def _doc(ref: str, data_classes: list[str], *, privileged: bool = False) -> dict:
    return manifest_doc(
        "as-agent",
        hop_budget=2,
        tools=[{"ref": ref, "data_classes": data_classes, "privileged": privileged}],
    )


async def _register(client, headers, manifest, override=None):
    body = {"name": "as-agent", "manifest": manifest}
    if override:
        body["override"] = override
    return await client.post("/v1/agents", json=body, headers=headers)


async def test_a_scope_the_authorization_server_does_not_issue_is_a_422_diff(
    client, admin_headers, m3
) -> None:
    doc = _doc("mcp://payments.internal/refund", ["payments.read", "payments.write"])
    r = await _register(client, admin_headers, doc)

    assert r.status_code == 422
    diff = r.json()["error"]["details"]["diff"]
    [entry] = [d for d in diff if d["code"] == "DECLARED_EXCEEDS_AUTHORIZATION_SERVER"]
    assert entry["tool_ref"] == "mcp://payments.internal/refund"
    assert entry["field"] == "data_classes"
    assert entry["declared"] == ["payments.read", "payments.write"]
    assert entry["discovered"] == ["payments.read"]
    assert entry["remedy"]


async def test_an_unreachable_authorization_server_blocks_registration(
    client, admin_headers, m3
) -> None:
    r = await _register(
        client, admin_headers, _doc("mcp://asdown.internal/read_notes", ["notes.read"])
    )
    assert r.status_code == 409
    codes = [d["code"] for d in r.json()["error"]["details"]["diff"]]
    assert codes == ["AUTHORIZATION_SERVER_UNAVAILABLE"]


async def test_no_authorization_server_reconciles_and_says_the_check_was_skipped(
    client, admin_headers, m3
) -> None:
    r = await _register(
        client, admin_headers, _doc("mcp://ledger.internal/read_ledger", ["ledger.read"])
    )
    assert r.status_code == 201, r.text
    report = (
        await client.get(f"/v1/agents/{r.json()['agent_id']}/reconciliation", headers=admin_headers)
    ).json()
    assert [d["code"] for d in report["diff"]] == ["AUTHORIZATION_SERVER_CHECK_SKIPPED"]


async def test_with_the_flag_off_registration_is_unchanged(client, admin_headers, flags) -> None:
    flags(as_metadata_enabled=False)
    doc = _doc("mcp://payments.internal/refund", ["payments.read", "payments.write"])
    assert (await _register(client, admin_headers, doc)).status_code == 201
