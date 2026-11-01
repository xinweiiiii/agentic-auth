"""Every row of the documentation's Features page (authzai.dev/reference/features), and
the test that proves it.

The page is written from what the release can do. This keeps it honest in the other
direction: a row is only listed here with a test behind it, and that test must exist. Add a
feature to the page, add its row here; remove a test, and this fails until the row points
at another proof.
"""

from __future__ import annotations

import importlib

import pytest

pytestmark = pytest.mark.e2e

#: Page section -> {feature row: proof}. A proof is "module::test" under tests/, or, for
#: what pytest cannot run, the workflow that proves it on every release.
FEATURES: dict[str, dict[str, str]] = {
    "Declare what an agent may do": {
        "Manifests": "e2e.test_declare::test_manifests_register_and_reconcile",
        "Reconciliation": (
            "e2e.test_declare::test_reconciliation_rejects_a_declaration_the_tool_does_not_publish"
        ),
        "Immutable versions": (
            "e2e.test_declare::test_a_manifest_change_is_a_new_version_and_sessions_keep_theirs"
        ),
        "Scope catalog": "e2e.test_declare::test_the_scope_catalog_shows_what_consent_grants",
        "CI drift check": "e2e.test_declare::test_the_drift_check_fails_on_an_undeclared_call",
        "Cold start": (
            "e2e.test_declare::test_cold_start_proposes_a_manifest_that_governs_only_after_review"
        ),
    },
    "Decide every call": {
        "Consent": "e2e.test_decide::test_consent_pins_the_policy_version_for_the_session",
        "Per-step decisions": "e2e.test_decide::test_every_step_is_decided_before_it_goes_out",
        "Narrowing tokens": (
            "e2e.test_decide::test_each_step_gets_a_narrower_token_naming_who_it_acts_for"
        ),
        "Transaction tokens": (
            "e2e.test_decide::test_a_privileged_call_is_bound_to_its_exact_parameters"
        ),
        "Taint labels": "e2e.test_decide::test_untrusted_content_cannot_trigger_a_privileged_call",
        "Consent to a subset": "e2e.test_decide::test_a_session_can_consent_to_fewer_data_classes",
        "Step-up consent": (
            "e2e.test_decide::test_step_up_asks_the_person_and_the_blocked_step_resumes"
        ),
    },
    "Enforce it on the way out": {
        "In-process SDK": "e2e.test_enforce::test_the_sdk_calls_the_tool_with_the_narrowed_token",
        "Sidecar": "e2e.test_enforce::test_the_sidecar_forwards_allowed_calls_and_blocks_the_rest",
        "Gateway": "e2e.test_enforce::test_the_gateway_enforces_for_the_fleet_and_fails_closed",
        "Resource-server guard": (
            "e2e.test_enforce::test_the_resource_guard_admits_only_a_grant_plus_identity"
        ),
        "MCP connector proxy": (
            "e2e.test_enforce::test_the_mcp_proxy_hides_and_refuses_undeclared_tools"
        ),
        "Egress proxy": "e2e.test_enforce::test_the_egress_proxy_says_it_is_not_available",
        "Observe mode": "e2e.test_enforce::test_observe_mode_records_refusals_without_blocking",
    },
    "Prove who the agent is": {
        "Enrollment": ("e2e.test_identity::test_enrollment_binds_a_key_to_a_person_or_quarantines"),
        "Offline verifier": (
            "e2e.test_identity::test_the_verifier_checks_calls_with_no_network_call"
        ),
        "Revocation": (
            "e2e.test_identity::test_revocation_cuts_off_the_agent_and_every_chain_through_it"
        ),
        "Required identity": (
            "e2e.test_identity::test_required_identity_refuses_agents_that_have_not_enrolled"
        ),
    },
    "Audit and operate": {
        "Decision log": "e2e.test_audit::test_every_decision_is_recorded_append_only",
        "Chain query": "e2e.test_audit::test_one_query_traces_an_action_back_to_the_person",
        "Audit export": "e2e.test_audit::test_old_decisions_export_without_deleting_anything",
        "Metrics": "e2e.test_audit::test_enforcement_points_report_metrics_without_identities",
        "Traces and logs": (
            "e2e.test_audit::test_decisions_emit_traces_with_pseudonymous_identities"
        ),
    },
    "Install and run": {
        # Builds the wheels and installs each extra into a fresh environment. Network-bound,
        # so it runs as CI's own Packaging job: `pytest -m packaging tests/packaging`.
        "PyPI package": "packaging.test_missing_extra::test_base_install_names_the_missing_extra",
        "Server image": "workflow: .github/workflows/release.yml (image job)",
        "Signed releases": "workflow: .github/workflows/release.yml (attestation steps)",
        "Embedded control plane": "e2e.test_run::test_the_embedded_control_plane_says_what_it_is",
        "Move to a deployment": (
            "e2e.test_run::test_an_embedded_instance_exports_everything_a_deployment_needs"
        ),
    },
}


def _tests() -> list[tuple[str, str]]:
    return [
        (row, proof)
        for rows in FEATURES.values()
        for row, proof in rows.items()
        if not proof.startswith("workflow:")
    ]


def test_the_page_has_thirty_four_rows() -> None:
    """The Features page at 0.3.0 has 34 rows. A new row needs a proof here first."""
    assert sum(len(rows) for rows in FEATURES.values()) == 34


@pytest.mark.parametrize(("row", "proof"), _tests(), ids=[row for row, _ in _tests()])
def test_every_row_names_a_test_that_exists(row: str, proof: str) -> None:
    module_name, _, test_name = proof.partition("::")
    try:
        module = importlib.import_module(f"tests.{module_name}")
    except ImportError as exc:  # the packaging suite needs its own extras
        if module_name.startswith("packaging."):
            pytest.skip(f"{row}: {module_name} imports packaging-only tooling ({exc.name})")
        raise
    assert callable(getattr(module, test_name, None)), f"{row}: no test {proof}"


def test_every_release_workflow_proof_exists() -> None:
    from pathlib import Path

    workflow = Path(__file__).parents[2] / ".github" / "workflows" / "release.yml"
    text = workflow.read_text(encoding="utf-8")
    assert "ghcr.io" in text, "Server image: the release workflow no longer publishes it"
    assert "attest" in text, "Signed releases: the release workflow no longer attests"
