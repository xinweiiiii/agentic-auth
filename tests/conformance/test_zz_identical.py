"""Remote and embedded produced the same transcript for every scenario (SC-002).

Named to sort after test_scenarios.py, whose parametrized runs fill ``RESULTS``. The only
field allowed to differ is ``deployment`` (contracts/conformance-suite.md); adding another
needs that contract changed first.
"""

from __future__ import annotations

import pytest

from tests.conformance.transcript import RESULTS, strip_allowed

pytestmark = pytest.mark.conformance

SCENARIOS = [
    "test_s01_three_hop_allow",
    "test_s02_out_of_scope",
    "test_s03_hop_budget_exceeded",
    "test_s04_edge_not_in_dag",
    "test_s05_tainted_into_privileged",
    "test_s06_step_up_lets_the_blocked_hop_finish",
    "test_s07_transaction_token_is_bound_to_its_params",
    "test_s08_revocation_mid_chain",
    "test_s09_identity_without_a_grant_is_not_admitted",
    "test_s10_chain_query_reaches_the_consenting_human",
    "test_s11_audit_rows_are_append_only",
    "test_s12_reconciliation_rejects_with_a_diff",
]


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_transcripts_identical(scenario: str) -> None:
    runs = RESULTS.get(scenario, {})
    if set(runs) != {"remote", "embedded"}:
        pytest.skip(f"{scenario} did not run under both deployments ({sorted(runs)})")
    assert strip_allowed(runs["embedded"]) == strip_allowed(runs["remote"])


def test_the_only_difference_is_the_deployment_label() -> None:
    """Not vacuous: where a transcript records audit rows, the label really differs."""
    labelled = [
        (s, runs)
        for s, runs in RESULTS.items()
        if set(runs) == {"remote", "embedded"} and "deployment" in str(runs["remote"])
    ]
    if not labelled:
        pytest.skip("no scenario with audit rows ran under both deployments")
    for _, runs in labelled:
        assert "'deployment': 'server'" in str(runs["remote"])
        assert "'deployment': 'embedded'" in str(runs["embedded"])
