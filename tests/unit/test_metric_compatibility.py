"""Published metric names and labels survive this phase unchanged.

The Phase 3 and Phase 4 metric surfaces are documented contracts that integrators have already
built dashboards and alerts against. This file pins every name **and its exact label set**.

The label set matters as much as the name. Adding a label to an existing family is a breaking
change wearing an additive costume: `sum by (outcome) (rate(agentic_auth_decisions_total[5m]))`
keeps working, but `agentic_auth_decisions_total{outcome="deny"}` silently stops matching
anything. So a new dimension goes in a new family, never onto an old one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from agentic_auth.services.metrics import (
    build_control_plane_metrics,
    build_drift_metrics,
    build_pep_metrics,
    build_verifier_metrics,
)

CONTRACTS = Path(__file__).resolve().parents[2] / "docs" / "contracts" / "metrics"

# ---------------------------------------------------------------------------------------
# The frozen contract, as published at https://authzai.dev/reference/telemetry-surface.
# Nothing in this table may change. New families belong in NEW_FAMILIES below.
# ---------------------------------------------------------------------------------------

# Kept per originating contract, because the documentation check below asserts each family is
# still named in the document that published it — they are two separate contracts with two
# separate audiences.
PHASE_3_CONTROL_PLANE: dict[str, tuple[str, ...]] = {
    "agentic_auth_decisions": ("outcome", "enforced", "target_kind"),
    "agentic_auth_denials": ("reason",),
    "agentic_auth_audit_write_failures": ("outcome",),
    "agentic_auth_chain_query_duration_seconds": ("result",),
    "agentic_auth_chain_queries": ("result",),
    "agentic_auth_chain_writes": ("complete", "break"),
}

PHASE_4_CONTROL_PLANE: dict[str, tuple[str, ...]] = {
    "agentic_auth_taint_blocks": ("source_class",),
    "agentic_auth_taint_marks": ("propagation",),
    "agentic_auth_transaction_mints": ("result",),
    "agentic_auth_enrollments": ("outcome",),
    "agentic_auth_revocations": (),
    "agentic_auth_revoked_hop_refusals": ("where",),
    "agentic_auth_exchange_pop_failures": ("cause",),
}

# Phase 5. Frozen here for the same reason as the others: once published, a label
# change on any of these silently breaks an exact-match query.
PHASE_5_CONTROL_PLANE: dict[str, tuple[str, ...]] = {
    "agentic_auth_decisions_by_guarantee": ("level", "outcome"),
    "agentic_auth_guarantee_degrades": ("from_level", "to_level"),
    "agentic_auth_step_up_challenges": ("reason",),
    "agentic_auth_step_up_outcomes": ("outcome",),
    "agentic_auth_step_up_resumptions": ("result",),
    "agentic_auth_sandbox_runs": ("status",),
    "agentic_auth_proposals_ratified": ("edited",),
}

PHASE_3_4_CONTROL_PLANE: dict[str, tuple[str, ...]] = {
    **PHASE_3_CONTROL_PLANE,
    **PHASE_4_CONTROL_PLANE,
    **PHASE_5_CONTROL_PLANE,
}

PHASE_3_DRIFT: dict[str, tuple[str, ...]] = {
    "agentic_auth_drift_checks": ("result",),
    "agentic_auth_drift_undeclared_edges": ("verdict",),
    "agentic_auth_drift_observed_edges": (),
    "agentic_auth_drift_unattributed_calls": (),
}

PHASE_4_VERIFIER: dict[str, tuple[str, ...]] = {
    "agentic_auth_admissions": ("result",),
    "agentic_auth_transaction_rejections": ("cause",),
    "agentic_auth_identity_view_age_seconds": (),
}

# Added by this phase. Listed so the test can distinguish "new" from "changed" and assert the
# two sets do not overlap.
NEW_FAMILIES: frozenset[str] = frozenset(
    {
        "agentic_auth_pep_calls",
        "agentic_auth_pep_blocks",
        "agentic_auth_pep_stage_duration_seconds",
        "agentic_auth_pep_overhead_seconds",
        "agentic_auth_pep_up",
        "agentic_auth_pep_info",
        "agentic_auth_trace_context_rejected",
        "agentic_auth_telemetry_dropped",
        "agentic_auth_telemetry_identity_disclosure",
    }
)


def _families(registry: CollectorRegistry) -> dict[str, tuple[str, ...]]:
    """Family name -> label names, as the registry actually describes itself."""
    out: dict[str, tuple[str, ...]] = {}
    for metric in registry.collect():
        out[metric.name] = tuple(sorted(metric.samples[0].labels)) if metric.samples else ()
    return out


def _declared(registry: CollectorRegistry) -> dict[str, tuple[str, ...]]:
    """Label names from the collector definitions, so a family with no observations yet is
    still checked. ``collect()`` alone cannot see the labels of an unused counter."""
    out: dict[str, tuple[str, ...]] = {}
    for collector in list(registry._collector_to_names):  # noqa: SLF001
        name = getattr(collector, "_name", None)
        if name:
            out[name] = tuple(sorted(getattr(collector, "_labelnames", ()) or ()))
    return out


# -- existence and label sets ---------------------------------------------------------------


@pytest.mark.parametrize(("name", "labels"), sorted(PHASE_3_4_CONTROL_PLANE.items()))
def test_control_plane_family_is_unchanged(name: str, labels: tuple[str, ...]) -> None:
    declared = _declared(build_control_plane_metrics().registry)
    assert name in declared, f"{name} has disappeared from the control-plane registry"
    assert declared[name] == tuple(sorted(labels)), (
        f"{name} labels changed: {declared[name]} != {tuple(sorted(labels))}. "
        "Adding a label to a published family silently breaks every exact-match query."
    )


@pytest.mark.parametrize(("name", "labels"), sorted(PHASE_3_DRIFT.items()))
def test_drift_family_is_unchanged(name: str, labels: tuple[str, ...]) -> None:
    declared = _declared(build_drift_metrics().registry)
    assert name in declared
    assert declared[name] == tuple(sorted(labels))


@pytest.mark.parametrize(("name", "labels"), sorted(PHASE_4_VERIFIER.items()))
def test_verifier_family_is_unchanged(name: str, labels: tuple[str, ...]) -> None:
    declared = _declared(build_verifier_metrics().registry)
    assert name in declared
    assert declared[name] == tuple(sorted(labels))


# -- additions are additions ----------------------------------------------------------------


def test_this_phase_added_only_new_families() -> None:
    """Every family in the control-plane registry is either in the frozen contract or in the
    declared new set. A family that is in neither was added without being documented."""
    declared = set(_declared(build_control_plane_metrics().registry))
    known = set(PHASE_3_4_CONTROL_PLANE) | NEW_FAMILIES
    assert declared <= known, f"undocumented metric families: {sorted(declared - known)}"


def test_new_families_do_not_collide_with_published_ones() -> None:
    assert not (NEW_FAMILIES & set(PHASE_3_4_CONTROL_PLANE))
    assert not (NEW_FAMILIES & set(PHASE_3_DRIFT))
    assert not (NEW_FAMILIES & set(PHASE_4_VERIFIER))


def test_the_new_families_match_the_surface_contract() -> None:
    from agentic_auth.observability import surface

    assert NEW_FAMILIES == surface.NEW_METRIC_NAMES, (
        "this test and agentic_auth/observability/surface.py disagree about what was added"
    )


# -- the contract documents still say what this test says -----------------------------------


@pytest.mark.parametrize(
    ("contract", "families"),
    [
        ("phase3.md", PHASE_3_CONTROL_PLANE),
        ("phase3.md", PHASE_3_DRIFT),
        ("phase4.md", PHASE_4_CONTROL_PLANE),
        ("phase4.md", PHASE_4_VERIFIER),
        ("phase5.md", PHASE_5_CONTROL_PLANE),
    ],
    ids=[
        "phase3-control-plane",
        "phase3-drift",
        "phase4-control-plane",
        "phase4-verifier",
        "phase5-control-plane",
    ],
)
def test_the_phase_contracts_still_name_every_family(
    contract: str, families: dict[str, tuple[str, ...]]
) -> None:
    """Guards against the opposite drift: someone deletes a metric and tidies the contract to
    match, leaving this test as the only objector."""
    path = CONTRACTS / contract
    assert path.exists(), f"the frozen metric contract is missing at {path}"
    text = path.read_text()
    for name in families:
        assert name in text, f"{name} is no longer documented in {contract}"


# -- exposition sanity ----------------------------------------------------------------------


def test_the_exposition_still_parses_with_the_new_families() -> None:
    m = build_control_plane_metrics()
    m.decisions.labels(outcome="allow", enforced="true", target_kind="tool").inc()
    m.trace_context_rejected.labels(cause="absent").inc()
    m.telemetry_identity_disclosure.set(0)
    text = generate_latest(m.registry).decode()

    assert (
        'agentic_auth_decisions_total{enforced="true",outcome="allow",target_kind="tool"} 1.0'
        in text
    )
    assert "agentic_auth_telemetry_identity_disclosure 0.0" in text


def test_no_metric_name_or_help_text_carries_an_identity() -> None:
    """Names and help strings are exported too, so a well-meaning example in a docstring would
    leak just as surely as a label."""
    for build in (build_control_plane_metrics, build_pep_metrics, build_verifier_metrics):
        text = generate_latest(build().registry).decode()
        assert "agent://" not in text
        assert "user:" not in text
        assert not re.search(r"\b[0-9a-f]{8}-[0-9a-f]{4}-", text), "a UUID appears in the surface"
