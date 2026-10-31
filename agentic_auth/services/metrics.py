"""Prometheus metrics. The published catalogue is at
https://authzai.dev/reference/telemetry-surface.

**Labels never carry identities.** No agent name, user sub, session id, action id, or target
appears in a label value. That bounds cardinality, and it keeps audit identities behind the
audit-reader check: per-agent breakdowns come from ``GET /v1/audit/decisions``, not from
``/metrics``.

Two metric sets exist. The control plane holds one process-wide set, swappable in tests via
``_current``. ``drift check`` builds a fresh, isolated set per run and writes it to a textfile.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, multiprocess

from agentic_auth import runtime

CHAIN_QUERY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)


@dataclass(frozen=True)
class ControlPlaneMetrics:
    registry: CollectorRegistry
    # outcome=allow|deny, enforced=true|false, target_kind=tool|agent
    decisions: Counter
    # reason=<DenyReason>
    denials: Counter
    # outcome=allow|deny
    audit_write_failures: Counter
    # result=complete|incomplete|not_found
    chain_query_duration: Histogram
    chain_queries: Counter
    # complete=true|false, break=none|<ChainBreak>
    chain_writes: Counter
    # -- Phase 4: transaction tokens, taint, identity --
    # source_class=tool|agent|reported|unknown
    taint_blocks: Counter
    # propagation=self|ancestor|sentinel
    taint_marks: Counter
    # result=minted|not_privileged|already_minted|tainted|invalid_token|too_large
    transaction_mints: Counter
    # outcome=enrolled|quarantined|rejected|key_revoked|idp_unavailable|reconciliation_rejected
    enrollments: Counter
    revocations: Counter
    # where=authorize|exchange
    revoked_hop_refusals: Counter
    # cause=missing|invalid|wrong_agent|not_enrolled
    exchange_pop_failures: Counter
    # -- guarantee levels --------------------------------------------------------
    # The operator view: how much traffic runs below full guarantee.
    decisions_by_guarantee: Counter
    # Non-zero deserves an alert: a degrade is never silent, and this is
    # the signal that it happened.
    guarantee_degrades: Counter
    step_up_challenges: Counter
    step_up_outcomes: Counter
    step_up_resumptions: Counter
    sandbox_runs: Counter
    proposals_ratified: Counter
    # -- Phase 6: the observability layer --
    # The layer observing itself, so telemetry loss and telemetry posture are both visible.
    # cause=malformed|absent|baggage_dropped
    trace_context_rejected: Counter
    # signal=span|log
    telemetry_dropped: Counter
    telemetry_identity_disclosure: Gauge


def build_control_plane_metrics(registry: CollectorRegistry | None = None) -> ControlPlaneMetrics:
    registry = registry if registry is not None else CollectorRegistry()
    return ControlPlaneMetrics(
        registry=registry,
        decisions=Counter(
            "agentic_auth_decisions",
            "Decisions rendered, counted once recorded",
            ["outcome", "enforced", "target_kind"],
            registry=registry,
        ),
        denials=Counter(
            "agentic_auth_denials",
            "Refusals returned to a caller, by reason",
            ["reason"],
            registry=registry,
        ),
        audit_write_failures=Counter(
            "agentic_auth_audit_write_failures",
            "Audit rows that could not be committed; allow means the call was blocked instead",
            ["outcome"],
            registry=registry,
        ),
        chain_query_duration=Histogram(
            "agentic_auth_chain_query_duration_seconds",
            "Delegation-chain query latency",
            ["result"],
            buckets=CHAIN_QUERY_BUCKETS,
            registry=registry,
        ),
        chain_queries=Counter(
            "agentic_auth_chain_queries",
            "Delegation-chain query outcomes",
            ["result"],
            registry=registry,
        ),
        chain_writes=Counter(
            "agentic_auth_chain_writes",
            "Chain completeness decided at write time",
            ["complete", "break"],
            registry=registry,
        ),
        taint_blocks=Counter(
            "agentic_auth_taint_blocks",
            "TAINTED_INTO_PRIVILEGED refusals, by what introduced the taint",
            ["source_class"],
            registry=registry,
        ),
        taint_marks=Counter(
            "agentic_auth_taint_marks",
            "Contexts marked tainted, by how the mark propagated",
            ["propagation"],
            registry=registry,
        ),
        transaction_mints=Counter(
            "agentic_auth_transaction_mints",
            "POST /v1/token/transaction outcomes",
            ["result"],
            registry=registry,
        ),
        enrollments=Counter(
            "agentic_auth_enrollments",
            "Enrollment completions, by outcome",
            ["outcome"],
            registry=registry,
        ),
        revocations=Counter(
            "agentic_auth_revocations",
            "Revocations that changed state",
            registry=registry,
        ),
        revoked_hop_refusals=Counter(
            "agentic_auth_revoked_hop_refusals",
            "Hops refused because an agent on the chain is revoked",
            ["where"],
            registry=registry,
        ),
        exchange_pop_failures=Counter(
            "agentic_auth_exchange_pop_failures",
            "actor_token failures at the exchange, by cause",
            ["cause"],
            registry=registry,
        ),
        decisions_by_guarantee=Counter(
            "agentic_auth_decisions_by_guarantee",
            "Every decision, by the guarantee level the enforcement point reported",
            ["level", "outcome"],
            registry=registry,
        ),
        guarantee_degrades=Counter(
            "agentic_auth_guarantee_degrades",
            "A session's reported guarantee level became weaker",
            ["from_level", "to_level"],
            registry=registry,
        ),
        step_up_challenges=Counter(
            "agentic_auth_step_up_challenges",
            "Step-up challenges raised, by the reason that raised them",
            ["reason"],
            registry=registry,
        ),
        step_up_outcomes=Counter(
            "agentic_auth_step_up_outcomes",
            "approved | declined | expired | replayed | out_of_ceiling",
            ["outcome"],
            registry=registry,
        ),
        step_up_resumptions=Counter(
            "agentic_auth_step_up_resumptions",
            "completed | partial | failed — the denial-UX signal the PRD asks for",
            ["result"],
            registry=registry,
        ),
        sandbox_runs=Counter(
            "agentic_auth_sandbox_runs",
            "Sandbox observation runs, by how they ended",
            ["status"],
            registry=registry,
        ),
        proposals_ratified=Counter(
            "agentic_auth_proposals_ratified",
            "Ratifications, labelled by whether the administrator edited the proposal "
            "first. A high edited rate means the generator is missing things.",
            ["edited"],
            registry=registry,
        ),
        trace_context_rejected=Counter(
            "agentic_auth_trace_context_rejected",
            "Inbound trace context not used, by cause; absent is normal for an agent the "
            "integrator does not control, malformed is a caller bug or an attempt",
            ["cause"],
            registry=registry,
        ),
        telemetry_dropped=Counter(
            "agentic_auth_telemetry_dropped",
            "Signals lost to queue overflow or a failing sink — telemetry loss reporting itself",
            ["signal"],
            registry=registry,
        ),
        telemetry_identity_disclosure=Gauge(
            "agentic_auth_telemetry_identity_disclosure",
            "1 when full identities are exported in traces and logs, 0 when pseudonymous",
            registry=registry,
        ),
    )


_current: ControlPlaneMetrics | None = None


def get_metrics() -> ControlPlaneMetrics:
    instance = runtime.override()
    if instance is not None:
        return instance.metrics
    global _current
    if _current is None:
        _current = build_control_plane_metrics()
    return _current


def exposition_registry() -> CollectorRegistry:
    """What ``/metrics`` serves. With several worker processes, values live in
    ``PROMETHEUS_MULTIPROC_DIR`` and must be collected from there."""
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return registry
    return get_metrics().registry


@dataclass(frozen=True)
class DriftMetrics:
    registry: CollectorRegistry
    # result=pass|drift|error
    checks: Counter
    # verdict=UNDECLARED_TOOL|UNDECLARED_DELEGATION|UNKNOWN_AGENT
    undeclared_edges: Gauge
    observed_edges: Gauge
    unattributed_calls: Gauge


def build_drift_metrics() -> DriftMetrics:
    """A fresh registry per ``drift check`` run, so a textfile holds exactly one run."""
    registry = CollectorRegistry()
    return DriftMetrics(
        registry=registry,
        checks=Counter(
            "agentic_auth_drift_checks", "Drift check runs by result", ["result"], registry=registry
        ),
        undeclared_edges=Gauge(
            "agentic_auth_drift_undeclared_edges",
            "Undeclared edges found in this run",
            ["verdict"],
            registry=registry,
        ),
        observed_edges=Gauge(
            "agentic_auth_drift_observed_edges",
            "Distinct attributed edges in the trace",
            registry=registry,
        ),
        unattributed_calls=Gauge(
            "agentic_auth_drift_unattributed_calls",
            "Calls that could not be attributed to an agent",
            registry=registry,
        ),
    )


@dataclass(frozen=True)
class VerifierMetrics:
    """Emitted by ``agentic_auth.verify.Verifier`` when the integrator supplies a registry.

    Lives here so the metric names have one home, but ``agentic_auth.verify`` must not import this
    module (it would pull in the control plane); the verifier defines the same names itself
    and this class is the documented mirror the tests compare against.
    """

    registry: CollectorRegistry
    # result=admitted|<refusal reason>
    admissions: Counter
    # cause=target_mismatch|params_mismatch|replay|expired|malformed|store_unavailable
    transaction_rejections: Counter
    identity_view_age: Gauge


def build_verifier_metrics(registry: CollectorRegistry | None = None) -> VerifierMetrics:
    registry = registry if registry is not None else CollectorRegistry()
    return VerifierMetrics(
        registry=registry,
        admissions=Counter(
            "agentic_auth_admissions", "admit() outcomes", ["result"], registry=registry
        ),
        transaction_rejections=Counter(
            "agentic_auth_transaction_rejections",
            "Transaction-token rejections by cause",
            ["cause"],
            registry=registry,
        ),
        identity_view_age=Gauge(
            "agentic_auth_identity_view_age_seconds",
            "Seconds since the anchor view was last refreshed",
            registry=registry,
        ),
    )


# ---------------------------------------------------------------------------------------
# Enforcement point
#
# Before this, nothing under agentic_auth/sidecar/ emitted anything: a sidecar that had been
# silently
# forwarding every call looked exactly like a healthy one. These are the series that tell the
# difference.
#
# The same labels-never-carry-identities rule applies. Every label below has a closed,
# enumerable value set (agentic_auth/observability/surface.py), which is what bounds cardinality
# regardless of how many agents, sessions or targets the deployment has.

PEP_STAGE_BUCKETS = CHAIN_QUERY_BUCKETS


@dataclass(frozen=True)
class PepMetrics:
    registry: CollectorRegistry
    # outcome=allowed|blocked|observed_would_block. `observed_would_block` is forwarded but
    # refused on the merits — never folded into `allowed`, or observe mode would read as a
    # working guardrail.
    calls: Counter
    # cause=policy|pdp_unreachable|exchange_unreachable|mint_unreachable|body_too_large|
    #       unresolvable_call
    # The most operationally important series in the layer: `policy` means the guardrail
    # worked, `pdp_unreachable` means it is fail-closing because it is broken. From the
    # agent's side both are just a refused call.
    blocks: Counter
    # stage=decide|exchange|mint|upstream
    stage_duration: Histogram
    # Guardrail-added time = total - upstream. Recorded separately from the stages so the two
    # cross-check: a divergence means unaccounted time inside the PEP.
    overhead: Histogram
    # Always 1 while serving. Liveness is absent() over this, not a value.
    up: Gauge
    # mode=enforcing|observing. Always 1. The unambiguous answer to "is this thing enforcing".
    info: Gauge
    trace_context_rejected: Counter
    telemetry_dropped: Counter
    telemetry_identity_disclosure: Gauge


def build_pep_metrics(registry: CollectorRegistry | None = None) -> PepMetrics:
    """One registry per PEP process, served at ``GET /__agentic/metrics``."""
    registry = registry if registry is not None else CollectorRegistry()
    return PepMetrics(
        registry=registry,
        calls=Counter(
            "agentic_auth_pep_calls",
            "Proxied calls by what the enforcement point did",
            ["outcome"],
            registry=registry,
        ),
        blocks=Counter(
            "agentic_auth_pep_blocks",
            "Blocked calls by cause; separates a policy refusal from the guardrail being unable "
            "to reach policy",
            ["cause"],
            registry=registry,
        ),
        stage_duration=Histogram(
            "agentic_auth_pep_stage_duration_seconds",
            "Per-hop time by stage",
            ["stage"],
            buckets=PEP_STAGE_BUCKETS,
            registry=registry,
        ),
        overhead=Histogram(
            "agentic_auth_pep_overhead_seconds",
            "Time the guardrail added to a call: total minus the upstream call",
            buckets=PEP_STAGE_BUCKETS,
            registry=registry,
        ),
        up=Gauge(
            "agentic_auth_pep_up",
            "1 while this enforcement point is serving",
            registry=registry,
        ),
        info=Gauge(
            "agentic_auth_pep_info",
            "1, labelled with the enforcement mode and version",
            ["mode", "version"],
            registry=registry,
        ),
        trace_context_rejected=Counter(
            "agentic_auth_trace_context_rejected",
            "Inbound trace context not used, by cause",
            ["cause"],
            registry=registry,
        ),
        telemetry_dropped=Counter(
            "agentic_auth_telemetry_dropped",
            "Signals lost to queue overflow or a failing sink",
            ["signal"],
            registry=registry,
        ),
        telemetry_identity_disclosure=Gauge(
            "agentic_auth_telemetry_identity_disclosure",
            "1 when full identities are exported in traces and logs, 0 when pseudonymous",
            registry=registry,
        ),
    )
