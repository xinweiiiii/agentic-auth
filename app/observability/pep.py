"""Enforcement-point telemetry: the registry, the two routes, and the outcome mapping.

Before this module, nothing under ``app/sidecar/`` emitted anything. The sidecar is the
component that actually blocks calls, fail-closes when the control plane is unreachable, and
runs in observe mode — so a sidecar that had been silently forwarding every call looked exactly
like a healthy one. These are the series that tell the difference.

The mapping in :func:`classify` is the heart of it. ``enforce()`` has around twenty return
paths, but every one of them already produces an :class:`~app.sidecar.enforce.EdgeAttribution`
with an outcome and a reason — so one mapping covers them all, rather than twenty call sites
each remembering to increment the right counter. The classification reuses the codebase's own
``POLICY_REASONS`` / ``INFRASTRUCTURE_REASONS`` split, which is already exactly the FR-005
distinction, instead of inventing a parallel one that could disagree with it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.observability import surface
from app.schemas.authorize import INFRASTRUCTURE_REASONS, POLICY_REASONS, DenyReason

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.services.metrics import PepMetrics

# EdgeAttribution.outcome values, from app/sidecar/enforce.py.
EDGE_ALLOW = "allow"
EDGE_DENY = "deny"
EDGE_OBSERVED = "observed"
EDGE_BLOCKED_INFRA = "blocked_infra"
EDGE_BLOCKED_LOCAL = "blocked_local"

# Sidecar-local refusal codes (app/sidecar/deny.py) -> block cause. These are the caller's
# problem or a configuration problem, never a guardrail outage, so none of them is in
# PEP_INFRA_BLOCK_CAUSES and none of them pages.
_LOCAL_CAUSES = {
    "UPSTREAM_NOT_MAPPED": "unresolvable_call",
    "TARGET_NOT_RESOLVED": "unresolvable_call",
    "UNAUTHORIZED": "unauthorized",
    "BODY_TOO_LARGE_TO_BIND": "body_too_large",
    "PARAMS_NOT_AN_OBJECT": "unbindable",
    "TRANSACTION_SERVICE_UNAVAILABLE": "mint_unreachable",
}

# Infrastructure DenyReason -> block cause. Each names which dependency failed, because
# "the guardrail is broken" is only actionable if it says which part.
_INFRA_CAUSES = {
    DenyReason.PDP_UNAVAILABLE.value: "pdp_unreachable",
    DenyReason.TOKEN_SERVICE_UNAVAILABLE.value: "exchange_unreachable",
    DenyReason.AUDIT_UNAVAILABLE.value: "audit_unavailable",
}

_POLICY_REASON_VALUES = frozenset(r.value for r in POLICY_REASONS)
_INFRA_REASON_VALUES = frozenset(r.value for r in INFRASTRUCTURE_REASONS)


@dataclass(frozen=True)
class Classification:
    """What one proxied call was, in telemetry terms."""

    outcome: str
    block_cause: str | None

    @property
    def is_infra_failure(self) -> bool:
        """The guardrail refused because it could not do its job, not because policy said no.
        This is the distinction FR-005 exists for."""
        return self.block_cause in surface.PEP_INFRA_BLOCK_CAUSES


def classify(edge_outcome: str, reason: str | None) -> Classification:
    """Map an ``EdgeAttribution`` to a PEP outcome and block cause.

    Unrecognised inputs fall through to ``other`` rather than being dropped: a path nobody
    mapped should show up as an odd label value on a dashboard, not as a call that never
    happened.
    """
    if edge_outcome == EDGE_ALLOW:
        return Classification("allowed", None)

    if edge_outcome == EDGE_OBSERVED:
        # Forwarded, but refused on the merits. Never folded into `allowed`, or observe mode
        # would read as a working guardrail; never into `blocked`, or it would overstate what
        # the enforcement point actually did.
        return Classification("observed_would_block", "policy")

    if edge_outcome == EDGE_DENY:
        # A policy verdict. `deny` is only ever constructed for POLICY_REASONS in enforce(),
        # but the reason is checked rather than assumed, so a future change that routes an
        # infrastructure reason here is visible instead of mislabelled as policy.
        if reason in _INFRA_REASON_VALUES:
            return Classification("blocked", _INFRA_CAUSES[reason])
        if reason in _POLICY_REASON_VALUES:
            return Classification("blocked", "policy")
        return Classification("blocked", _LOCAL_CAUSES.get(reason or "", "other"))

    if edge_outcome == EDGE_BLOCKED_INFRA:
        cause = _INFRA_CAUSES.get(reason or "") or _LOCAL_CAUSES.get(reason or "")
        return Classification("blocked", cause or "other")

    if edge_outcome == EDGE_BLOCKED_LOCAL:
        return Classification("blocked", _LOCAL_CAUSES.get(reason or "", "other"))

    return Classification("blocked", "other")


class StageTimer:
    """Accumulates per-stage durations for one proxied call.

    Overhead is reported as *total minus upstream* rather than as a separately accumulated
    number, so the two can be cross-checked: if ``overhead`` stops tracking the sum of the
    non-upstream stages, there is unaccounted time inside the enforcement point.
    """

    __slots__ = ("_metrics", "_stages", "_started")

    def __init__(self, metrics: PepMetrics | None) -> None:
        self._metrics = metrics
        self._stages: dict[str, float] = {}
        self._started = time.perf_counter()

    def stage(self, name: str) -> _StageContext:
        return _StageContext(self, name)

    def _record(self, name: str, seconds: float) -> None:
        self._stages[name] = self._stages.get(name, 0.0) + seconds
        if self._metrics is not None and name in surface.PEP_STAGES:
            self._metrics.stage_duration.labels(stage=name).observe(seconds)

    def finish(self) -> None:
        """Record the guardrail's own added time. Called once, after the call completes."""
        if self._metrics is None:
            return
        total = time.perf_counter() - self._started
        overhead = total - self._stages.get("upstream", 0.0)
        self._metrics.overhead.observe(max(0.0, overhead))

    @property
    def stages(self) -> dict[str, float]:
        return dict(self._stages)


class _StageContext:
    __slots__ = ("_name", "_started", "_timer")

    def __init__(self, timer: StageTimer, name: str) -> None:
        self._timer = timer
        self._name = name

    def __enter__(self) -> _StageContext:
        self._started = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> None:
        # Recorded even when the stage raised: an unreachable control plane is exactly the
        # latency an operator needs to see, and dropping it would make an outage look fast.
        self._timer._record(self._name, time.perf_counter() - self._started)


def record(metrics: PepMetrics | None, classification: Classification) -> None:
    """Increment the call and block counters for one proxied call."""
    if metrics is None:
        return
    metrics.calls.labels(outcome=classification.outcome).inc()
    if classification.block_cause is not None and classification.outcome == "blocked":
        metrics.blocks.labels(cause=classification.block_cause).inc()
