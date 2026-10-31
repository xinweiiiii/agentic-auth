"""Gateway metrics — see ``contracts/metrics.md`` §2.

A separate registry from the control plane's, because the gateway is a separate
deployment with its own ``/metrics``. Names still share the ``agentic_auth_`` prefix so
one scrape config finds both.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Histogram


@dataclass(frozen=True)
class GatewayMetrics:
    decisions: Counter
    # Every increment here is a REFUSED call: past the deadline, the gateway does not
    # retry, because a slow decision is no decision (FR-003).
    deadline_exceeded: Counter
    # A spike usually means a route table that has drifted from the agents it serves.
    route_misses: Counter
    # Did the agent supply verifying identity headers? With identity_required on, `false`
    # means the call was refused; it is also what decides whether this gateway may report
    # `full` (research.md R2).
    identity_relayed: Counter
    upstream_latency: Histogram


def build_gateway_metrics(registry: CollectorRegistry | None = None) -> GatewayMetrics:
    kwargs: dict[str, Any] = {"registry": registry} if registry is not None else {}
    return GatewayMetrics(
        decisions=Counter(
            "agentic_auth_gateway_decisions",
            "Decisions made at the shared gateway",
            ["outcome", "reason"],
            **kwargs,
        ),
        deadline_exceeded=Counter(
            "agentic_auth_gateway_deadline_exceeded",
            "Decisions abandoned past the deadline. Every one is a refused call.",
            **kwargs,
        ),
        route_misses=Counter(
            "agentic_auth_gateway_route_misses",
            "Requests with no matching route-table entry",
            **kwargs,
        ),
        identity_relayed=Counter(
            "agentic_auth_gateway_identity_relayed",
            "Whether the agent supplied identity headers for the gateway to relay",
            ["present"],
            **kwargs,
        ),
        upstream_latency=Histogram(
            "agentic_auth_gateway_upstream_latency_seconds",
            "Request in to response out, for the p95 budget",
            **kwargs,
        ),
    )


_METRICS: GatewayMetrics | None = None


def get_gateway_metrics() -> GatewayMetrics:
    global _METRICS
    if _METRICS is None:
        _METRICS = build_gateway_metrics()
    return _METRICS


def reset_gateway_metrics(metrics: GatewayMetrics | None = None) -> None:
    """Tests build their own registry; a module-level singleton would leak counts across
    them and make an assertion on a known mix depend on test order."""
    global _METRICS
    _METRICS = metrics


__all__ = [
    "GatewayMetrics",
    "build_gateway_metrics",
    "get_gateway_metrics",
    "reset_gateway_metrics",
]
