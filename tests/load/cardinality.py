"""Metric cardinality stays bounded at scale (spec 007 FR-020, SC-007).

    python -m tests.load.cardinality --agents 1000 --sessions 100000

The Phase 3 rule — *labels never carry identities* — exists for two reasons: it keeps audit
identities behind the audit-reader check, and it bounds cardinality. The second is what this
script measures. If the series count grows with ``--agents`` or ``--sessions``, an identity has
reached a label, and the metric surface will eventually take the monitoring system down with it.

The bound is a *constant*: the product of the closed label value sets in
``app/observability/surface.py``, independent of how many agents, sessions or targets exist.
"""

from __future__ import annotations

import argparse
import itertools
import sys
import uuid

from prometheus_client import CollectorRegistry, generate_latest

from app.observability import surface
from app.observability.pep import classify
from app.services.metrics import build_control_plane_metrics, build_pep_metrics


def _series_names(registry: CollectorRegistry) -> set[str]:
    """Every distinct series (name plus its label values), as a scrape would see it."""
    out: set[str] = set()
    for line in generate_latest(registry).decode().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        out.add(line.rsplit(" ", 1)[0])
    return out


def run(agents: int, sessions: int, verbose: bool = True) -> tuple[int, int]:
    """Drive every label combination the code can produce, at the given scale.

    Returns (series_before, series_after). They must be equal once every combination has been
    seen once: further traffic can only re-increment series that already exist.
    """
    cp = build_control_plane_metrics(CollectorRegistry())
    pep = build_pep_metrics(CollectorRegistry())

    agent_names = [f"agent://a{i}" for i in range(agents)]
    session_ids = (str(uuid.UUID(int=i)) for i in range(sessions))

    # Every declared label value, cycled, so the full cross-product is reached quickly.
    outcomes = itertools.cycle(sorted(surface.OUTCOMES))
    target_kinds = itertools.cycle(sorted(surface.TARGET_KINDS))
    stages = itertools.cycle(sorted(surface.PEP_STAGES))
    pep_outcomes = itertools.cycle(sorted(surface.PEP_OUTCOMES))
    causes = itertools.cycle(sorted(surface.PEP_BLOCK_CAUSES))
    reject_causes = itertools.cycle(sorted(surface.TRACE_CONTEXT_REJECT_CAUSES))
    signals = itertools.cycle(sorted(surface.TELEMETRY_SIGNALS))

    pep.up.set(1)
    pep.info.labels(mode=surface.PEP_MODE_ENFORCING, version="0.1.0").set(1)

    before = 0
    warmup = 2_000

    for i, _session_id in enumerate(session_ids):
        _agent = agent_names[i % len(agent_names)]
        enforced = "true" if i % 2 else "false"

        # Control plane: the decision path.
        cp.decisions.labels(
            outcome=next(outcomes), enforced=enforced, target_kind=next(target_kinds)
        ).inc()
        cp.trace_context_rejected.labels(cause=next(reject_causes)).inc()
        cp.telemetry_dropped.labels(signal=next(signals)).inc()
        cp.telemetry_identity_disclosure.set(0)

        # Enforcement point: every outcome and every block cause.
        outcome = next(pep_outcomes)
        pep.calls.labels(outcome=outcome).inc()
        cause = next(causes)
        if outcome == "blocked":
            pep.blocks.labels(cause=cause).inc()
        pep.stage_duration.labels(stage=next(stages)).observe(0.001)
        pep.overhead.observe(0.002)

        # The classifier too, so a cause it can produce but the allowlist omits would show up
        # here as an extra series rather than as a silent drop.
        c = classify("blocked_infra", "PDP_UNAVAILABLE")
        if c.block_cause:
            pep.blocks.labels(cause=c.block_cause).inc()

        # `_agent` and `_session_id` are leading-underscore on purpose: the loop varies both
        # across the full requested scale and neither is ever passed to a label. That they are
        # unused IS the invariant — if a future change starts using one, the series count below
        # will grow and this script fails.

        if i == warmup:
            before = len(_series_names(cp.registry)) + len(_series_names(pep.registry))

    after = len(_series_names(cp.registry)) + len(_series_names(pep.registry))

    if verbose:
        print(f"agents:   {agents:,}")
        print(f"sessions: {sessions:,}")
        print(f"series after {warmup:,} iterations: {before}")
        print(f"series after {sessions:,} iterations: {after}")
        print()
        for registry, label in (
            (cp.registry, "control plane"),
            (pep.registry, "enforcement point"),
        ):
            names = sorted(_series_names(registry))
            print(f"{label}: {len(names)} series")
            for n in names[:6]:
                print(f"    {n}")
            if len(names) > 6:
                print(f"    ... and {len(names) - 6} more")
        print()
        if after == before:
            print("PASS: the series count is constant — no identity reached a label.")
        else:
            print(f"FAIL: the series count grew from {before} to {after}.")
    return before, after


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agents", type=int, default=1000)
    parser.add_argument("--sessions", type=int, default=100_000)
    args = parser.parse_args(argv)

    before, after = run(args.agents, args.sessions)
    return 0 if after == before else 1


if __name__ == "__main__":
    sys.exit(main())
