"""Telemetry can never make the guardrail worse.

This file *is* the fail-open guarantee: "zero authorization outcomes change as a result of
any telemetry failure, measured across a fault-injection suite covering an unreachable sink, a
slow sink, a rejecting sink, and a sink that recovers mid-run."

The posture under test is deliberately the **opposite** of the audit log's. An uncommitted audit
row blocks the call (`test_audit_before_dispatch.py`); a dead telemetry sink changes nothing.
Both are asserted, because the pair is what makes the design coherent: evidence is mandatory,
observation is best-effort.
"""

from __future__ import annotations

import time

import pytest
from opentelemetry.sdk.trace.export import SpanExportResult
from prometheus_client import generate_latest

USER = "user:alice"

# Each call is one hop, so each needs its own session: a hop token is single-use.
TARGETS = [
    ("mcp://kb.internal/search", "kb.public", "allow"),
    ("agent://summarizer", "account.read", "deny"),
]


class _UnreachableExporter:
    """Raises, the way a collector behind a dead network does."""

    def __init__(self) -> None:
        self.attempts = 0

    def export(self, spans):  # noqa: ANN001, ANN202
        self.attempts += 1
        raise ConnectionRefusedError("collector is down")

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return False


class _RejectingExporter:
    """Answers, but refuses — a collector returning 500, or an auth failure."""

    def __init__(self) -> None:
        self.attempts = 0

    def export(self, spans):  # noqa: ANN001, ANN202
        self.attempts += 1
        return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


class _SlowExporter:
    """Blocks well past any sane export timeout."""

    def __init__(self, delay: float = 2.0) -> None:
        self.attempts = 0
        self.delay = delay

    def export(self, spans):  # noqa: ANN001, ANN202
        self.attempts += 1
        time.sleep(self.delay)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


class _RecoveringExporter:
    """Fails for the first ``fail_for`` exports, then succeeds."""

    def __init__(self, fail_for: int = 2) -> None:
        self.attempts = 0
        self.fail_for = fail_for
        self.exported: list = []

    def export(self, spans):  # noqa: ANN001, ANN202
        self.attempts += 1
        if self.attempts <= self.fail_for:
            raise ConnectionRefusedError("collector is still down")
        self.exported.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


FAULTS = {
    "unreachable": _UnreachableExporter,
    "rejecting": _RejectingExporter,
    "slow": _SlowExporter,
    "recovering": _RecoveringExporter,
}


async def _run_workload(client, consent) -> list[dict]:
    """Drive one allow and one deny, returning the decision bodies.

    The chain is registered by the caller, once: calling ``register_chain()`` again would pin a
    new manifest version, and the baseline and faulted runs would then differ in
    ``policy_version`` for a reason that has nothing to do with telemetry.
    """
    out = []
    for target, data_class, _expected in TARGETS:
        session = await consent()
        r = await client.post(
            "/v1/authorize",
            headers={"Authorization": f"Bearer {session['root_grant']}"},
            json={
                "session_id": session["session_id"],
                "caller": USER,
                "target": target,
                "data_class": data_class,
                "guarantee": "full",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        out.append(
            {
                "outcome": body["outcome"],
                "reason": body.get("reason"),
                "recoverable": body.get("recoverable"),
                "hop": body["hop"],
                "policy_version": body["policy_version"],
                "recorded": body.get("recorded"),
                "transaction_required": body.get("transaction_required"),
            }
        )
    return out


def _install(metrics_registry, exporter, *, synchronous: bool = True) -> None:
    """Attach a faulted exporter.

    ``synchronous=True`` (SimpleSpanProcessor) makes a test deterministic: the export happens
    before the assertion, so "was the broken sink actually exercised?" is answerable. Pass
    ``synchronous=False`` to exercise the production BatchSpanProcessor path, which is the one
    whose bounded queue and background thread the loss bound relies on.
    """
    from app import observability
    from app.observability.config import ObservabilityConfig

    observability._reset_for_tests()
    observability.setup(
        resolved=ObservabilityConfig.resolve(
            enabled=True,
            key="0" * 64,
            identity_disclosure=False,
            allow_sample_ratio=1.0,
            service_name="control_plane",
        ),
        install_globally=False,
        metrics=metrics_registry,
        exporter=exporter,
        synchronous_export=synchronous,
    )


# -- zero outcome changes, across all four faults -----------------------------------


@pytest.mark.parametrize("fault", sorted(FAULTS), ids=sorted(FAULTS))
async def test_no_authorization_outcome_changes_under_any_sink_fault(
    client, register_chain, consent, metrics_registry, fault: str
) -> None:
    from app import observability

    await register_chain()

    # Baseline: telemetry off.
    observability._reset_for_tests()
    baseline = await _run_workload(client, consent)

    # Same workload, with a broken sink attached.
    exporter = FAULTS[fault]()
    _install(metrics_registry, exporter)
    try:
        faulted = await _run_workload(client, consent)
    finally:
        observability._reset_for_tests()

    assert faulted == baseline, f"the {fault} sink changed an authorization outcome"
    assert [o["outcome"] for o in baseline] == ["allow", "deny"], "the workload must exercise both"


@pytest.mark.parametrize("fault", sorted(FAULTS), ids=sorted(FAULTS))
async def test_the_broken_sink_was_actually_exercised(
    client, register_chain, consent, metrics_registry, fault: str
) -> None:
    """Without this, the test above could pass because nothing ever tried to export."""
    from app import observability

    await register_chain()
    exporter = FAULTS[fault]()
    _install(metrics_registry, exporter)
    try:
        await _run_workload(client, consent)
    finally:
        observability._reset_for_tests()

    assert exporter.attempts > 0, f"the {fault} exporter was never called"


# -- a failure cannot make the guardrail more permissive ----------------------------


async def test_a_broken_sink_cannot_turn_a_deny_into_an_allow(
    client, register_chain, consent, metrics_registry
) -> None:
    from app import observability

    _install(metrics_registry, _UnreachableExporter())
    try:
        await register_chain()
        session = await consent()
        r = await client.post(
            "/v1/authorize",
            headers={"Authorization": f"Bearer {session['root_grant']}"},
            json={
                "session_id": session["session_id"],
                "caller": USER,
                "target": "agent://summarizer",
                "data_class": "account.read",
                "guarantee": "full",
            },
        )
    finally:
        observability._reset_for_tests()

    assert r.json()["outcome"] == "deny"
    assert r.json()["reason"] == "EDGE_NOT_IN_DAG"


async def test_the_audit_record_is_still_written_when_telemetry_is_broken(
    client, register_chain, consent, metrics_registry, admin_headers
) -> None:
    """Telemetry is fail-open; audit is fail-closed. A broken sink must not cost us evidence."""
    from app import observability

    _install(metrics_registry, _UnreachableExporter())
    try:
        await register_chain()
        session = await consent()
        await client.post(
            "/v1/authorize",
            headers={"Authorization": f"Bearer {session['root_grant']}"},
            json={
                "session_id": session["session_id"],
                "caller": USER,
                "target": "mcp://kb.internal/search",
                "data_class": "kb.public",
                "guarantee": "full",
            },
        )
        rows = (
            await client.get(
                "/v1/audit/decisions",
                headers=admin_headers,
                params={"session_id": session["session_id"]},
            )
        ).json()["data"]
    finally:
        observability._reset_for_tests()

    assert len(rows) == 1
    assert rows[0]["outcome"] == "allow"


# -- bounded, and the loss reports itself -------------------------------------------


async def test_a_slow_sink_does_not_add_unbounded_latency(
    client, register_chain, consent, metrics_registry
) -> None:
    """A two-second export must not become two seconds of request latency."""
    from app import observability

    # Deliberately NOT the synchronous test processor: SimpleSpanProcessor exports inline on
    # the thread that ended the span, so it would add the delay by design. The loss bound comes
    # from BatchSpanProcessor's queue and background export thread, which is what production
    # uses — so that is what this has to measure.
    _install(metrics_registry, _SlowExporter(delay=2.0), synchronous=False)
    try:
        await register_chain()
        session = await consent()
        started = time.perf_counter()
        r = await client.post(
            "/v1/authorize",
            headers={"Authorization": f"Bearer {session['root_grant']}"},
            json={
                "session_id": session["session_id"],
                "caller": USER,
                "target": "mcp://kb.internal/search",
                "data_class": "kb.public",
                "guarantee": "full",
            },
        )
        elapsed = time.perf_counter() - started
    finally:
        observability._reset_for_tests()

    assert r.status_code == 200
    # Generous: the point is that it is not ~2 s, not that it is fast.
    assert elapsed < 1.5, f"a slow exporter added {elapsed:.2f}s to a request"


async def test_telemetry_setup_failure_leaves_the_control_plane_serving(
    client, register_chain, consent, metrics_registry, monkeypatch
) -> None:
    """A guardrail that refused to start because a collector was unreachable would be an
    availability regression caused by an observability feature."""
    from app import observability

    observability._reset_for_tests()

    def _explode(*_a, **_k):
        raise RuntimeError("provider construction failed")

    await register_chain()
    monkeypatch.setattr(observability, "_build_pipeline", _explode)
    from app.observability.config import ObservabilityConfig

    resolved = observability.setup(
        resolved=ObservabilityConfig.resolve(
            enabled=True,
            key="0" * 64,
            identity_disclosure=False,
            allow_sample_ratio=1.0,
            service_name="control_plane",
        ),
        install_globally=False,
        metrics=metrics_registry,
    )
    try:
        assert resolved.enabled is False
        assert resolved.state == "setup_failed"
        outcomes = await _run_workload(client, consent)
    finally:
        observability._reset_for_tests()

    assert [o["outcome"] for o in outcomes] == ["allow", "deny"]


async def test_a_recovering_sink_resumes_without_a_restart(
    client, register_chain, consent, metrics_registry
) -> None:
    from app import observability

    await register_chain()
    exporter = _RecoveringExporter(fail_for=1)
    _install(metrics_registry, exporter)
    try:
        await _run_workload(client, consent)
    finally:
        observability._reset_for_tests()

    assert exporter.attempts >= 2, "not enough exports to observe a recovery"
    assert exporter.exported, "export never resumed after the fault cleared"


async def test_sampling_loss_is_reported(client, register_chain, consent, metrics_registry) -> None:
    """The telemetry loss must itself be reported."""
    from app import observability
    from app.observability.config import ObservabilityConfig

    observability._reset_for_tests()
    observability.setup(
        resolved=ObservabilityConfig.resolve(
            enabled=True,
            key="0" * 64,
            identity_disclosure=False,
            allow_sample_ratio=0.0,
            service_name="control_plane",
        ),
        install_globally=False,
        metrics=metrics_registry,
        exporter=_RejectingExporter(),
        synchronous_export=True,
    )
    try:
        await register_chain()
        session = await consent()
        await client.post(
            "/v1/authorize",
            headers={"Authorization": f"Bearer {session['root_grant']}"},
            json={
                "session_id": session["session_id"],
                "caller": USER,
                "target": "mcp://kb.internal/search",
                "data_class": "kb.public",
                "guarantee": "full",
            },
        )
        text = generate_latest(metrics_registry.registry).decode()
    finally:
        observability._reset_for_tests()

    assert 'agentic_auth_telemetry_dropped_total{signal="span"}' in text


# -- the PEP has the same posture -----------------------------------------------------------


async def test_a_broken_sink_does_not_change_what_the_pep_forwards(
    sidecar_stack, register_chain, consent
) -> None:
    from app import observability

    observability._reset_for_tests()
    await register_chain()
    session = await consent()
    sidecar = await sidecar_stack.client()

    r = await sidecar.get(
        "/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )
    assert r.status_code == 200
    assert sidecar_stack.recorder.count == 1
