"""Inbound trace context is untrusted input.

A caller-supplied ``traceparent`` arrives from an agent process the integrator may not control.
The conclusion this file is built around:

    **A trace id is never evidence.** The audit record, keyed by ``action_id``, is the evidence.
    The span is a handle that points at it.

So the tests do not try to stop a caller claiming a trace id — it can, and that is a correlation
nuisance rather than a security bypass. They assert the thing that must hold: nothing a caller
sends can change an outcome, a deny reason, an audit row, or a metric label.
"""

from __future__ import annotations

import pytest
from prometheus_client import generate_latest

from app.observability import surface
from app.observability.context import extract_parent
from app.observability.ids import session_trace_id

USER = "user:alice"
KEY = b"k" * 32
SESSION = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
GOOD = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

MALFORMED = [
    "garbage",
    "",
    "00-tooshort-00f067aa0ba902b7-01",
    "00-00000000000000000000000000000000-00f067aa0ba902b7-01",  # all-zero trace id
    "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",  # all-zero span id
    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",  # missing flags
    "../../etc/passwd",
    "00-" + "f" * 200 + "-00f067aa0ba902b7-01",
]


async def _rooted(register_chain, consent):
    await register_chain()
    return await consent()


async def _authorize(
    client, session, *, headers=None, target="mcp://kb.internal/search", data_class="kb.public"
):
    h = {"Authorization": f"Bearer {session['root_grant']}"}
    h.update(headers or {})
    return await client.post(
        "/v1/authorize",
        headers=h,
        json={
            "session_id": session["session_id"],
            "caller": USER,
            "target": target,
            "data_class": data_class,
            "guarantee": "full",
        },
    )


# -- unit level: the resolver itself --------------------------------------------------------


@pytest.mark.parametrize("raw", MALFORMED)
def test_a_malformed_traceparent_falls_back_to_the_session_root(raw: str) -> None:
    from opentelemetry import trace as trace_api

    ctx = extract_parent({"traceparent": raw}, session_id=SESSION, key=KEY)
    got = trace_api.get_current_span(ctx).get_span_context().trace_id
    assert got == session_trace_id(SESSION, KEY), f"{raw!r} was accepted or lost the fallback"


def test_a_future_traceparent_version_is_accepted_by_design() -> None:
    """Not a bug: W3C trace-context requires a parser to accept an unknown *higher* version
    whose prefix it can still read, so that a newer caller interoperates with an older
    service. Asserted explicitly so nobody later "fixes" it into a rejection.

    It is safe for the same reason everything else here is: the trace id is a correlation
    handle, never evidence.
    """
    from opentelemetry import trace as trace_api

    ctx = extract_parent(
        {"traceparent": "99-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
        session_id=SESSION,
        key=KEY,
    )
    got = trace_api.get_current_span(ctx).get_span_context().trace_id
    assert got == 0x4BF92F3577B34DA6A3CE929D0E0E4736
    assert got != session_trace_id(SESSION, KEY)


def test_baggage_is_never_extracted_and_never_propagated() -> None:
    """The SDK default propagator is ``tracecontext,baggage``, and the baggage propagator would
    extract attacker-controlled key/value data and re-inject it into every outbound call."""
    from opentelemetry import baggage

    ctx = extract_parent(
        {"traceparent": GOOD, "baggage": "evil=" + "A" * 9000},
        session_id=SESSION,
        key=KEY,
    )
    assert baggage.get_all(ctx) == {}

    from app.observability.context import inject

    assert "baggage" not in inject({})


def test_tracestate_is_dropped() -> None:
    ctx = extract_parent(
        {"traceparent": GOOD, "tracestate": "vendor=evil,other=1"},
        session_id=SESSION,
        key=KEY,
    )
    from opentelemetry import trace as trace_api

    state = trace_api.get_current_span(ctx).get_span_context().trace_state
    assert len(state) == 0, f"tracestate survived: {state}"


def test_an_oversized_header_cannot_blow_up_the_resolver() -> None:
    ctx = extract_parent({"traceparent": "00-" + "a" * 100_000}, session_id=SESSION, key=KEY)
    from opentelemetry import trace as trace_api

    assert trace_api.get_current_span(ctx).get_span_context().trace_id == session_trace_id(
        SESSION, KEY
    )


# -- integration: nothing inbound can change a decision -------------------------------------


class TestInertness:
    @pytest.mark.parametrize(
        "headers",
        [
            {"traceparent": GOOD},
            {"traceparent": "garbage"},
            {"baggage": "x=" + "A" * 9000},
            {"tracestate": "vendor=evil"},
            {"traceparent": GOOD, "baggage": "outcome=allow"},
        ],
        ids=["valid", "malformed", "huge-baggage", "tracestate", "baggage-claims-allow"],
    )
    async def test_a_denied_hop_is_denied_identically_whatever_the_caller_sends(
        self, client, telemetry, register_chain, consent, admin_headers, headers: dict
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        control = await _authorize(
            client, session, target="agent://summarizer", data_class="account.read"
        )
        hostile = await _authorize(
            client,
            session,
            headers=headers,
            target="agent://summarizer",
            data_class="account.read",
        )

        for r in (control, hostile):
            assert r.status_code == 200
            assert r.json()["outcome"] == "deny"
            assert r.json()["reason"] == "EDGE_NOT_IN_DAG"

        # And the recorded rows agree on everything that matters.
        rows = (
            await client.get(
                "/v1/audit/decisions",
                headers=admin_headers,
                params={"session_id": session["session_id"]},
            )
        ).json()["data"]
        assert len(rows) == 2
        # Everything except the per-row identity and timing must match exactly.
        volatile = {"id", "action_id", "ts", "seq"}
        significant = [{k: v for k, v in row.items() if k not in volatile} for row in rows]
        assert len(significant[0]) >= 15, "the comparison must not be vacuous"
        assert significant[0] == significant[1], "an inbound header changed the audit record"

    async def test_a_claimed_trace_id_does_not_appear_in_the_audit_record(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        await _authorize(client, session, headers={"traceparent": GOOD})

        rows = (
            await client.get(
                "/v1/audit/decisions",
                headers=admin_headers,
                params={"session_id": session["session_id"]},
            )
        ).json()["data"]
        assert "4bf92f3577b34da6a3ce929d0e0e4736" not in str(rows)

    async def test_a_claimed_trace_id_does_not_become_a_metric_label(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        await _authorize(client, session, headers={"traceparent": GOOD})

        text = generate_latest(telemetry.metrics.registry).decode()
        assert "4bf92f3577b34da6a3ce929d0e0e4736" not in text


# -- the rejections are counted, so a deployment can see them --------------------------------


class TestCounters:
    async def test_a_malformed_traceparent_is_counted(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        await _authorize(client, session, headers={"traceparent": "garbage"})

        text = generate_latest(telemetry.metrics.registry).decode()
        assert 'agentic_auth_trace_context_rejected_total{cause="malformed"} 1.0' in text

    async def test_dropped_baggage_is_counted_even_alongside_a_good_traceparent(
        self, client, telemetry, register_chain, consent
    ) -> None:
        """Otherwise a caller could smuggle baggage past the counter by also sending valid
        trace context."""
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        await _authorize(client, session, headers={"traceparent": GOOD, "baggage": "a=1"})

        text = generate_latest(telemetry.metrics.registry).decode()
        assert 'agentic_auth_trace_context_rejected_total{cause="baggage_dropped"} 1.0' in text

    async def test_a_valid_traceparent_is_not_counted_as_a_rejection(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        await _authorize(client, session, headers={"traceparent": GOOD})

        text = generate_latest(telemetry.metrics.registry).decode()
        assert "agentic_auth_trace_context_rejected_total" not in text or (
            'cause="malformed"' not in text and 'cause="absent"' not in text
        )

    async def test_the_reject_causes_are_all_declared_values(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        await _authorize(client, session, headers={"traceparent": "garbage", "baggage": "a=1"})
        await _authorize(client, session)

        text = generate_latest(telemetry.metrics.registry).decode()
        import re

        seen = set(
            re.findall(r'agentic_auth_trace_context_rejected_total\{cause="([^"]+)"\}', text)
        )
        assert seen <= surface.TRACE_CONTEXT_REJECT_CAUSES, seen
