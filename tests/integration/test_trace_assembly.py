"""US2 — one blocked call, followed end to end (spec 007 FR-007..FR-016, SC-001, SC-002).

The workflow this exists for: an agent task fails, and an engineer needs the decision that
refused it, the reason, and the delegation chain — without correlating timestamps by hand.

Everything here asserts on what was actually exported, via an in-memory exporter, rather than
on what the code intended to export.
"""

from __future__ import annotations

import pytest

from app.observability import surface
from app.observability.ids import session_trace_id

USER = "user:alice"
GOOD_TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
CALLER_TRACE_ID = 0x4BF92F3577B34DA6A3CE929D0E0E4736

DENIED = {
    "X-Agentic-Target": "agent://summarizer",
    "X-Agentic-Data-Class": "account.read",
}


async def _rooted(register_chain, consent):
    await register_chain()
    return await consent()


async def _authorize(client, session, token, **overrides):
    payload = {
        "session_id": session["session_id"],
        "caller": USER,
        "target": "mcp://kb.internal/search",
        "data_class": "kb.public",
        "guarantee": "full",
    }
    payload.update(overrides)
    headers = {"Authorization": f"Bearer {token}"}
    headers.update(overrides.pop("_headers", {}) if "_headers" in overrides else {})
    return await client.post("/v1/authorize", headers=headers, json=payload)


# -- FR-009: a caller's trace context is honoured -------------------------------------------


class TestWithInboundContext:
    async def test_the_decision_joins_the_callers_trace(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        r = await client.post(
            "/v1/authorize",
            headers={
                "Authorization": f"Bearer {session['root_grant']}",
                "traceparent": GOOD_TRACEPARENT,
            },
            json={
                "session_id": session["session_id"],
                "caller": USER,
                "target": "mcp://kb.internal/search",
                "data_class": "kb.public",
                "guarantee": "full",
            },
        )
        assert r.status_code == 200, r.text

        spans = telemetry.named(surface.SPAN_DECIDE)
        assert len(spans) == 1
        assert spans[0].context.trace_id == CALLER_TRACE_ID
        assert spans[0].parent is not None
        assert spans[0].parent.span_id == 0x00F067AA0BA902B7

    async def test_every_hop_of_a_chain_lands_in_one_trace(
        self, client, telemetry, register_chain, consent
    ) -> None:
        """FR-009's "preserving hop order across the whole chain"."""
        telemetry.enable()
        session = await _rooted(register_chain, consent)
        headers = {
            "Authorization": f"Bearer {session['root_grant']}",
            "traceparent": GOOD_TRACEPARENT,
        }

        await client.post(
            "/v1/authorize",
            headers=headers,
            json={
                "session_id": session["session_id"],
                "caller": USER,
                "target": "mcp://kb.internal/search",
                "data_class": "kb.public",
                "guarantee": "full",
            },
        )
        await client.post(
            "/v1/authorize",
            headers=headers,
            json={
                "session_id": session["session_id"],
                "caller": USER,
                "target": "agent://kb-search",
                "data_class": "kb.internal",
                "guarantee": "full",
            },
        )

        spans = telemetry.named(surface.SPAN_DECIDE)
        assert len(spans) == 2
        assert {s.context.trace_id for s in spans} == {CALLER_TRACE_ID}
        assert [s.attributes[surface.ATTR_HOP] for s in spans] == sorted(
            s.attributes[surface.ATTR_HOP] for s in spans
        )


# -- FR-007, FR-008, SC-002: the denying span carries the handle -----------------------------


class TestADeniedHop:
    async def test_the_denying_span_carries_the_reason_and_the_action_id(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

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
        assert r.json()["outcome"] == "deny"

        (span,) = telemetry.named(surface.SPAN_DECIDE)
        a = span.attributes
        assert a[surface.ATTR_OUTCOME] == "deny"
        assert a[surface.ATTR_DENY_REASON] == "EDGE_NOT_IN_DAG"
        assert a[surface.ATTR_RECOVERABLE] is False
        assert a[surface.ATTR_ENFORCED] is True
        assert a[surface.ATTR_HOP] >= 1
        assert a[surface.ATTR_POLICY_VERSION] >= 1
        assert a[surface.ATTR_ACTION_ID], "FR-008: the handle must be present"

    async def test_the_action_id_resolves_the_delegation_chain(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        """SC-001/SC-002 end to end: span -> action id -> the verified chain. This is the step
        that makes telemetry a pointer into the audit record rather than a second copy of it."""
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        await client.post(
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
        (span,) = telemetry.named(surface.SPAN_DECIDE)
        action_id = span.attributes[surface.ATTR_ACTION_ID]

        chain = await client.get(f"/v1/audit/actions/{action_id}/chain", headers=admin_headers)
        assert chain.status_code == 200, chain.text
        body = chain.json()
        assert str(body["action_id"]) == action_id
        assert body["chain"], "the span's action id did not resolve to a chain"
        # Back to the consenting human, which is the point of the chain query (FR-019).
        assert body["root_consent"]["user_sub"] == USER, body["root_consent"]
        assert str(body["root_consent"]["session_id"]) == str(session["session_id"])

    async def test_every_decision_is_discoverable(
        self, client, telemetry, register_chain, consent
    ) -> None:
        """SC-002: 100% of decisions, allow and deny, carry a chain-resolving identifier."""
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        for target, data_class in [
            ("mcp://kb.internal/search", "kb.public"),
            ("agent://summarizer", "account.read"),
        ]:
            await client.post(
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

        spans = telemetry.named(surface.SPAN_DECIDE)
        assert len(spans) == 2
        for span in spans:
            assert span.attributes.get(surface.ATTR_ACTION_ID), span.attributes

    async def test_a_deny_reason_is_present_exactly_when_the_outcome_is_deny(
        self, client, telemetry, register_chain, consent
    ) -> None:
        """Mirrors the ck_audit_decisions_reason_iff_deny database constraint, so a span and
        its row can never disagree about whether a reason exists."""
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        for target, data_class in [
            ("mcp://kb.internal/search", "kb.public"),
            ("agent://summarizer", "account.read"),
        ]:
            await client.post(
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

        for span in telemetry.named(surface.SPAN_DECIDE):
            has_reason = surface.ATTR_DENY_REASON in span.attributes
            is_deny = span.attributes[surface.ATTR_OUTCOME] == "deny"
            assert has_reason == is_deny, span.attributes


# -- FR-023: pseudonymous by default --------------------------------------------------------


class TestIdentityDisclosure:
    async def test_no_identity_appears_with_disclosure_off(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

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

        for span in telemetry.spans():
            rendered = repr(dict(span.attributes))
            assert surface.ATTR_AGENT not in span.attributes
            assert surface.ATTR_ACT_CHAIN not in span.attributes
            assert surface.ATTR_TAINT_SOURCE not in span.attributes
            assert "agent://" not in rendered, rendered
            assert USER not in rendered, rendered

    async def test_plaintext_appears_only_with_the_opt_in(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable(identity_disclosure=True)
        session = await _rooted(register_chain, consent)

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

        (span,) = telemetry.named(surface.SPAN_DECIDE)
        assert surface.ATTR_ACT_CHAIN in span.attributes
        # Never both spellings of one identity.
        assert surface.ATTR_ACT_CHAIN_REF not in span.attributes
        assert surface.ATTR_AGENT_REF not in span.attributes


# -- FR-010: one chain, one trace, with an uncooperative caller -----------------------------


class TestWithoutInboundContext:
    async def test_decisions_in_one_session_share_the_session_derived_root(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        for target, data_class in [
            ("mcp://kb.internal/search", "kb.public"),
            ("agent://kb-search", "kb.internal"),
        ]:
            await client.post(
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

        spans = telemetry.named(surface.SPAN_DECIDE)
        assert len(spans) == 2
        expected = session_trace_id(str(session["session_id"]), telemetry.key)
        assert {s.context.trace_id for s in spans} == {expected}, (
            "both decisions must land in the trace derived from the session, with nothing "
            "passed between the processes that produced them"
        )

    async def test_an_absent_traceparent_is_counted_but_is_not_an_error(
        self, client, telemetry, register_chain, consent
    ) -> None:
        """`absent` is normal for an agent the integrator does not control."""
        telemetry.enable()
        session = await _rooted(register_chain, consent)

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

        from prometheus_client import generate_latest

        text = generate_latest(telemetry.metrics.registry).decode()
        assert 'agentic_auth_trace_context_rejected_total{cause="absent"} 1.0' in text

    async def test_different_sessions_are_different_traces(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable()
        await register_chain()
        first = await consent()
        second = await consent()

        for session in (first, second):
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

        traces = {s.context.trace_id for s in telemetry.named(surface.SPAN_DECIDE)}
        assert len(traces) == 2


# -- FR-021: sampling never loses a refusal -------------------------------------------------


class TestSampling:
    async def test_a_refusal_survives_zero_ratio_sampling(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable(allow_sample_ratio=0.0)
        session = await _rooted(register_chain, consent)

        await client.post(
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

        spans = telemetry.named(surface.SPAN_DECIDE)
        assert len(spans) == 1, "a deny was dropped by sampling"
        assert spans[0].attributes[surface.ATTR_OUTCOME] == "deny"

    async def test_an_allow_is_dropped_at_zero_ratio(
        self, client, telemetry, register_chain, consent
    ) -> None:
        telemetry.enable(allow_sample_ratio=0.0)
        session = await _rooted(register_chain, consent)

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
        assert r.json()["outcome"] == "allow"
        assert telemetry.named(surface.SPAN_DECIDE) == []

    async def test_a_sampling_drop_is_reported_as_telemetry_loss(
        self, client, telemetry, register_chain, consent
    ) -> None:
        """FR-018: the layer admits its own gaps."""
        telemetry.enable(allow_sample_ratio=0.0)
        session = await _rooted(register_chain, consent)

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

        from prometheus_client import generate_latest

        text = generate_latest(telemetry.metrics.registry).decode()
        assert 'agentic_auth_telemetry_dropped_total{signal="span"} 1.0' in text


# -- FR-014..FR-016: structured, joinable logs ----------------------------------------------


class TestStructuredLogs:
    async def test_an_operational_failure_is_joinable_to_its_session(
        self, client, telemetry, register_chain, consent, monkeypatch
    ) -> None:
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        # An uncommitted audit row, which is the single most important operational record in
        # the system: it means a call was refused for lack of evidence. (The taint-store path
        # only logs for a *protected* target, which needs an agent-held token — a narrower
        # setup for a less important record.)
        from app.services.audit import AuditService

        async def _boom(self, db):  # noqa: ANN001
            raise RuntimeError("commit refused")

        monkeypatch.setattr(AuditService, "_commit", _boom)

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

        records = [r for r in telemetry.logs() if "audit record failed" in str(r.log_record.body)]
        assert records, "the audit failure was not logged"
        attrs = records[0].log_record.attributes
        assert attrs.get(surface.LOG_COMPONENT) == surface.COMPONENT_CONTROL_PLANE
        assert attrs.get(surface.ATTR_SESSION_ID) == str(session["session_id"])
        assert attrs.get(surface.ATTR_ERROR_TYPE) == "RuntimeError"
        assert attrs.get(surface.ATTR_HOP) == 1

    async def test_no_log_record_carries_a_stack_trace(
        self, client, telemetry, register_chain, consent, monkeypatch
    ) -> None:
        """FR-019. A traceback through token verification can carry a token fragment, so the
        dispatch path records `error.type` and loses the trace."""
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        from app.services.audit import AuditService

        async def _boom(self, db):  # noqa: ANN001
            raise RuntimeError("a token fragment eyJhbGciOiJFZERTQSJ9 in the message")

        monkeypatch.setattr(AuditService, "_commit", _boom)

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

        assert telemetry.logs(), "nothing was logged, so this assertion would be vacuous"
        for record in telemetry.logs():
            attrs = record.log_record.attributes or {}
            assert "exception.stacktrace" not in attrs, attrs
            assert "exception.message" not in attrs, attrs
            assert "eyJhbGciOiJFZERTQSJ9" not in repr(attrs), "a token fragment was exported"
            assert "eyJhbGciOiJFZERTQSJ9" not in str(record.log_record.body)

    async def test_a_routine_deny_is_not_logged_as_an_error(
        self, client, telemetry, register_chain, consent
    ) -> None:
        """FR-016. A policy refusal is the guardrail working; paging on it would cry wolf."""
        telemetry.enable()
        session = await _rooted(register_chain, consent)

        await client.post(
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

        severities = {
            r.log_record.severity_text
            for r in telemetry.logs()
            if (r.log_record.attributes or {}).get(surface.LOG_COMPONENT)
        }
        assert "ERROR" not in severities, severities
        assert "FATAL" not in severities, severities


# -- the span surface stays inside the contract ---------------------------------------------


async def test_every_exported_attribute_is_in_the_contract(
    client, telemetry, register_chain, consent
) -> None:
    telemetry.enable()
    session = await _rooted(register_chain, consent)

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

    for span in telemetry.spans():
        for key in span.attributes:
            assert surface.forbidden_reason(key) is None, f"{span.name} exported {key}"


@pytest.mark.parametrize("span_name", [surface.SPAN_DECIDE])
async def test_dispatch_spans_never_record_exceptions(
    client, telemetry, register_chain, consent, span_name: str
) -> None:
    telemetry.enable()
    session = await _rooted(register_chain, consent)

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

    for span in telemetry.named(span_name):
        assert span.events == (), f"{span_name} recorded an exception event"
