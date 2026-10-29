"""No secrets and no identities leave the deployment.

This file *is* the no-secrets guarantee. Rather than inspect a synthetic span, it drives real
authorization flows — allow, deny, taint, privileged mint, exchange, enrollment — with in-memory
exporters attached, then sweeps **everything captured**.

The patterns matter more than the key names. An allowlist catches a key someone added on purpose;
only a value sweep catches a token that arrived inside a field nobody suspected. Both run here,
because the leak path is the SDK's, not ours: ``LoggingHandler`` exports
``exception.message`` and a full ``exception.stacktrace`` whenever ``exc_info`` is set, and a
traceback through token verification can carry a token fragment.
"""

from __future__ import annotations

import re

import pytest

from app.observability import surface

USER = "user:alice"

# A JWT is three base64url segments. Matching the shape rather than a known value is what makes
# this a sweep instead of a spot check.
JWT_SHAPE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
# A long unbroken base64url run: a token fragment, a signature, or a binding hash.
BLOB_SHAPE = re.compile(r"[A-Za-z0-9_-]{60,}")
# A bare hex digest — params_hash, a binding, a key fingerprint.
HEX_DIGEST = re.compile(r"\b[0-9a-f]{40,}\b")

# 128-bit pseudonyms are 32 hex characters and are the one hex value that may appear.
PSEUDONYM = re.compile(r"^[0-9a-f]{32}$")


def _values(mapping) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key, value in dict(mapping or {}).items():
        out.append((str(key), str(value)))
    return out


def _assert_clean(key: str, value: str, where: str) -> None:
    assert not JWT_SHAPE.search(value), f"{where}: {key} looks like a JWT: {value[:40]}..."
    if not PSEUDONYM.match(value):
        assert not HEX_DIGEST.search(value), f"{where}: {key} contains a hex digest: {value[:40]}"
        assert not BLOB_SHAPE.search(value), f"{where}: {key} contains a blob: {value[:40]}"


async def _drive_everything(client, register_chain, consent, admin_headers) -> dict:
    """One pass through as much of the dispatch path as the fixtures reach."""
    await register_chain()
    seen = {"allow": 0, "deny": 0}

    for target, data_class in [
        ("mcp://kb.internal/search", "kb.public"),
        ("agent://kb-search", "kb.internal"),
        ("agent://summarizer", "account.read"),
    ]:
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
        seen[body["outcome"]] = seen.get(body["outcome"], 0) + 1

        # Exchange the allowed hop, so authz.exchange is exercised with a real token.
        if body["outcome"] == "allow":
            await client.post(
                "/v1/token/exchange",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token": session["root_grant"],
                    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                    "resource": target,
                    "scope": data_class,
                    "action_id": body["action_id"],
                },
            )

    # A refused exchange, which is the path that logs and spans a failure.
    await client.post(
        "/v1/token/exchange",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c2VyOmFsaWNlIn0.bogus-signature",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "resource": "mcp://kb.internal/search",
            "scope": "kb.public",
            "action_id": "00000000-0000-4000-8000-000000000000",
        },
    )
    return seen


# -- nothing secret, anywhere ------------------------------------------------------


class TestSecrets:
    async def test_no_span_attribute_key_is_outside_the_contract(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        telemetry.enable()
        await _drive_everything(client, register_chain, consent, admin_headers)

        spans = telemetry.spans()
        assert spans, "the sweep captured no spans, so it would be vacuous"
        for span in spans:
            for key in span.attributes or {}:
                assert surface.forbidden_reason(key) is None, (
                    f"{span.name} exported {key!r}: {surface.forbidden_reason(key)}"
                )

    async def test_no_span_value_looks_like_a_secret(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        telemetry.enable()
        await _drive_everything(client, register_chain, consent, admin_headers)

        assert telemetry.spans(), "vacuous sweep"
        for span in telemetry.spans():
            for key, value in _values(span.attributes):
                _assert_clean(key, value, f"span {span.name}")

    async def test_no_log_record_carries_a_secret(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        telemetry.enable()
        await _drive_everything(client, register_chain, consent, admin_headers)

        for record in telemetry.logs():
            body = str(record.log_record.body)
            assert not JWT_SHAPE.search(body), f"a log body carries a JWT: {body[:80]}"
            for key, value in _values(record.log_record.attributes):
                _assert_clean(key, value, "log record")

    async def test_no_signal_anywhere_carries_a_stack_trace(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        """The SDK's leak path. ``exception.stacktrace`` is exported verbatim
        by the SDK once a sink is attached, so the dispatch path must never set ``exc_info``."""
        telemetry.enable()
        await _drive_everything(client, register_chain, consent, admin_headers)

        for record in telemetry.logs():
            attrs = dict(record.log_record.attributes or {})
            for forbidden in ("exception.stacktrace", "exception.message", "exception.type"):
                assert forbidden not in attrs, f"{forbidden} was exported: {attrs.get(forbidden)}"

        for span in telemetry.spans():
            assert span.events == (), f"{span.name} recorded an exception event"

    async def test_no_metric_label_carries_a_secret_or_an_identity(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        """The Phase 3 rule, swept rather than asserted family by family."""
        from prometheus_client import generate_latest

        telemetry.enable()
        await _drive_everything(client, register_chain, consent, admin_headers)

        text = generate_latest(telemetry.metrics.registry).decode()
        label_values = re.findall(r'\w+="([^"]*)"', text)
        assert label_values, "no labels were emitted, so this would be vacuous"
        for value in label_values:
            assert "://" not in value, f"a label carries a URI: {value}"
            assert not value.startswith("user:"), f"a label carries a user sub: {value}"
            assert not JWT_SHAPE.search(value), f"a label carries a JWT: {value}"
            assert not re.fullmatch(r"[0-9a-f-]{32,}", value), f"a label carries an id: {value}"


# -- no identities with disclosure off ----------------------------------------------


class TestDisclosureOff:
    async def test_no_agent_name_or_chain_is_exported(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        telemetry.enable()  # disclosure defaults to off
        await _drive_everything(client, register_chain, consent, admin_headers)

        assert telemetry.spans(), "vacuous sweep"
        for span in telemetry.spans():
            attrs = dict(span.attributes or {})
            for plaintext in surface.DISCLOSED_ATTRS:
                assert plaintext not in attrs, f"{span.name} exported {plaintext}"
            rendered = repr(attrs)
            assert "agent://" not in rendered, rendered
            assert "mcp://" not in rendered, rendered
            assert USER not in rendered, rendered

    async def test_pseudonyms_are_exported_instead(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        """Absence alone would also be satisfied by emitting nothing; grouping by agent has to
        still work."""
        telemetry.enable()
        await _drive_everything(client, register_chain, consent, admin_headers)

        refs = [
            v
            for span in telemetry.spans()
            for k, v in _values(span.attributes)
            if k in surface.PSEUDONYMOUS_ATTRS
        ]
        assert refs, "no pseudonymous identity reference was exported at all"
        for value in refs:
            assert PSEUDONYM.match(value), f"not a 32-hex pseudonym: {value}"

    async def test_no_log_record_carries_an_identity(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        telemetry.enable()
        await _drive_everything(client, register_chain, consent, admin_headers)

        for record in telemetry.logs():
            rendered = repr(dict(record.log_record.attributes or {}))
            assert "agent://" not in rendered, rendered
            assert USER not in rendered, rendered


# -- the opt-in works, announces itself, and never doubles up ----------------------


class TestDisclosureOn:
    async def test_plaintext_identities_appear(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        telemetry.enable(identity_disclosure=True)
        await _drive_everything(client, register_chain, consent, admin_headers)

        attrs = [dict(s.attributes or {}) for s in telemetry.spans()]
        assert any(surface.ATTR_ACT_CHAIN in a for a in attrs), (
            "disclosure is on but no plaintext chain was exported"
        )

    async def test_a_pseudonym_and_its_plaintext_are_never_both_present(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        """A backend that received both would hold two spellings of one identity, which defeats
        the point of having a default."""
        telemetry.enable(identity_disclosure=True)
        await _drive_everything(client, register_chain, consent, admin_headers)

        for span in telemetry.spans():
            attrs = dict(span.attributes or {})
            overlap = {
                plaintext
                for plaintext in surface.DISCLOSED_ATTRS
                if plaintext in attrs and f"{plaintext}_ref" in attrs
            }
            assert not overlap, f"{span.name} exported both spellings of {overlap}"

    async def test_metric_labels_are_unaffected_by_the_opt_in(
        self, client, telemetry, register_chain, consent, admin_headers
    ) -> None:
        """ "Labels never carry identities" is absolute and has no opt-in: a label is a
        cardinality problem as well as a privacy one, and the two do not share an escape hatch."""
        from prometheus_client import generate_latest

        telemetry.enable(identity_disclosure=True)
        await _drive_everything(client, register_chain, consent, admin_headers)

        text = generate_latest(telemetry.metrics.registry).decode()
        assert "agent://" not in text
        assert USER not in text

    async def test_the_posture_is_itself_a_signal(
        self, client, telemetry, register_chain, consent
    ) -> None:
        """So an organisation can alert on any deployment that has disclosure on."""
        from prometheus_client import generate_latest

        telemetry.enable(identity_disclosure=True)
        telemetry.metrics.telemetry_identity_disclosure.set(1)
        text = generate_latest(telemetry.metrics.registry).decode()
        assert "agentic_auth_telemetry_identity_disclosure 1.0" in text


# -- the sweep is not vacuous ---------------------------------------------------------------


async def test_the_workload_exercises_both_outcomes(
    client, telemetry, register_chain, consent, admin_headers
) -> None:
    telemetry.enable()
    seen = await _drive_everything(client, register_chain, consent, admin_headers)
    assert seen["allow"] >= 1 and seen["deny"] >= 1, seen


async def test_the_detectors_actually_detect(client) -> None:
    """Guards the guard: a regex that matched nothing would make every sweep above pass."""
    token = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c2VyOmFsaWNlIn0.c2lnbmF0dXJlLWhlcmU"
    assert JWT_SHAPE.search(token)
    assert BLOB_SHAPE.search("A" * 64)
    assert HEX_DIGEST.search("a" * 64)
    with pytest.raises(AssertionError):
        _assert_clean("authz.token", token, "self-test")
    # And a legitimate pseudonym must pass.
    _assert_clean("authz.agent_ref", "0" * 32, "self-test")
