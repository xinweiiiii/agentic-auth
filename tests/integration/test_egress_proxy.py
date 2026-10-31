"""The injected egress proxy (US7; FR-013, FR-014).

The narrowest rung and the heaviest to operate, so the tests concentrate on the two
things that are genuinely its own: **anything uninspectable is refused**, and the
deployment is honest that it is weaker than the rungs above it.

Once a connection is intercepted the request is an ordinary HTTP request and
``enforce()`` runs on it unchanged — that path is already covered by the sidecar and
gateway suites, and re-testing it here would be testing the same code twice.
"""

from __future__ import annotations

import pytest

from agentic_auth.boundary.egress import (
    GUARANTEE,
    UNINSPECTABLE_NO_CA,
    UNINSPECTABLE_NO_LEAF,
    UNINSPECTABLE_NOT_TLS,
    CertificateAuthority,
    Uninspectable,
    inspect,
    install_snippet,
    parse_connect,
    refusal,
)


@pytest.fixture(scope="module")
def ca() -> CertificateAuthority:
    return CertificateAuthority.generate()


# -- what can be inspected ------------------------------------------------------------


def test_a_connect_request_yields_a_host_and_port(ca) -> None:
    assert inspect(ca, "CONNECT bank.internal:443 HTTP/1.1") == ("bank.internal", 443)


def test_a_leaf_is_minted_for_the_host(ca) -> None:
    """Interception is invisible to an agent that trusts the CA — which is the whole
    mechanism, and also the reason the CA has to be installed."""
    certificate, _ = ca.leaf_for("bank.internal")

    assert certificate.issuer == ca.certificate.subject
    assert "bank.internal" in certificate.subject.rfc4514_string()


def test_leaves_are_cached_per_host(ca) -> None:
    """Minting an RSA key per connection would put key generation on the request path."""
    first, _ = ca.leaf_for("cache.internal")
    second, _ = ca.leaf_for("cache.internal")

    assert first is second


def test_an_ip_literal_gets_an_ip_san(ca) -> None:
    certificate, _ = ca.leaf_for("10.0.0.7")

    assert "10.0.0.7" in str(certificate.extensions)


# -- what cannot is REFUSED, never passed through (FR-014) -------------------------------


def test_without_a_ca_nothing_is_inspectable(ca) -> None:
    """Not a pass-through, not a warning. A proxy that forwards what it cannot inspect
    is a proxy that enforces nothing, and centrally that is every call this runtime
    makes."""
    with pytest.raises(Uninspectable) as exc:
        inspect(None, "CONNECT bank.internal:443 HTTP/1.1")

    assert exc.value.cause == UNINSPECTABLE_NO_CA


def test_the_missing_trust_material_is_named(ca) -> None:
    """FR-014's operator-facing requirement: the reason has to be actionable, not
    'blocked'."""
    with pytest.raises(Uninspectable) as exc:
        inspect(None, "CONNECT bank.internal:443 HTTP/1.1")

    detail = exc.value.detail
    assert "trust store" in detail
    assert "egress-ca" in detail


@pytest.mark.parametrize(
    "line",
    [
        "GET /accounts HTTP/1.1",
        "POST /x HTTP/1.1",
        "CONNECT",
        "CONNECT bank.internal HTTP/1.1",  # no port
        "CONNECT :443 HTTP/1.1",  # no host
        "CONNECT bank.internal:https HTTP/1.1",  # non-numeric port
        "",
    ],
)
def test_anything_unparseable_is_refused(ca, line: str) -> None:
    with pytest.raises(Uninspectable) as exc:
        inspect(ca, line)

    assert exc.value.cause in {UNINSPECTABLE_NOT_TLS, UNINSPECTABLE_NO_LEAF}


def test_parse_connect_is_strict_about_the_method(ca) -> None:
    with pytest.raises(Uninspectable):
        parse_connect("connect-ish bank.internal:443")


# -- the refusal says what it is ----------------------------------------------------------


def test_the_refusal_envelope_matches_every_other_enforcement_point() -> None:
    body = refusal(Uninspectable(UNINSPECTABLE_NO_CA, "no CA"))["error"]

    assert body["code"] == "policy_denied"
    assert body["details"]["reason"] == UNINSPECTABLE_NO_CA
    assert body["details"]["recoverable"] is False


def test_the_refusal_reports_network_not_full() -> None:
    """The honesty requirement. This mode depends on trust material in a runtime the
    integrator does not fully own, so it is weaker than the resource guard and the
    connector proxy — and says so on every refusal."""
    body = refusal(Uninspectable(UNINSPECTABLE_NO_CA, "no CA"))["error"]

    assert body["details"]["guarantee_level"] == "network"
    assert GUARANTEE.value == "network"


# -- the operator prerequisite is documented, not automated (research.md R10) -------------


def test_the_install_snippet_states_the_prerequisite_and_the_cost(ca) -> None:
    snippet = install_snippet(ca)

    assert "trust store" in snippet
    assert "guarantee_level=network rather than full" in snippet
    # Several runtimes, because the step differs per runtime and guessing wrong installs
    # a CA in the wrong place.
    assert "update-ca-certificates" in snippet
    assert "SSL_CERT_FILE" in snippet
    assert "NODE_EXTRA_CA_CERTS" in snippet


def test_the_ca_certificate_is_exportable_as_pem(ca) -> None:
    pem = ca.certificate_pem()

    assert pem.startswith(b"-----BEGIN CERTIFICATE-----")


def test_a_ca_round_trips_through_pem(ca) -> None:
    """An operator with an existing internal CA loads it rather than generating one."""
    from cryptography.hazmat.primitives import serialization

    key_pem = ca.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    loaded = CertificateAuthority.from_pem(ca.certificate_pem(), key_pem)

    assert loaded.certificate.subject == ca.certificate.subject
    assert loaded.leaf_for("bank.internal")[0].issuer == ca.certificate.subject
