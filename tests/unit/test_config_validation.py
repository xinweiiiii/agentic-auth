"""Settings combinations that must be refused at startup.

A configuration that comes up but cannot do what it claims is the failure this whole
project exists to prevent, one level down. The sidecar already refuses to start without a
PDP or an upstream map; ``Settings`` refuses the one Phase 5 combination that is not merely
unusual but incoherent.
"""

from __future__ import annotations

import pytest

from agentic_auth.config import Settings


def test_step_up_without_consent_granularity_is_refused() -> None:
    """The only recoverable reason is SCOPE_NOT_CONSENTED, and without granularity it
    fires only for a data class the pinned policy never declared — which step-up may never
    grant. The endpoints would refuse every request correctly, forever."""
    with pytest.raises(ValueError, match="requires consent_granularity_enabled"):
        Settings(step_up_enabled=True, consent_granularity_enabled=False)


def test_step_up_with_consent_granularity_is_accepted() -> None:
    settings = Settings(step_up_enabled=True, consent_granularity_enabled=True)
    assert settings.step_up_enabled
    assert settings.consent_granularity_enabled


def test_consent_granularity_alone_is_accepted() -> None:
    """Granularity without step-up is a real posture: consent to a subset and let the
    refusal stand. It narrows, so it is always safe."""
    settings = Settings(consent_granularity_enabled=True, step_up_enabled=False)
    assert settings.consent_granularity_enabled
    assert not settings.step_up_enabled


def test_defaults_reproduce_phase_4() -> None:
    """Every Phase 5 control is off by default, so a deployment that upgrades and changes
    nothing behaves exactly as it did."""
    settings = Settings()
    assert settings.consent_granularity_enabled is False
    assert settings.step_up_enabled is False
    assert settings.sandbox_enabled is False
    assert settings.default_guarantee_level == "full"


def test_phase_5_numeric_defaults() -> None:
    settings = Settings()
    assert settings.step_up_challenge_ttl_seconds == 300
    assert settings.sandbox_run_deadline_seconds == 300
    # Matches the sidecar's control_plane_timeout_seconds (2.0s), so the gateway is not
    # less available than a sidecar against the same control plane.
    assert settings.gateway_decision_deadline_ms == 2000


# -- 0.4.0: MCP OAuth 2.1 baseline (feature 011, FR-019, FR-020) -------------------------

_IDP = {
    "principal_idp_issuer": "https://idp.example.com",
    "principal_idp_jwks_url": "https://idp.example.com/.well-known/jwks.json",
}


def test_every_mcp_oauth_milestone_is_off_by_default() -> None:
    settings = Settings()
    assert not settings.verified_consent_enabled
    assert not settings.as_metadata_enabled
    assert not settings.client_mapping_enabled
    assert settings.consent_token == ""
    assert settings.consent_audiences == ()
    assert settings.principal_algorithms == ("RS256", "ES256", "EdDSA")


def test_client_mapping_without_verified_consent_is_refused() -> None:
    with pytest.raises(ValueError, match="AGENTIC_AUTH_VERIFIED_CONSENT_ENABLED"):
        Settings(client_mapping_enabled=True)


@pytest.mark.parametrize("missing", ["principal_idp_issuer", "principal_idp_jwks_url"])
def test_verified_consent_without_the_principal_idp_is_refused(missing) -> None:
    values = {**_IDP, missing: "", "consent_idp_audiences": "https://authz.example.com"}
    with pytest.raises(ValueError, match=f"AGENTIC_AUTH_{missing.upper()}"):
        Settings(verified_consent_enabled=True, **values)


def test_verified_consent_without_audiences_is_refused() -> None:
    with pytest.raises(ValueError, match="AGENTIC_AUTH_CONSENT_IDP_AUDIENCES"):
        Settings(verified_consent_enabled=True, **_IDP)


def test_verified_consent_and_client_mapping_together_are_accepted() -> None:
    settings = Settings(
        verified_consent_enabled=True,
        client_mapping_enabled=True,
        consent_idp_audiences="https://authz.example.com, https://mcp-proxy.example.com",
        **_IDP,
    )
    assert settings.consent_audiences == (
        "https://authz.example.com",
        "https://mcp-proxy.example.com",
    )


@pytest.mark.parametrize("issuer", ["agentic-auth", "http://authz.example.com"])
def test_as_metadata_needs_an_https_issuer(issuer) -> None:
    with pytest.raises(ValueError, match="AGENTIC_AUTH_ISSUER"):
        Settings(as_metadata_enabled=True, issuer=issuer)


def test_as_metadata_with_an_https_issuer_is_accepted() -> None:
    assert Settings(as_metadata_enabled=True, issuer="https://authz.example.com").issuer


@pytest.mark.parametrize("algorithms", ["none", "HS256", "RS256,HS512", "", "RS999"])
def test_unsafe_principal_algorithms_are_refused(algorithms) -> None:
    with pytest.raises(ValueError, match="AGENTIC_AUTH_PRINCIPAL_IDP_ALGORITHMS"):
        Settings(principal_idp_algorithms=algorithms)
