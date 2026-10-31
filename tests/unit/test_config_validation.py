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
