"""The enrollment outcome table, as a pure decision."""

from __future__ import annotations

import pytest

from agentic_auth.services.enrollment_rules import (
    Bound,
    EnrollDecision,
    NotConfigured,
    Unbindable,
    Unreachable,
    decide,
)

BOUND = Bound("https://idp.example#alice")
UNBINDABLE = Unbindable("assertion names another agent")
UNREACHABLE = Unreachable("connection refused")
NOT_CONFIGURED = NotConfigured()

TABLE = [
    # signature_ok, revoked_key, principal, reconciled -> decision
    (False, False, BOUND, True, EnrollDecision.REJECTED_SIGNATURE),
    (False, True, BOUND, True, EnrollDecision.REJECTED_SIGNATURE),  # signature first
    (False, False, UNREACHABLE, True, EnrollDecision.REJECTED_SIGNATURE),
    (True, True, BOUND, True, EnrollDecision.REJECTED_KEY_REVOKED),
    (True, True, UNBINDABLE, True, EnrollDecision.REJECTED_KEY_REVOKED),  # before quarantine
    (True, True, UNREACHABLE, False, EnrollDecision.REJECTED_KEY_REVOKED),
    (True, False, UNREACHABLE, True, EnrollDecision.FAILED_IDP_UNREACHABLE),
    (True, False, UNREACHABLE, False, EnrollDecision.FAILED_IDP_UNREACHABLE),  # never quarantine
    (True, False, UNBINDABLE, True, EnrollDecision.QUARANTINED),
    (True, False, UNBINDABLE, False, EnrollDecision.QUARANTINED),  # binding before manifest
    (True, False, NOT_CONFIGURED, True, EnrollDecision.QUARANTINED),
    (True, False, BOUND, False, EnrollDecision.REJECTED_MANIFEST),
    (True, False, BOUND, True, EnrollDecision.ENROLLED),
]


@pytest.mark.parametrize("signature_ok,revoked_key,principal,reconciled,expected", TABLE)
def test_the_outcome_table(signature_ok, revoked_key, principal, reconciled, expected) -> None:
    assert (
        decide(
            signature_ok=signature_ok,
            revoked_key=revoked_key,
            principal=principal,
            manifest_reconciled=reconciled,
        )
        is expected
    )


def test_enrolled_requires_all_three() -> None:
    """No combination short of signature + bound principal + reconciled manifest enrolls."""
    for principal in (UNBINDABLE, UNREACHABLE, NOT_CONFIGURED):
        assert (
            decide(
                signature_ok=True, revoked_key=False, principal=principal, manifest_reconciled=True
            )
            is not EnrollDecision.ENROLLED
        )
    assert (
        decide(signature_ok=True, revoked_key=False, principal=BOUND, manifest_reconciled=False)
        is not EnrollDecision.ENROLLED
    )
    assert (
        decide(signature_ok=False, revoked_key=False, principal=BOUND, manifest_reconciled=True)
        is not EnrollDecision.ENROLLED
    )
    assert (
        decide(signature_ok=True, revoked_key=True, principal=BOUND, manifest_reconciled=True)
        is not EnrollDecision.ENROLLED
    )


def test_the_function_never_raises() -> None:
    for sig in (True, False):
        for rev in (True, False):
            for principal in (BOUND, UNBINDABLE, UNREACHABLE, NOT_CONFIGURED):
                for rec in (True, False):
                    assert isinstance(
                        decide(
                            signature_ok=sig,
                            revoked_key=rev,
                            principal=principal,
                            manifest_reconciled=rec,
                        ),
                        EnrollDecision,
                    )
