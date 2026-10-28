"""The enrollment decision — pure (contracts/identity.md §3).

Given what the service established (did the signature verify, is any presented key on a
revoked anchor, what did principal binding say, is the manifest reconciled), decide one of
five outcomes, in a fixed order. No I/O, no exceptions: every row of the contract's table
is a branch here, and ``tests/unit/test_enrollment_rules.py`` is that table.

The order matters. A bad signature is refused before anything is looked up. A revoked key
is refused before binding, so a revoked agent cannot even be quarantined back into
inspection. An unreachable IdP is a retry, never a quarantine. Reconciliation is checked
last, so its diff reaches an agent whose identity is otherwise in order.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


@dataclass(frozen=True)
class Bound:
    principal_ref: str


@dataclass(frozen=True)
class Unbindable:
    detail: str


@dataclass(frozen=True)
class Unreachable:
    detail: str


@dataclass(frozen=True)
class NotConfigured:
    pass


PrincipalResult = Bound | Unbindable | Unreachable | NotConfigured


class EnrollDecision(StrEnum):
    ENROLLED = "enrolled"
    QUARANTINED = "quarantined"
    REJECTED_SIGNATURE = "rejected_signature"
    REJECTED_KEY_REVOKED = "rejected_key_revoked"
    FAILED_IDP_UNREACHABLE = "failed_idp_unreachable"
    REJECTED_MANIFEST = "rejected_manifest"


def decide(
    *,
    signature_ok: bool,
    revoked_key: bool,
    principal: PrincipalResult,
    manifest_reconciled: bool,
) -> EnrollDecision:
    if not signature_ok:
        return EnrollDecision.REJECTED_SIGNATURE
    if revoked_key:
        return EnrollDecision.REJECTED_KEY_REVOKED
    if isinstance(principal, Unreachable):
        return EnrollDecision.FAILED_IDP_UNREACHABLE
    if isinstance(principal, Unbindable | NotConfigured):
        return EnrollDecision.QUARANTINED
    if not manifest_reconciled:
        return EnrollDecision.REJECTED_MANIFEST
    return EnrollDecision.ENROLLED


__all__ = [
    "Bound",
    "EnrollDecision",
    "NotConfigured",
    "PrincipalResult",
    "Unbindable",
    "Unreachable",
    "decide",
]
