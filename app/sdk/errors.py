"""Every way an SDK call can refuse, in one place.

Three kinds, because a caller handles them differently:

* :class:`PolicyDenied` — the system worked and the answer is no. Carries the machine
  reason, the recorded ``action_id``, and whether a step-up could recover it.
* :class:`ControlPlaneRejected` — the *request* was wrong (unknown agent, bad manifest,
  wrong bearer). Fix the call. :class:`ManifestRejected` is the one worth catching by
  name: it carries the reconciliation diff that says what to change.
* :class:`ControlPlaneUnavailable` — the system could not answer. Never proceed.

:class:`TransactionParamsRequired` is its own case: a privileged call the SDK refuses to
even attempt, because binding it needs parameters the caller did not pass. It is raised
before anything is spent.

They live here rather than next to the client so the admin/audit/identity planes and the
hop path can raise the same types without importing each other.
"""

from __future__ import annotations

from typing import Any

from app.schemas.authorize import DenyReason, is_recoverable


class PolicyDenied(Exception):
    """A hop was refused.

    Raised rather than returned: a refusal that is easy to ignore is a refusal that gets
    ignored, and routing around the SDK is the failure mode this product exists to
    prevent.
    """

    def __init__(
        self,
        reason: DenyReason,
        *,
        message: str,
        target: str,
        hop: int,
        session_id: str,
        policy_version: int | None = None,
        action_id: str | None = None,
        taint: str | None = None,
        taint_source: str | None = None,
        challenge: dict[str, Any] | None = None,
        data_class: str | None = None,
    ) -> None:
        super().__init__(f"{reason.value}: {message}")
        self.reason = reason
        self.message = message
        self.target = target
        self.hop = hop
        self.session_id = session_id
        self.policy_version = policy_version
        # Phase 4: the effective taint the refusal was decided under, and what introduced it.
        self.taint = taint
        self.taint_source = taint_source
        # The audit record of this refusal — fetch its chain with
        # GET /v1/audit/actions/{action_id}/chain. None when it could not be recorded.
        self.action_id = action_id
        # Phase 5. Present only when this refusal is recoverable AND the deployment has
        # step-up enabled: the question to put to the consenting human. A non-recoverable
        # refusal never carries one, so `if denied.challenge:` is a safe thing to branch
        # on without re-checking recoverability.
        self.challenge = challenge
        self.data_class = data_class

    @property
    def recoverable(self) -> bool:
        """True only for ``SCOPE_NOT_CONSENTED``.

        Since Phase 5 that means "the human did not consent to this data class", not
        "the manifest never declared it" — the second is ``OUT_OF_SCOPE`` and final,
        because consent may only widen within the pinned manifest.
        """
        return is_recoverable(self.reason)


class ControlPlaneUnavailable(Exception):
    """The control plane could not be reached or answered unusably. Always fatal to the
    hop — there is no path here that proceeds with the un-narrowed token."""


class TransactionParamsRequired(Exception):
    """The decision says this privileged call needs a transaction token, and no ``params``
    were supplied to bind. Raised BEFORE any exchange, so nothing was spent."""


class ControlPlaneRejected(Exception):
    """The control plane understood the request and refused it: the caller's to fix.

    Distinct from :class:`ControlPlaneUnavailable`, which says nothing about the request.
    Retrying this one unchanged will fail the same way.
    """

    def __init__(
        self,
        *,
        status: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
        method: str = "",
        path: str = "",
    ) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}
        self.method = method
        self.path = path


class ManifestRejected(ControlPlaneRejected):
    """A manifest was refused by reconciliation, or held for review.

    ``diff`` is the reconciliation diff: one entry per tool reference that exceeds or
    conflicts with what capability discovery advertises, each with its own ``remedy``.
    ``needs_review`` separates the two cases — a hard rejection (edit the manifest) from
    discovery having been unavailable (resubmit with ``override_reason=``, which is
    recorded as a human attestation).
    """

    @property
    def diff(self) -> list[dict[str, Any]]:
        entries = self.details.get("diff")
        return entries if isinstance(entries, list) else []

    @property
    def needs_review(self) -> bool:
        return self.code == "needs_review"

    def remedies(self) -> list[str]:
        """One line per diff entry: the tool ref and what to do about it."""
        return [f"{e.get('tool_ref', '?')}: {e.get('remedy', '')}" for e in self.diff]


__all__ = [
    "ControlPlaneRejected",
    "ControlPlaneUnavailable",
    "ManifestRejected",
    "PolicyDenied",
    "TransactionParamsRequired",
]
