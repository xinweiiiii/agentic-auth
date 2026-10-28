"""``TokenProfile`` — the seam that isolates a moving spec surface.

The design doc's versioning strategy puts token-exchange, transaction-token and AAuth
handling behind this interface: spec changes ship as new profiles, and a pinned manifest
keeps resolving against the profile version it was attested under.

Concretely, this is what lets Phase 4 add transaction tokens and Phase 5 swap in an
external issuer without the PDP, the routes, or the sidecar changing at all.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.schemas.authorize import Taint
from app.services.tokens.act_chain import current_actor, hop_of, walk


@dataclass(frozen=True)
class VerifiedToken:
    """A token whose signature and claims have already been checked.

    Only ever constructed by :meth:`TokenProfile.verify`. Every consumer takes this
    rather than a raw string, so there is no way to read a claim off an unverified token.
    """

    raw: str
    sub: str
    aud: str
    scope: str
    session_id: str
    policy_version: int
    hop: int
    jti: str
    expires_at: datetime
    act: dict[str, Any] | None = None
    # The recorded allow that authorized minting this token. Absent on root grants and on
    # tokens minted before Phase 3. Grants nothing: it links the next audit row to this one.
    action_id: str | None = None
    # Phase 4: the effective taint of the decision that minted this token. A delegate
    # inherits its delegator's taint through this signed claim and cannot lower it. Absent
    # on root grants and pre-Phase-4 tokens, which reads as trusted_internal.
    taint: Taint | None = None

    @property
    def actor(self) -> str:
        """Who is presenting this token — the outermost actor, or the human at the root."""
        return current_actor(self.act, self.sub)

    @property
    def act_chain(self) -> list[str]:
        """``[human, first delegate, ..., current actor]``."""
        return walk(self.act, self.sub)

    @property
    def next_hop(self) -> int:
        """The depth of the hop this token is being presented *for*."""
        return hop_of(self.act)

    @property
    def holder(self) -> str | None:
        """The agent this token was issued *to* — the one entitled to present it.

        ``act`` records who has already delegated; ``aud`` records who holds it now.
        Confusing the two would let a delegator's identity stand in for its delegate's.

        ``None`` when the token was issued for a tool call rather than a delegation:
        such a token goes to a resource server and can never authorize a further hop.
        """
        if self.act is None:
            return self.aud  # the root grant names the consented scope
        return self.aud.removeprefix("agent://") if self.aud.startswith("agent://") else None

    @property
    def presenter(self) -> str:
        """The identity expected to present this token: the human at the root, or the
        agent it was issued to."""
        return self.sub if self.act is None else self.aud


@dataclass(frozen=True)
class VerifiedTransaction:
    """A transaction token whose signature and claims have been checked.

    Only ever constructed by :meth:`TokenProfile.verify_transaction_token`. Single use and
    parameter binding are NOT checked here — they belong to the resource-side verifier,
    which holds the presented params and the replay store.
    """

    raw: str
    jti: str
    sub: str
    aud: str
    session_id: str
    action_id: str
    hop: int
    act: dict[str, Any] | None
    taint: Taint | None
    params_hash: str
    binding: list[str] | None
    expires_at: datetime


TRANSACTION_TYP = "txn+jwt"


class TokenProfile(ABC):
    """Mints and verifies the tokens that carry authority between hops."""

    @abstractmethod
    def mint_root_grant(self, *, sub: str, scope: str, session_id: str, policy_version: int) -> str:
        """The hop-1 token produced at consent: no ``act``, ``aud`` = the consented scope.

        It is never presentable to a resource server — every real call exchanges first.
        """

    @abstractmethod
    def mint_hop_token(
        self,
        *,
        sub: str,
        target: str,
        data_class: str,
        session_id: str,
        policy_version: int,
        hop: int,
        act: dict[str, Any] | None,
        action_id: str,
        taint: Taint | None = None,
    ) -> str:
        """A single-hop token bound to exactly one target and one data class, naming the
        recorded allow decision that authorized it, carrying the effective taint."""

    @abstractmethod
    def verify(self, token: str, *, audience: str | None = None) -> VerifiedToken:
        """Verify signature and claims, or raise.

        Must fail closed: any step that cannot be completed is a rejection, never a
        partial acceptance.
        """

    @abstractmethod
    def mint_transaction_token(
        self, *, hop: VerifiedToken, params_hash: str, binding: list[str] | None
    ) -> str:
        """Call-bound authority layered on ``hop`` (a verified tool-call token): same
        ``sub``/``aud``/``session_id``/``action_id``/``hop``/``act``/``taint``, plus the
        binding. Header ``typ`` is ``txn+jwt``. Short lifetime, single use at the resource."""

    @abstractmethod
    def verify_transaction_token(self, token: str, *, audience: str) -> VerifiedTransaction:
        """Verify signature, ``typ``, claims and audience, or raise. Fails closed."""

    @abstractmethod
    def verify_actor_token(
        self, token: str, *, anchor_jwks: dict[str, Any], subject_token: str, expected_agent: str
    ) -> str:
        """Proof of possession at the exchange (Phase 4): the actor token verifies against
        the holder's pinned keys, names ``expected_agent``, is addressed to this issuer, is
        fresh, and hashes the exact ``subject_token``. Returns the agent name, or raises."""

    @abstractmethod
    def jwks(self) -> dict[str, Any]:
        """Public keys, so any resource server can verify offline."""
