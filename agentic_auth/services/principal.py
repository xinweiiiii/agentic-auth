"""Principal binding: is this agent acting for an accountable human or organization?

The agent presents an OIDC ID token from the organization's human IdP. The control plane
verifies it against the IdP's JWKS and requires the binding claim to name this agent.
Three outcomes are distinct on purpose:

- ``Bound``: the assertion verifies and names this agent.
- ``Unbindable``: no assertion, or one that does not verify or names another agent. This
  is quarantine — a fact about the agent.
- ``Unreachable``: the IdP could not be consulted. This is a retryable failure — a fact about
  the network — and must never become a quarantine.

The IdP's JWKS is fetched over ``httpx`` through a module-level factory so tests can route
it to an in-process fake. Verification itself is ``agentic_auth.oauth.validate``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

import httpx

from agentic_auth import runtime
from agentic_auth.config import Settings, get_settings
from agentic_auth.oauth.validate import IdpUnavailable, JwksCache, TokenInvalid, TokenValidator
from agentic_auth.services.enrollment_rules import (
    Bound,
    NotConfigured,
    PrincipalResult,
    Unbindable,
    Unreachable,
)

logger = logging.getLogger(__name__)

AGENT_PREFIX = "agent://"


def _default_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(5.0))


# Replaced by tests with a client routed to the fake IdP.
jwks_http_client: Callable[[], httpx.AsyncClient] = _default_client


def idp_http() -> httpx.AsyncClient:
    """The client for this request's IdP calls.

    An embedded instance reaches its own identity provider through its own transport,
    whatever this module's hook has been pointed at for the rest of the process.
    """
    current = runtime.override()
    return current.http if current is not None else jwks_http_client()


class PrincipalBinder:
    """Verifies human IdP tokens through the shared validator (feature 011, research F4).

    Before 0.4.0 this decoded with ``algorithms=[header["alg"]]``, which let the token
    choose how it was checked. It now goes through ``agentic_auth.oauth.validate`` with the
    operator's algorithm list, like every other place an IdP token enters. Clock leeway
    stays at zero here, as it was: enrollment and step-up keep their 0.3.0 semantics apart
    from the algorithm pin.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def configured(self) -> bool:
        s = self._settings
        return bool(
            s.principal_idp_issuer and s.principal_idp_jwks_url and s.principal_idp_audience
        )

    def _validator(self) -> TokenValidator:
        s = self._settings
        return TokenValidator(
            issuer=s.principal_idp_issuer,
            audiences=[s.principal_idp_audience],
            jwks=JwksCache(s.principal_idp_jwks_url, idp_http),
            algorithms=s.principal_algorithms,
            leeway=0,
            require=("exp", "iat", "sub", "iss", "aud"),
        )

    async def bind(self, assertion: str | None, agent_name: str) -> PrincipalResult:
        if not self.configured:
            return NotConfigured()
        if not assertion:
            return Unbindable("no principal assertion presented")

        try:
            verified = await self._validator().validate(assertion)
        except IdpUnavailable as exc:
            logger.warning("principal identity provider unreachable: %s", exc)
            return Unreachable(str(exc))
        except TokenInvalid as exc:
            return Unbindable(f"assertion did not verify: {exc.check.value}")

        s = self._settings
        bound_agent = verified.claims.get(s.principal_binding_claim)
        expected = f"{AGENT_PREFIX}{agent_name}"
        if bound_agent != expected:
            return Unbindable(
                f"assertion names {bound_agent!r}, not {expected!r} "
                f"(claim {s.principal_binding_claim!r})"
            )
        return Bound(verified.principal)

    async def verify_human(self, assertion: str) -> str:
        """Verify a HUMAN's ID token and return its subject (Phase 5, FR-025).

        Deliberately not ``bind()``. That one answers "is this agent accountable to
        someone?" and therefore insists on the ``agent`` claim naming a specific agent. A
        human approving a step-up is the accountable party themselves — there is no agent
        claim to check, and requiring one would make the flow impossible.

        Raises rather than returning a result type, because unlike enrollment there is no
        useful middle outcome here: either we know who approved, or nothing is approved.
        """
        if not self.configured:
            raise ValueError("no human identity provider is configured")
        try:
            verified = await self._validator().validate(assertion)
        except TokenInvalid as exc:
            raise ValueError(f"credential did not verify: {exc.check.value}") from exc
        return verified.principal


__all__ = ["PrincipalBinder", "idp_http", "jwks_http_client"]
