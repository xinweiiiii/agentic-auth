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
it to an in-process fake; PyJWT's ``PyJWK`` loads the OKP/EC/RSA key it names.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import httpx
import jwt

from agentic_auth import runtime
from agentic_auth.config import Settings, get_settings
from agentic_auth.services.enrollment_rules import (
    Bound,
    NotConfigured,
    PrincipalResult,
    Unbindable,
    Unreachable,
)

logger = logging.getLogger(__name__)

AGENT_PREFIX = "agent://"


class _IdpUnreachable(Exception):
    """Internal: the JWKS fetch failed. ``bind`` turns it into ``Unreachable``."""


def _default_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(5.0))


# Replaced by tests with a client routed to the fake IdP.
jwks_http_client: Callable[[], httpx.AsyncClient] = _default_client


class PrincipalBinder:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def configured(self) -> bool:
        s = self._settings
        return bool(
            s.principal_idp_issuer and s.principal_idp_jwks_url and s.principal_idp_audience
        )

    async def bind(self, assertion: str | None, agent_name: str) -> PrincipalResult:
        if not self.configured:
            return NotConfigured()
        if not assertion:
            return Unbindable("no principal assertion presented")

        try:
            header = jwt.get_unverified_header(assertion)
        except jwt.PyJWTError as exc:
            return Unbindable(f"assertion is not a JWT: {exc}")
        kid = header.get("kid")

        try:
            jwks = await self._fetch_jwks()
        except _IdpUnreachable as exc:
            logger.warning("principal identity provider unreachable: %s", exc)
            return Unreachable(str(exc))

        key = _key_for(jwks, kid)
        if key is None:
            return Unbindable(f"assertion kid {kid!r} is not in the identity provider's JWKS")

        s = self._settings
        try:
            claims: dict[str, Any] = jwt.decode(
                assertion,
                key,
                algorithms=[header.get("alg", "EdDSA")],
                issuer=s.principal_idp_issuer,
                audience=s.principal_idp_audience,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            return Unbindable(f"assertion did not verify: {exc}")

        bound_agent = claims.get(s.principal_binding_claim)
        expected = f"{AGENT_PREFIX}{agent_name}"
        if bound_agent != expected:
            return Unbindable(
                f"assertion names {bound_agent!r}, not {expected!r} "
                f"(claim {s.principal_binding_claim!r})"
            )
        return Bound(f"{claims['iss']}#{claims['sub']}")

    async def _fetch_jwks(self) -> dict[str, Any]:
        # An embedded instance reaches its own identity provider through its own transport,
        # whatever this module's hook has been pointed at for the rest of the process.
        current = runtime.override()
        client = current.http if current is not None else jwks_http_client()
        try:
            response = await client.get(self._settings.principal_idp_jwks_url)
        except httpx.HTTPError as exc:
            raise _IdpUnreachable(f"could not fetch JWKS: {type(exc).__name__}") from exc
        if response.status_code >= 500:
            raise _IdpUnreachable(f"identity provider returned {response.status_code}")
        if response.status_code != 200:
            # A 4xx is the IdP telling us the URL is wrong: a configuration fact, so a
            # deployment notices, but not something a retry fixes. Treated as unreachable
            # because enrolling nobody is safer than quarantining everybody.
            raise _IdpUnreachable(f"identity provider returned {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise _IdpUnreachable("identity provider JWKS is not JSON") from exc
        if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
            raise _IdpUnreachable("identity provider JWKS is malformed")
        return body


def _key_for(jwks: dict[str, Any], kid: str | None) -> Any:
    for entry in jwks.get("keys", []):
        if entry.get("kid") == kid:
            try:
                return jwt.PyJWK(dict(entry)).key
            except jwt.PyJWTError:
                return None
    return None


__all__ = ["PrincipalBinder", "jwks_http_client"]
