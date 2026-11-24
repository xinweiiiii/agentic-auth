"""Validate an inbound OAuth access token or ID token from the customer's IdP (research R2).

One implementation for every place a human IdP token enters: the connector proxy and the
gateway (M1), consent (M2), enrollment binding and step-up. One implementation is one
conformance surface; two would drift.

Rules, each a refusal with a named ``Check``:

- **The algorithm is ours to choose, not the token's.** The header's ``alg`` must be in an
  operator allow-list, default ``RS256, ES256, EdDSA``. ``none`` and HMAC algorithms can
  never be configured: a verifier that lets the token pick its algorithm can be handed a
  token "signed" with the public key as an HMAC secret (research F4).
- **Audience is matched exactly.** One of the token's audiences must equal one we accept
  (RFC 8707). A prefix or a lookalike is a different resource.
- **Clock skew is tolerated, briefly**: 60 seconds by default on ``exp`` and ``nbf``.
- **Keys come from the IdP's JWKS**, cached for its ``Cache-Control`` max-age clamped to
  5–60 minutes. An unknown ``kid`` (a rotation) refreshes at most once per 30 seconds, so a
  stream of junk ``kid`` values cannot turn us into a load generator against the IdP.
- **Unavailable is not invalid.** No valid cached keys and an unreachable IdP raises
  ``IdpUnavailable``, which callers turn into a retryable refusal. It never allows
  (FR-021), and it is never reported as the token's fault.

This module imports PyJWT and httpx only, never the database, the models or the control
plane's settings, because the enforcement points deploy next to an agent.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import httpx
import jwt

logger = logging.getLogger(__name__)

DEFAULT_ALGORITHMS: tuple[str, ...] = ("RS256", "ES256", "EdDSA")
DEFAULT_LEEWAY_SECONDS = 60
MIN_JWKS_TTL_SECONDS = 300
MAX_JWKS_TTL_SECONDS = 3600
UNKNOWN_KID_REFRESH_SECONDS = 30

# What may be put on the allow-list at all. Asymmetric only: with HMAC the verifier holds
# the signing secret, which for a token from someone else's IdP is never what we want.
_ASYMMETRIC = frozenset(
    {
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512",
        "EdDSA",
    }
)  # fmt: skip

_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*(\d+)\s*(?:,|$)", re.IGNORECASE)


class Check(StrEnum):
    """Which rule a token failed. Safe to show a client: it never echoes token content."""

    SIGNATURE = "signature"
    ISSUER = "issuer"
    AUDIENCE = "audience"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    ALGORITHM = "algorithm"
    MALFORMED = "malformed"


class TokenInvalid(Exception):
    """The token is not acceptable. The client's fault; retrying the same token is futile."""

    def __init__(self, check: Check, detail: str = "") -> None:
        self.check = check
        self.detail = detail
        super().__init__(f"token refused: {check.value}{f' ({detail})' if detail else ''}")


class IdpUnavailable(Exception):
    """The IdP's keys could not be obtained and none are cached. Retryable; never an allow."""


def fingerprint(token: str) -> str:
    """What logs, traces and metrics may carry instead of the token (INV-4)."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def check_algorithms(algorithms: Iterable[str]) -> tuple[str, ...]:
    """Normalise an operator's allow-list, refusing anything unsafe or unknown."""
    chosen = tuple(a.strip() for a in algorithms if a.strip())
    if not chosen:
        raise ValueError("at least one signing algorithm must be allowed")
    for alg in chosen:
        if alg.lower() == "none" or alg.upper().startswith("HS"):
            raise ValueError(
                f"signing algorithm {alg!r} is never allowed for IdP tokens: "
                "use an asymmetric algorithm (for example RS256, ES256 or EdDSA)"
            )
        if alg not in _ASYMMETRIC:
            raise ValueError(f"unknown signing algorithm {alg!r}; allowed: {sorted(_ASYMMETRIC)}")
    return chosen


@dataclass(frozen=True)
class InboundToken:
    """A token that passed validation. Never persisted, never logged in full."""

    issuer: str
    subject: str
    client_id: str | None
    audiences: tuple[str, ...]
    scopes: tuple[str, ...]
    expires_at: int
    fingerprint: str
    claims: dict[str, Any] = field(repr=False, compare=False)

    @property
    def principal(self) -> str:
        """The subject in the form audit chains already use: ``iss#sub``."""
        return f"{self.issuer}#{self.subject}"


HttpFactory = Callable[[], httpx.AsyncClient]


class JwksCache:
    """The IdP's signing keys, fetched lazily and cached within bounds.

    ``http`` is a factory rather than a client so the caller decides the client's lifetime,
    and an embedded control plane can route the fetch through its own transport.

    With no ``url``, ``discover_from`` names the issuer whose discovery document supplies
    ``jwks_uri`` on first use (research R2). Until that succeeds there are no keys, so a
    discovery failure is ``IdpUnavailable``: fail closed.
    """

    def __init__(
        self,
        url: str,
        http: HttpFactory,
        *,
        clock: Callable[[], float] = time.monotonic,
        discover_from: str | None = None,
    ) -> None:
        if not url and not discover_from:
            raise ValueError("a JWKS cache needs a JWKS URL or an issuer to discover it from")
        self.url = url
        self._discover_from = discover_from
        self._http = http
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._expires_at = 0.0
        # Rate-limits only refreshes an unknown kid triggers. A scheduled refresh must not
        # count, or a key rotated just after start-up would be refused for 30 seconds.
        self._last_kid_refresh: float | None = None

    async def key_for(self, kid: str | None) -> Any | None:
        """The key for ``kid``, or None if the IdP does not publish it."""
        now = self._clock()
        if now >= self._expires_at:
            await self._refresh()  # raises IdpUnavailable: nothing valid to fall back on
        key = self._keys.get(kid or "")
        if key is not None:
            return key
        if (
            self._last_kid_refresh is not None
            and now - self._last_kid_refresh < UNKNOWN_KID_REFRESH_SECONDS
        ):
            return None
        self._last_kid_refresh = now
        try:
            await self._refresh()
        except IdpUnavailable:
            # The cached set is still valid, so this is an unknown key, not an outage.
            logger.warning("JWKS refresh for an unknown kid failed; keeping the cached set")
            return None
        return self._keys.get(kid or "")

    async def _refresh(self) -> None:
        fetched_at = self._clock()
        if not self.url:
            await self._discover()
        try:
            response = await self._http().get(self.url)
        except httpx.HTTPError as exc:
            raise IdpUnavailable(f"could not fetch JWKS: {type(exc).__name__}") from exc
        if response.status_code != 200:
            raise IdpUnavailable(f"JWKS endpoint returned {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise IdpUnavailable("JWKS is not JSON") from exc
        if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
            raise IdpUnavailable("JWKS is malformed")

        keys: dict[str, Any] = {}
        for entry in body["keys"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("kid"), str):
                continue
            try:
                keys[entry["kid"]] = jwt.PyJWK(dict(entry)).key
            except jwt.PyJWTError:
                continue  # one unusable key (an unsupported type) must not hide the rest
        self._keys = keys
        self._expires_at = fetched_at + _ttl(response.headers.get("cache-control"))

    async def _discover(self) -> None:
        from agentic_auth.oauth.metadata import MetadataUnavailable, discover

        assert self._discover_from is not None  # checked in __init__
        try:
            server = await discover(self._discover_from, self._http)
        except MetadataUnavailable as exc:
            raise IdpUnavailable(f"IdP discovery failed: {exc}") from exc
        if server.jwks_uri is None:
            raise IdpUnavailable("the IdP's discovery document names no jwks_uri")
        self.url = server.jwks_uri

    async def prime(self) -> None:
        """Fetch now. For a process's start-up, so an unreachable IdP stops it starting
        rather than failing its first request."""
        await self._refresh()


def _ttl(cache_control: str | None) -> float:
    match = _MAX_AGE.search(cache_control or "")
    seconds = int(match.group(1)) if match else MIN_JWKS_TTL_SECONDS
    return float(min(max(seconds, MIN_JWKS_TTL_SECONDS), MAX_JWKS_TTL_SECONDS))


class TokenValidator:
    def __init__(
        self,
        *,
        issuer: str,
        audiences: Iterable[str],
        jwks: JwksCache,
        algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
        leeway: int = DEFAULT_LEEWAY_SECONDS,
        require: Iterable[str] = ("exp", "sub", "iss", "aud"),
    ) -> None:
        self.issuer = issuer
        self.audiences = tuple(audiences)
        if not self.audiences:
            raise ValueError("a validator needs at least one accepted audience")
        self.algorithms = check_algorithms(algorithms)
        self.leeway = leeway
        self.require = list(require)
        self._jwks = jwks

    async def validate(self, token: str) -> InboundToken:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenInvalid(Check.MALFORMED, "not a JWT") from exc

        alg = header.get("alg")
        if alg not in self.algorithms:
            raise TokenInvalid(Check.ALGORITHM, f"{alg!r} is not allowed")

        key = await self._jwks.key_for(header.get("kid"))
        if key is None:
            raise TokenInvalid(Check.SIGNATURE, "unknown signing key")

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=[alg],
                issuer=self.issuer,
                audience=list(self.audiences),
                leeway=self.leeway,
                options={"require": self.require},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenInvalid(Check.EXPIRED) from exc
        except jwt.ImmatureSignatureError as exc:
            raise TokenInvalid(Check.NOT_YET_VALID) from exc
        except jwt.MissingRequiredClaimError as exc:
            raise TokenInvalid(Check.MALFORMED, f"missing {exc.claim!r}") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenInvalid(Check.AUDIENCE) from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenInvalid(Check.ISSUER) from exc
        except jwt.InvalidSignatureError as exc:
            raise TokenInvalid(Check.SIGNATURE) from exc
        except jwt.InvalidAlgorithmError as exc:
            # The header named an allowed algorithm the published key cannot do.
            raise TokenInvalid(Check.ALGORITHM, "key does not match the algorithm") from exc
        except jwt.PyJWTError as exc:
            raise TokenInvalid(Check.MALFORMED) from exc

        return _inbound(token, claims)


def _inbound(token: str, claims: dict[str, Any]) -> InboundToken:
    subject = claims.get("sub")
    issuer = claims.get("iss")
    if not isinstance(subject, str) or not subject or not isinstance(issuer, str):
        raise TokenInvalid(Check.MALFORMED, "sub and iss must be strings")

    raw_aud = claims.get("aud")
    audiences = (raw_aud,) if isinstance(raw_aud, str) else tuple(raw_aud or ())

    client_id = claims.get("azp") or claims.get("client_id")
    scope = claims.get("scope")
    return InboundToken(
        issuer=issuer,
        subject=subject,
        client_id=client_id if isinstance(client_id, str) and client_id else None,
        audiences=audiences,
        scopes=tuple(scope.split()) if isinstance(scope, str) else (),
        expires_at=int(claims["exp"]) if "exp" in claims else 0,
        fingerprint=fingerprint(token),
        claims=claims,
    )


__all__ = [
    "DEFAULT_ALGORITHMS",
    "Check",
    "IdpUnavailable",
    "InboundToken",
    "JwksCache",
    "TokenInvalid",
    "TokenValidator",
    "check_algorithms",
    "fingerprint",
]
