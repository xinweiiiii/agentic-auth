"""A connector proxy or gateway as an OAuth 2.1 protected resource (feature 011, M1).

What an off-the-shelf MCP client needs from the thing it calls, and nothing more:

- **Protected Resource Metadata** (RFC 9728) naming this resource, the customer's IdP as its
  authorization server, and the scopes it accepts. A scope is a data class name (research
  R7), the same vocabulary as the token exchange.
- **Challenges** (RFC 6750 §3): ``401`` with ``WWW-Authenticate`` pointing at that metadata
  when there is no token or a bad one, ``403 insufficient_scope`` when a valid token's
  ``scope`` claim does not cover the call. Every ``401`` carries ``resource_metadata``
  (INV-3).
- **A gate** that validates the inbound token locally, before anything else sees it, then
  turns it into a session by calling consent with it as ``subject_token``, under a
  credential that can call consent and nothing else (research R1, R3). The session is cached
  by the token's hash until the earlier of the token's and the session's expiry, so one
  login is one consent.

The inbound token is never forwarded anywhere but consent, and never logged: refusals carry
its fingerprint. Like the rest of this package this imports no database or control-plane
settings, so it deploys wherever the proxy does.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from agentic_auth.oauth.validate import IdpUnavailable, InboundToken, TokenInvalid, TokenValidator

logger = logging.getLogger(__name__)

WELL_KNOWN = "/.well-known/oauth-protected-resource"
RESOURCE_NAME = "Agentic Auth protected resource"

# Characters that would let a value escape its quoted-string in a challenge (RFC 7230 §3.2.6).
_UNSAFE_IN_QUOTES = frozenset('"\\\r\n')


# -- metadata -------------------------------------------------------------------------------


def _split(resource_url: str) -> tuple[str, str]:
    url = httpx.URL(resource_url)
    return f"{url.scheme}://{url.netloc.decode()}", url.path.rstrip("/")


def metadata_url(resource_url: str) -> str:
    """Where a client fetches this resource's metadata (RFC 9728 §3.1)."""
    origin, path = _split(resource_url)
    return f"{origin}{WELL_KNOWN}{path}"


def metadata_paths(resource_url: str) -> list[str]:
    """The paths the metadata is served at: the RFC 9728 form first, and for a resource with
    a path also the root form, which some clients try first."""
    _, path = _split(resource_url)
    return [f"{WELL_KNOWN}{path}", WELL_KNOWN] if path else [WELL_KNOWN]


def protected_resource_metadata(
    resource_url: str, authorization_server: str, *, scopes: Iterable[str]
) -> dict[str, Any]:
    return {
        "resource": resource_url,
        "authorization_servers": [authorization_server],
        "scopes_supported": sorted(set(scopes)),
        # The query string and form body are refused (MCPA-RS-BEARER): a token there ends up
        # in logs and Referer headers.
        "bearer_methods_supported": ["header"],
        "resource_name": RESOURCE_NAME,
    }


def challenge(
    resource_url: str,
    *,
    scopes: Iterable[str],
    error: str | None = None,
    description: str | None = None,
) -> str:
    """A ``WWW-Authenticate`` value. Never carries token content: ``description`` is a
    ``Check`` value, not a message."""
    params: list[tuple[str, str]] = []
    if error is not None:
        params.append(("error", error))
    if description is not None:
        params.append(("error_description", description))
    params.append(("resource_metadata", metadata_url(resource_url)))
    scope = " ".join(sorted(set(scopes)))
    if scope:
        params.append(("scope", scope))
    for _, value in params:
        if _UNSAFE_IN_QUOTES & set(value):
            raise ValueError("challenge parameter contains a character that breaks quoting")
    return "Bearer " + ", ".join(f'{name}="{value}"' for name, value in params)


# -- the session cache ----------------------------------------------------------------------


@dataclass(frozen=True)
class SessionEntry:
    root_grant: str = field(repr=False)
    session_id: str
    expires_at: float  # epoch seconds


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SessionCache:
    """IdP token → session, in memory, bounded and least-recently-used.

    Keyed by the token's full SHA-256, never the token. An entry never outlives either the
    IdP token or the session it maps to; on eviction the next call simply consents again.
    """

    def __init__(self, max_entries: int = 10_000, *, clock: Callable[[], float] = time.time):
        if max_entries < 1:
            raise ValueError("the session cache needs room for at least one entry")
        self._max = max_entries
        self._clock = clock
        self._entries: OrderedDict[str, SessionEntry] = OrderedDict()

    def get(self, token: str) -> SessionEntry | None:
        key = _hash(token)
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires_at <= self._clock():
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return entry

    def put(self, token: str, entry: SessionEntry) -> None:
        if entry.expires_at <= self._clock():
            return
        key = _hash(token)
        self._entries[key] = entry
        self._entries.move_to_end(key)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def hashes(self) -> list[str]:
        """The keys held: token hashes, never tokens."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


# -- the gate ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Admitted:
    """The inbound token is valid and has a session. ``root_grant`` is what ``enforce()``
    presents; the inbound token goes no further."""

    root_grant: str = field(repr=False)
    session_id: str
    inbound: InboundToken


@dataclass(frozen=True)
class Refused:
    """Why the call stops here, in the shape the enforcement point renders.

    ``kind``:

    - ``challenge``: answer in HTTP with ``status`` and ``www_authenticate``. MCP clients
      discover authorization from the HTTP layer, so this is never a JSON-RPC error.
    - ``consent``: consent refused the session. A policy refusal, rendered the way every
      other refusal is, with ``reason`` and ``recoverable``.
    - ``infra``: the IdP or the control plane could not be asked. Retryable, never an allow.
    """

    kind: str
    status: int
    reason: str  # an edge-trace reason: ^[A-Z_]{1,32}$
    message: str
    recoverable: bool = False
    www_authenticate: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    fingerprint: str | None = None


@dataclass
class ResourceGate:
    resource_url: str
    authorization_server: str
    scopes: tuple[str, ...]
    validator: TokenValidator
    pdp_url: str
    consent_token: str = field(repr=False)
    http: httpx.AsyncClient = field(repr=False)
    cache: SessionCache = field(default_factory=SessionCache)
    # The scope to ask consent for. None lets consent choose: with client mapping (M4) on,
    # it is the scope of the agent the token's client maps to.
    consent_scope: str | None = None
    # Set only for a control plane with verified consent off (research R10): consent is then
    # called with the validated subject as an *asserted* user_sub and this scope. The weaker
    # root, chosen by the operator, never fallen back to.
    asserted_root_scope: str | None = None
    timeout_seconds: float = 2.0

    @property
    def asserted_root(self) -> bool:
        return self.asserted_root_scope is not None

    def metadata(self) -> dict[str, Any]:
        return protected_resource_metadata(
            self.resource_url, self.authorization_server, scopes=self.scopes
        )

    def _challenge(self, **kwargs: Any) -> str:
        return challenge(self.resource_url, scopes=self.scopes, **kwargs)

    async def admit(
        self,
        headers: Mapping[str, str],
        query: Mapping[str, str],
        *,
        data_class: str | None = None,
    ) -> Admitted | Refused:
        if "access_token" in query:
            # RFC 6750 §2.3 is a MAY we refuse: a token in a URL is a token in every log.
            return Refused(
                "challenge",
                400,
                "TOKEN_IN_QUERY",
                "send the access token in the Authorization header, not the query string",
                www_authenticate=self._challenge(
                    error="invalid_request", description="token_in_query"
                ),
            )

        authorization = headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or not authorization[7:].strip():
            return Refused(
                "challenge",
                401,
                "TOKEN_MISSING",
                "this resource requires an access token from its authorization server",
                www_authenticate=self._challenge(),
            )
        token = authorization[7:].strip()

        try:
            inbound = await self.validator.validate(token)
        except TokenInvalid as exc:
            refused = Refused(
                "challenge",
                401,
                "INVALID_TOKEN",
                f"access token refused: {exc.check.value}",
                www_authenticate=self._challenge(
                    error="invalid_token", description=exc.check.value
                ),
                details={"check": exc.check.value},
            )
            return _logged(refused, token)
        except IdpUnavailable:
            return _logged(
                Refused(
                    "infra",
                    503,
                    "IDP_UNAVAILABLE",
                    "the authorization server's keys could not be obtained; retry",
                    recoverable=True,
                ),
                token,
            )

        if data_class is not None and inbound.scopes and data_class not in inbound.scopes:
            return _logged(
                Refused(
                    "challenge",
                    403,
                    "INSUFFICIENT_SCOPE",
                    f"the access token's scope does not include {data_class!r}",
                    www_authenticate=challenge(
                        self.resource_url, scopes=[data_class], error="insufficient_scope"
                    ),
                ),
                token,
            )

        cached = self.cache.get(token)
        if cached is not None:
            return Admitted(cached.root_grant, cached.session_id, inbound)
        return await self._consent(token, inbound)

    async def _consent(self, token: str, inbound: InboundToken) -> Admitted | Refused:
        body: dict[str, Any]
        if self.asserted_root_scope is not None:
            body = {"scope": self.asserted_root_scope, "user_sub": inbound.principal}
        else:
            body = {"subject_token": token}
            if self.consent_scope is not None:
                body["scope"] = self.consent_scope
        try:
            response = await self.http.post(
                f"{self.pdp_url}/v1/consent",
                headers={"Authorization": f"Bearer {self.consent_token}"},
                json=body,
                timeout=httpx.Timeout(self.timeout_seconds),
            )
        except Exception as exc:
            logger.warning("consent unreachable: %s", type(exc).__name__)
            return _logged(
                Refused(
                    "infra",
                    503,
                    "PDP_UNAVAILABLE",
                    "the control plane could not be reached to start a session; retry",
                    recoverable=True,
                ),
                token,
            )

        if response.status_code == 201:
            session = response.json()
            expires = min(float(inbound.expires_at), _epoch(session.get("expires_at")))
            entry = SessionEntry(session["root_grant"], session["session_id"], expires)
            self.cache.put(token, entry)
            return Admitted(entry.root_grant, entry.session_id, inbound)
        return _logged(_consent_refusal(response), token)


def _epoch(value: Any) -> float:
    from datetime import datetime

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0  # unparseable: cache nothing rather than guess a lifetime


def _consent_refusal(response: httpx.Response) -> Refused:
    try:
        error = response.json().get("error") or {}
    except ValueError:
        error = {}
    code = str(error.get("code") or "consent_refused")
    raw_details = error.get("details")
    details: dict[str, Any] = raw_details if isinstance(raw_details, dict) else {}
    message = str(error.get("message") or "consent refused")
    if response.status_code >= 500:
        return Refused("infra", 503, code.upper()[:32], message, recoverable=True, details=details)
    # Consent's own refusals carry a DenyReason in details (CLIENT_NOT_AUTHORIZED) or an
    # envelope code (subject_token_invalid). Either way, upper-cased it is an edge reason.
    reason = str(details.get("reason") or code).upper()[:32]
    return Refused(
        "consent",
        403,
        reason,
        message,
        recoverable=bool(details.get("recoverable", False)),
        details=details,
    )


def _logged(refused: Refused, token: str) -> Refused:
    """Every refusal after a token was presented is logged with its fingerprint, the only
    trace of the token anywhere (INV-4)."""
    from agentic_auth.oauth.validate import fingerprint

    fp = fingerprint(token)
    logger.info(
        "inbound token refused",
        extra={"reason": refused.reason, "kind": refused.kind, "token_fingerprint": fp},
    )
    return Refused(**{**refused.__dict__, "fingerprint": fp})


def gate_for(config: Any, http: httpx.AsyncClient) -> ResourceGate:
    """The gate a connector proxy or gateway runs, from its configuration.

    ``config`` is a ``GatewayConfig``; typed loosely so this package does not import the
    gateway's. The JWKS is fetched through the proxy's own client: whatever reaches the IdP
    for the operator reaches it here.
    """
    from agentic_auth.oauth.validate import JwksCache

    if config.asserted_root_scope is not None:
        logger.warning(
            "protected resource is rooting sessions in an ASSERTED subject (scope %r): the "
            "control plane does not verify the user's token. Turn on verified consent there "
            "and unset ASSERTED_ROOT_SCOPE for a verified root.",
            config.asserted_root_scope,
        )
    jwks = JwksCache(
        config.idp_jwks_url,
        lambda: http,
        discover_from=None if config.idp_jwks_url else config.idp_issuer,
    )
    return ResourceGate(
        resource_url=config.resource_url,
        authorization_server=config.idp_issuer,
        scopes=config.scopes_supported,
        validator=TokenValidator(
            issuer=config.idp_issuer,
            audiences=[config.resource_url],
            jwks=jwks,
            algorithms=config.idp_algorithms,
            leeway=config.clock_leeway_seconds,
        ),
        pdp_url=config.pdp_url,
        consent_token=config.consent_token,
        http=http,
        cache=SessionCache(config.session_cache_size),
        consent_scope=config.consent_scope,
        asserted_root_scope=config.asserted_root_scope,
        timeout_seconds=config.control_plane_timeout_seconds,
    )


async def startup_check(config: Any, http: httpx.AsyncClient | None = None) -> str | None:
    """Fetch the IdP's keys once before serving. Returns why the process must not start, or
    None. A protected resource that cannot validate any token would refuse every call while
    looking healthy (FR-020, FR-021)."""
    if not config.oauth_resource_enabled:
        return None
    from agentic_auth.oauth.validate import JwksCache

    owned = http is None
    client = http or httpx.AsyncClient(timeout=httpx.Timeout(10.0))
    jwks = JwksCache(
        config.idp_jwks_url,
        lambda: client,
        discover_from=None if config.idp_jwks_url else config.idp_issuer,
    )
    try:
        await jwks.prime()
    except IdpUnavailable as exc:
        setting = "IDP_JWKS_URL" if config.idp_jwks_url else "IDP_ISSUER (or set IDP_JWKS_URL)"
        return f"the IdP's signing keys could not be fetched: {exc}. Check {setting}."
    finally:
        if owned:
            await client.aclose()
    return None


__all__ = [
    "Admitted",
    "Refused",
    "ResourceGate",
    "SessionCache",
    "SessionEntry",
    "challenge",
    "gate_for",
    "startup_check",
    "metadata_paths",
    "metadata_url",
    "protected_resource_metadata",
]
