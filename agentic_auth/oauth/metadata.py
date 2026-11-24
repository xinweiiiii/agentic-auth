"""Authorization server metadata: reading an IdP's, and (M3) publishing our own.

Reading (research R2, R9): given an issuer, find its RFC 8414 document, falling back to
OIDC discovery, and return what the validator and the reconciler need from it. The
document's ``issuer`` must equal the one we asked about (RFC 8414 §3.3); a document that
names a different issuer is a misconfiguration or an attack, and either way its keys are
not the ones we were told to trust.

Like the rest of this package, this imports no database or control-plane settings.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

RFC8414_SUFFIX = "/.well-known/oauth-authorization-server"
OIDC_SUFFIX = "/.well-known/openid-configuration"


class MetadataUnavailable(Exception):
    """Neither discovery document could be fetched, parsed, or trusted."""


@dataclass(frozen=True)
class AuthorizationServer:
    issuer: str
    jwks_uri: str | None
    scopes_supported: tuple[str, ...] | None
    source: str  # the URL the document came from


def discovery_urls(issuer: str) -> list[str]:
    """RFC 8414 §3.1 inserts the well-known segment before any issuer path; OIDC
    Discovery §4 appends it. For a path-less issuer the two only differ in the suffix."""
    url = httpx.URL(issuer.rstrip("/"))
    origin = f"{url.scheme}://{url.netloc.decode()}"
    path = url.path.rstrip("/")
    return [f"{origin}{RFC8414_SUFFIX}{path}", f"{origin}{path}{OIDC_SUFFIX}"]


async def discover(issuer: str, http: Callable[[], httpx.AsyncClient]) -> AuthorizationServer:
    """Fetch ``issuer``'s metadata, RFC 8414 first. Raises ``MetadataUnavailable``."""
    failures: list[str] = []
    for url in discovery_urls(issuer):
        try:
            response = await http().get(url)
        except httpx.HTTPError as exc:
            failures.append(f"{url}: {type(exc).__name__}")
            continue
        if response.status_code != 200:
            failures.append(f"{url}: HTTP {response.status_code}")
            continue
        try:
            document: Any = response.json()
        except ValueError:
            failures.append(f"{url}: not JSON")
            continue
        if not isinstance(document, dict):
            failures.append(f"{url}: not a JSON object")
            continue
        if document.get("issuer") != issuer:
            failures.append(f"{url}: names issuer {document.get('issuer')!r}, not {issuer!r}")
            continue
        return AuthorizationServer(
            issuer=issuer,
            jwks_uri=_string(document.get("jwks_uri")),
            scopes_supported=_strings(document.get("scopes_supported")),
            source=url,
        )
    raise MetadataUnavailable("; ".join(failures))


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _strings(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    return tuple(v for v in value if isinstance(v, str))


# -- publishing our own (M3, research R8) -----------------------------------------------------

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def authorization_server_metadata(
    issuer: str, *, scopes: list[str] | set[str], transaction_tokens: bool
) -> dict[str, Any]:
    """The control plane's RFC 8414 document.

    The only honest metadata for a server that issues tokens by exchange alone: no
    ``authorization_endpoint`` (logins happen at the customer's IdP, PRD §4.2) and no
    ``registration_endpoint`` (clients register there too, spec FR-015). Every URL is built
    from ``issuer``, which RFC 8414 requires to be the token ``iss``.
    """
    base = issuer.rstrip("/")
    document: dict[str, Any] = {
        "issuer": issuer,
        "token_endpoint": f"{base}/v1/token/exchange",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "grant_types_supported": [TOKEN_EXCHANGE_GRANT],
        # The subject and actor tokens are the credentials; there is no client secret.
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": sorted(set(scopes)),
        "agentic_auth_consent_endpoint": f"{base}/v1/consent",
    }
    if transaction_tokens:
        document["agentic_auth_transaction_endpoint"] = f"{base}/v1/token/transaction"
    return document


__all__ = [
    "AuthorizationServer",
    "MetadataUnavailable",
    "authorization_server_metadata",
    "discover",
    "discovery_urls",
]
