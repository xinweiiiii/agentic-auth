"""RFC 9728 capability discovery.

Resolves each ``mcp://host[:port]/tool`` reference to an authority and fetches
``/.well-known/oauth-protected-resource``. A network/parse failure is never a silent
pass — it surfaces as a :class:`DiscoveryResult` with ``ok=False`` which the reconciler
turns into a ``DISCOVERY_UNAVAILABLE`` diff entry.

**Following ``authorization_servers``** (feature 011, M3, research R9), only with
``as_metadata_enabled``: for each resource whose metadata names an authorization server, the
first one's RFC 8414 metadata (or OIDC discovery) is fetched, because that is the server that
issues the scopes, and the one a client would use. The result rides on the
``DiscoveryResult``; the reconciler decides what it means.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict

from agentic_auth.oauth.metadata import MetadataUnavailable
from agentic_auth.oauth.metadata import discover as discover_authorization_server

WELL_KNOWN_PATH = "/.well-known/oauth-protected-resource"


class DiscoveredTool(BaseModel):
    model_config = ConfigDict(extra="ignore")
    data_classes: list[str] = []
    privileged: bool = False


class DiscoveredResource(BaseModel):
    model_config = ConfigDict(extra="ignore")
    resource: str = ""
    authorization_servers: list[str] = []
    scopes_supported: list[str] = []
    tools: dict[str, DiscoveredTool] = {}


@dataclass(frozen=True)
class DiscoveredAuthorizationServer:
    """What the resource's authorization server says it issues. ``issuer`` None means the
    resource named none; ``scopes_supported`` None means the server did not say."""

    issuer: str | None
    scopes_supported: tuple[str, ...] | None = None
    ok: bool = True
    error: str | None = None


@dataclass
class DiscoveryResult:
    authority: str
    ok: bool
    resource: DiscoveredResource | None = None
    error: str | None = None
    # 0.4.0. Set only when the check ran (as_metadata_enabled); None means "not attempted".
    authorization_server: DiscoveredAuthorizationServer | None = None


def _following_authorization_servers() -> bool:
    """Whether M3 is on, read lazily: this module ships in the ``drift`` extra, whose CLI
    registers manifests, and that install has no server settings (``pydantic-settings``)
    and therefore no M3 to turn on."""
    try:
        from agentic_auth.config import get_settings
    except ImportError:
        return False
    return get_settings().as_metadata_enabled


def authority_for(tool_ref: str) -> str:
    """``mcp://kb.internal:8443/search`` -> ``https://kb.internal:8443``."""
    parts = urlsplit(tool_ref)
    if parts.scheme != "mcp" or not parts.netloc:
        raise ValueError(f"not an mcp:// tool ref: {tool_ref!r}")
    return f"https://{parts.netloc}"


def tool_name(tool_ref: str) -> str:
    return urlsplit(tool_ref).path.lstrip("/")


class DiscoveryClient:
    def __init__(
        self,
        *,
        timeout: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._timeout = timeout
        self._client = client
        self._owns_client = client is None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def discover(self, authorities: set[str]) -> dict[str, DiscoveryResult]:
        client = await self._get_client()
        out: dict[str, DiscoveryResult] = {}
        for authority in sorted(authorities):
            url = authority.rstrip("/") + WELL_KNOWN_PATH
            try:
                resp = await client.get(url, timeout=self._timeout)
            except httpx.HTTPError as exc:  # timeout, connection error, etc.
                out[authority] = DiscoveryResult(authority, ok=False, error=str(exc))
                continue
            if resp.status_code != 200:
                out[authority] = DiscoveryResult(
                    authority, ok=False, error=f"HTTP {resp.status_code}"
                )
                continue
            try:
                resource = DiscoveredResource.model_validate(resp.json())
            except (ValueError, TypeError) as exc:
                out[authority] = DiscoveryResult(authority, ok=False, error=str(exc))
                continue
            result = DiscoveryResult(authority, ok=True, resource=resource)
            if _following_authorization_servers():
                result.authorization_server = await self._authorization_server(client, resource)
            out[authority] = result
        return out

    async def _authorization_server(
        self, client: httpx.AsyncClient, resource: DiscoveredResource
    ) -> DiscoveredAuthorizationServer:
        if not resource.authorization_servers:
            return DiscoveredAuthorizationServer(issuer=None)
        issuer = resource.authorization_servers[0]
        try:
            server = await discover_authorization_server(issuer, lambda: client)
        except MetadataUnavailable as exc:
            return DiscoveredAuthorizationServer(issuer, ok=False, error=str(exc))
        return DiscoveredAuthorizationServer(issuer, scopes_supported=server.scopes_supported)
