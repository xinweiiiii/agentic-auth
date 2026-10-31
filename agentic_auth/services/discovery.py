"""RFC 9728 capability discovery.

Resolves each ``mcp://host[:port]/tool`` reference to an authority and fetches
``/.well-known/oauth-protected-resource``. A network/parse failure is never a silent
pass — it surfaces as a :class:`DiscoveryResult` with ``ok=False`` which the reconciler
turns into a ``DISCOVERY_UNAVAILABLE`` diff entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict

WELL_KNOWN_PATH = "/.well-known/oauth-protected-resource"


class DiscoveredTool(BaseModel):
    model_config = ConfigDict(extra="ignore")
    data_classes: list[str] = []
    privileged: bool = False


class DiscoveredResource(BaseModel):
    model_config = ConfigDict(extra="ignore")
    resource: str = ""
    scopes_supported: list[str] = []
    tools: dict[str, DiscoveredTool] = {}


@dataclass
class DiscoveryResult:
    authority: str
    ok: bool
    resource: DiscoveredResource | None = None
    error: str | None = None


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
            out[authority] = DiscoveryResult(authority, ok=True, resource=resource)
        return out
