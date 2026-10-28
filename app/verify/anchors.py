"""Where a resource gets the keys it verifies against — and how fresh that view is.

Two kinds of material: the control plane's issuer JWKS (hop and transaction tokens) and
each agent's pinned trust anchor (identity assertions). ``Static*`` variants are for tests
and air-gapped deployments; ``Http*`` variants bootstrap once and refresh in the
background. Every verification is a dictionary lookup: no I/O on the request path.

Freshness is a property the verifier refuses on. ``as_of()`` is the last successful
refresh; past ``freshness_seconds`` every identity is ``IDENTITY_STALE`` until a refresh
succeeds (spec FR-040). A store that never bootstrapped refuses everything.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

logger = logging.getLogger(__name__)


# -- issuer keys -------------------------------------------------------------------------


class JwksSource(Protocol):
    def jwks(self) -> Mapping[str, Any] | None: ...


class StaticJwks:
    def __init__(self, jwks: Mapping[str, Any]) -> None:
        self._jwks = dict(jwks)

    def jwks(self) -> Mapping[str, Any]:
        return self._jwks


class HttpJwks:
    """Fetches ``GET {url}`` once at bootstrap and on every refresh."""

    def __init__(self, url: str, *, client: Any = None) -> None:
        self._url = url
        self._client = client
        self._jwks: dict[str, Any] | None = None

    def jwks(self) -> Mapping[str, Any] | None:
        return self._jwks

    async def refresh(self) -> None:
        import httpx

        client = self._client or httpx.AsyncClient(timeout=httpx.Timeout(5.0))
        try:
            response = await client.get(self._url)
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
                raise ValueError("JWKS document is malformed")
            self._jwks = body
        finally:
            if self._client is None:
                await client.aclose()


# -- trust anchors ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Anchor:
    """One agent's identity material, as ``GET /v1/agents/{id}/identity`` serves it."""

    agent: str
    status: str
    trust_anchor_version: int | None
    jwks: Mapping[str, Any] | None
    revoked: bool

    @staticmethod
    def from_read(read: Mapping[str, Any]) -> Anchor:
        return Anchor(
            agent=str(read["agent"]),
            status=str(read.get("status", "registered")),
            trust_anchor_version=read.get("trust_anchor_version"),
            jwks=read.get("jwks"),
            revoked=bool(read.get("revoked", False)) or read.get("status") == "revoked",
        )

    @property
    def live(self) -> bool:
        return self.status == "enrolled" and not self.revoked and self.jwks is not None


class AnchorStore(Protocol):
    def current(self, agent: str) -> Anchor | None: ...
    def revoked(self, agent: str) -> bool: ...
    def as_of(self) -> datetime | None: ...


class StaticAnchors:
    """Anchors shipped as data. Never stale: the integrator owns rotation."""

    def __init__(self, reads: Iterable[Mapping[str, Any]]) -> None:
        self._anchors = {a.agent: a for a in (Anchor.from_read(r) for r in reads)}
        self._as_of = datetime.now(UTC)

    def current(self, agent: str) -> Anchor | None:
        return self._anchors.get(agent)

    def revoked(self, agent: str) -> bool:
        anchor = self._anchors.get(agent)
        return anchor is not None and anchor.revoked

    def as_of(self) -> datetime | None:
        return self._as_of

    def revoke(self, agent: str) -> None:  # tests and manual operations
        anchor = self._anchors.get(agent)
        if anchor is not None:
            self._anchors[agent] = Anchor(
                anchor.agent, "revoked", anchor.trust_anchor_version, anchor.jwks, True
            )


def _is_unknown_agent(response: Any) -> bool:
    """The control plane answers an unregistered agent with its error envelope
    (``{"error": {"code": "not_found"}}``). A bare ``{"detail": "Not Found"}`` is the
    framework saying the route does not exist — a deployment problem that must fail the
    bootstrap, not be mistaken for an agent nobody registered."""
    try:
        body = response.json()
    except ValueError:
        return False
    return isinstance(body, dict) and isinstance(body.get("error"), dict)


@dataclass
class HttpAnchors:
    """Bootstraps each configured agent's identity and the revocation list from the
    control plane, then refreshes every ``freshness_seconds``.

    ``token`` is an identity-reader bearer (the audit reader or admin token) — it needs no
    other privilege. ``agents`` are the names this resource expects to see; an agent outside
    the list is ``IDENTITY_UNKNOWN_AGENT`` until the list is widened.
    """

    base_url: str
    token: str
    agents: list[str]
    freshness_seconds: int = 30
    client: Any = None
    clock: Any = time.monotonic
    _anchors: dict[str, Anchor] = field(default_factory=dict)
    _as_of: datetime | None = None
    _as_of_mono: float | None = None
    _revocations_since: str | None = None
    _task: asyncio.Task[None] | None = None

    def current(self, agent: str) -> Anchor | None:
        return self._anchors.get(agent)

    def revoked(self, agent: str) -> bool:
        anchor = self._anchors.get(agent)
        return anchor is not None and anchor.revoked

    def as_of(self) -> datetime | None:
        return self._as_of

    def age_seconds(self) -> float | None:
        return None if self._as_of_mono is None else self.clock() - self._as_of_mono

    # -- I/O ----------------------------------------------------------------------

    def _http(self) -> Any:
        import httpx

        return self.client or httpx.AsyncClient(timeout=httpx.Timeout(5.0))

    async def bootstrap(self) -> None:
        """Fetch everything once. Raises on failure: a verifier must not start with an
        empty view and admit nothing while looking healthy — it must fail to start."""
        await self.refresh(raise_on_error=True)

    async def refresh(self, *, raise_on_error: bool = False) -> bool:
        """Refresh the view. Returns ``True`` on success. On failure the previous view is
        kept and ``as_of`` keeps ageing toward stale."""
        http = self._http()
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            fresh: dict[str, Anchor] = {}
            for name in self.agents:
                r = await http.get(f"{self.base_url}/v1/identity/agents/{name}", headers=headers)
                if r.status_code == 404 and _is_unknown_agent(r):
                    continue  # never registered: unknown, not an error
                r.raise_for_status()  # a 404 WITHOUT the error envelope is a missing route
                fresh[name] = Anchor.from_read(r.json())
            revoked = await http.get(
                f"{self.base_url}/v1/identity/revocations?limit=100", headers=headers
            )
            revoked.raise_for_status()
            for item in revoked.json().get("items", []):
                name = item["agent"]
                anchor = fresh.get(name)
                if anchor is not None and not anchor.revoked:
                    fresh[name] = Anchor(
                        anchor.agent, "revoked", anchor.trust_anchor_version, anchor.jwks, True
                    )
            self._anchors = fresh
            self._as_of = datetime.now(UTC)
            self._as_of_mono = self.clock()
            return True
        except Exception as exc:
            logger.warning("anchor refresh failed: %s", type(exc).__name__)
            if raise_on_error:
                raise
            return False
        finally:
            if self.client is None:
                await http.aclose()

    def start(self) -> None:
        """Refresh in the background every ``freshness_seconds / 2``."""
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(max(self.freshness_seconds / 2, 1))
            await self.refresh()


__all__ = [
    "Anchor",
    "AnchorStore",
    "HttpAnchors",
    "HttpJwks",
    "JwksSource",
    "StaticAnchors",
    "StaticJwks",
]
