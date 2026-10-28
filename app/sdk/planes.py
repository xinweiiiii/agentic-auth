"""The three read/admin planes, as the SDK exposes them.

The hop path (``consent`` → ``authorize`` → ``call``) is what an agent runs. These are
what everything *around* the agent runs: the pipeline that registers manifests, the
auditor that reads decision history, the resource server that bootstraps identity
material. Same base URL, different credential — which is the point of splitting them:

====================  =========================  ==================================
``client.admin``      admin bearer               register, submit, catalogs, reports
``client.audit``      audit-reader bearer        decision history, delegation chains
``client.identity``   identity-reader bearer     agent identity, revocation list
====================  =========================  ==================================

``client.audit`` and ``client.identity`` send the read-only token when one is configured
and fall back to the admin token, so a notebook or a test can hold one credential while
production holds three. An auditor should never need the bearer that can record consent.

Every method raises rather than returning something falsy, for the same reason
``authorize`` does: see :mod:`app.sdk.errors`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import httpx

from app.sdk.errors import ControlPlaneRejected, ControlPlaneUnavailable, ManifestRejected

# Reconciliation outcomes, which the manifest routes report as error envelopes even though
# nothing is wrong with the request shape (contracts: 422 hard reject, 409 needs review).
_MANIFEST_OUTCOMES = frozenset({"reconciliation_rejected", "needs_review"})


def _params(**values: Any) -> dict[str, Any]:
    """Query parameters, minus the ones not asked for. A ``None`` must not be sent as the
    string ``"None"`` — the server would reject it as an invalid filter value."""
    return {k: v for k, v in values.items() if v is not None}


@dataclass(frozen=True)
class Transport:
    """One HTTP conversation with the control plane, shared by every plane."""

    client: httpx.AsyncClient
    base_url: str
    timeout: httpx.Timeout

    async def json(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json: Any = None,
        params: dict[str, Any] | None = None,
        expect: tuple[int, ...] = (200,),
    ) -> Any:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            response = await self.client.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                json=json,
                params=params,
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise ControlPlaneUnavailable(f"{method} {path} failed: {exc}") from exc

        if response.status_code in expect:
            return _decode(response, method, path)
        raise _refusal(response, method, path)


def _decode(response: httpx.Response, method: str, path: str) -> Any:
    try:
        return response.json()
    except ValueError as exc:
        raise ControlPlaneUnavailable(f"{method} {path} returned an unusable body: {exc}") from exc


def _refusal(response: httpx.Response, method: str, path: str) -> Exception:
    """A 4xx is the caller's to fix; anything else is an outage, and the two are never
    conflated — one is worth retrying unchanged and the other never is."""
    if not 400 <= response.status_code < 500:
        return ControlPlaneUnavailable(
            f"{method} {path} returned {response.status_code}: {response.text[:500]}"
        )
    try:
        body = response.json()
    except ValueError:
        # A refusal with no parseable body is still a refusal; the status carries it.
        body = {}
    envelope = body.get("error") if isinstance(body, dict) else None
    if isinstance(envelope, dict):
        code = str(envelope.get("code", "error"))
        message = str(envelope.get("message", response.text[:500]))
        details = envelope.get("details") if isinstance(envelope.get("details"), dict) else None
    else:
        # The token endpoint speaks OAuth (RFC 6749 §5.2), not this envelope.
        code = str(envelope or "error")
        message = (
            str(body.get("error_description", response.text[:500]))
            if isinstance(body, dict)
            else response.text[:500]
        )
        details = None
    kind = ManifestRejected if code in _MANIFEST_OUTCOMES else ControlPlaneRejected
    return kind(
        status=response.status_code,
        code=code,
        message=message,
        details=details,
        method=method,
        path=path,
    )


@dataclass(frozen=True)
class AgentRegistration:
    """What ``register_agent`` returns on a 201. ``status`` is the reconciliation verdict:
    ``reconciled`` (discovery agreed) or ``needs_review`` (an override was attested)."""

    agent_id: str
    manifest_version: int
    status: str


@dataclass(frozen=True)
class ManifestSubmission:
    agent: str
    version: int
    status: str


class AdminPlane:
    """Registration, manifest versions, compiled catalogs, reconciliation reports.

    Everything here needs the admin bearer. It is the pipeline's credential, not an
    agent's: nothing on the hop path uses it.
    """

    def __init__(self, transport: Transport, token: str | None) -> None:
        self._t = transport
        self._token = token

    # -- registration ----------------------------------------------------------

    async def register_agent(
        self,
        name: str,
        manifest: dict[str, Any],
        *,
        override_reason: str | None = None,
    ) -> AgentRegistration:
        """Register an agent and its first manifest version.

        The manifest is reconciled against what each tool's host advertises
        (RFC 9728 capability discovery) before anything is compiled. Raises
        :class:`ManifestRejected` when the declaration exceeds what is discoverable, and
        again — with ``needs_review`` — when discovery could not be reached. Pass
        ``override_reason`` to proceed on the second case: it is stored as the human
        attestation for that version, so the gap is recorded rather than hidden.
        """
        body: dict[str, Any] = {"name": name, "manifest": manifest}
        if override_reason is not None:
            body["override"] = {"reason": override_reason}
        created = await self._t.json(
            "POST", "/v1/agents", token=self._token, json=body, expect=(201,)
        )
        return AgentRegistration(
            agent_id=created["agent_id"],
            manifest_version=created["manifest_version"],
            status=created["status"],
        )

    async def submit_manifest(
        self,
        agent: str,
        manifest: dict[str, Any],
        *,
        override_reason: str | None = None,
    ) -> ManifestSubmission:
        """Add a new, immutable manifest version for an agent that already exists.

        Sessions keep the policy version they were consented under, so a submission never
        changes a decision already in flight.
        """
        body: dict[str, Any] = {"agent": agent, "manifest": manifest}
        if override_reason is not None:
            body["override"] = {"reason": override_reason}
        created = await self._t.json(
            "POST", "/v1/manifests", token=self._token, json=body, expect=(201,)
        )
        return ManifestSubmission(
            agent=created["agent"], version=created["version"], status=created["status"]
        )

    # -- reads -----------------------------------------------------------------

    async def manifest(self, scope: str, *, version: int | None = None) -> dict[str, Any]:
        """One stored manifest version, verbatim. Omit ``version`` for the latest."""
        return await self._t.json(
            "GET",
            f"/v1/manifests/{scope}",
            token=self._token,
            params=_params(version=version),
        )

    async def agents(
        self, *, status: str | None = None, limit: int | None = None, cursor: str | None = None
    ) -> dict[str, Any]:
        """One page of registered agents: ``{"data": [...], "page": {...}}``."""
        return await self._t.json(
            "GET",
            "/v1/agents",
            token=self._token,
            params=_params(status=status, limit=limit, cursor=cursor),
        )

    async def agent_id(self, name: str) -> str:
        """Resolve an agent name to the id that ``enroll`` and ``revoke`` address.

        Registration already returns it; this is for the pipeline that comes back later
        holding only a name.
        """
        cursor: str | None = None
        while True:
            page = await self.agents(limit=100, cursor=cursor)
            for item in page["data"]:
                if item["name"] == name:
                    return str(item["id"])
            cursor = page["page"].get("next_cursor")
            if not cursor:
                raise ControlPlaneRejected(
                    status=404,
                    code="not_found",
                    message=f"no agent named {name!r} is registered",
                    method="GET",
                    path="/v1/agents",
                )

    async def reconciliation(self, agent_id: str | uuid.UUID) -> dict[str, Any]:
        """The latest reconciliation report: the diff between what the agent declared and
        what its tools advertise. Empty ``diff`` with ``discovery_ok`` is a clean pass."""
        return await self._t.json("GET", f"/v1/agents/{agent_id}/reconciliation", token=self._token)

    async def scope_catalog(self, scope: str, *, version: int | None = None) -> dict[str, Any]:
        """What consenting to ``scope`` actually grants: every tool, data class, declared
        downstream agent and the hop budget, as compiled. This is what a consent screen
        should be built from — not the manifest, which is the declaration, not the DAG."""
        return await self._t.json(
            "GET",
            f"/v1/scopes/{scope}/catalog",
            token=self._token,
            params=_params(version=version),
        )


class AuditPlane:
    """The read-only audit plane. Nothing here writes: audit rows are created only by the
    decision path, and the database refuses to change them afterwards."""

    def __init__(self, transport: Transport, token: str | None) -> None:
        self._t = transport
        self._token = token

    async def chain(self, action_id: str | uuid.UUID) -> dict[str, Any]:
        """The full delegation chain for one recorded action, back to the consenting human.

        Every :class:`~app.sdk.errors.PolicyDenied` carries the ``action_id`` to pass here,
        so "why was this refused, and who asked for it" is one call from the exception.
        """
        return await self._t.json("GET", f"/v1/audit/actions/{action_id}/chain", token=self._token)

    async def decisions(
        self,
        *,
        session_id: str | None = None,
        agent: str | None = None,
        outcome: str | None = None,
        deny_reason: str | None = None,
        enforced: bool | None = None,
        target_kind: str | None = None,
        since: str | None = None,
        until: str | None = None,
        taint: str | None = None,
        privileged: bool | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Filtered decision history, newest first, stable under concurrent appends.

        ``enforced=False`` is the observe-mode query: every call that *would* have been
        blocked. Booleans go on the wire lowercased, as the API's filters expect.
        """
        return await self._t.json(
            "GET",
            "/v1/audit/decisions",
            token=self._token,
            params=_params(
                session_id=session_id,
                agent=agent,
                outcome=outcome,
                deny_reason=deny_reason,
                enforced=None if enforced is None else str(enforced).lower(),
                target_kind=target_kind,
                since=since,
                until=until,
                taint=taint,
                privileged=None if privileged is None else str(privileged).lower(),
                limit=limit,
                cursor=cursor,
            ),
        )


class IdentityPlane:
    """What an offline verifier bootstraps from, and what an operator reads back.

    A resource server needs exactly these two routes and an identity-reader bearer — it
    cannot list agents, and does not need to.
    """

    def __init__(self, transport: Transport, token: str | None) -> None:
        self._t = transport
        self._token = token

    async def of(self, agent_name: str) -> dict[str, Any]:
        """One agent's pinned identity: status, trust-anchor version, public JWKS, whether
        it is revoked, and the ``as_of`` the view was taken."""
        return await self._t.json("GET", f"/v1/identity/agents/{agent_name}", token=self._token)

    async def by_id(self, agent_id: str | uuid.UUID) -> dict[str, Any]:
        """The same material, addressed by agent id."""
        return await self._t.json("GET", f"/v1/agents/{agent_id}/identity", token=self._token)

    async def revocations(
        self, *, since: str | None = None, limit: int | None = None, cursor: str | None = None
    ) -> dict[str, Any]:
        """Revoked agents, newest first. ``as_of`` is the freshness a verifier refuses on:
        past its own window without a successful refresh, every identity is stale."""
        return await self._t.json(
            "GET",
            "/v1/identity/revocations",
            token=self._token,
            params=_params(since=since, limit=limit, cursor=cursor),
        )


__all__ = [
    "AdminPlane",
    "AgentRegistration",
    "AuditPlane",
    "IdentityPlane",
    "ManifestSubmission",
    "Transport",
]
