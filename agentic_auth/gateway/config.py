"""Gateway configuration — see ``contracts/gateway.openapi.yaml``.

Startup is strict for the same reason the sidecar's is: a gateway that comes up but cannot
enforce is worse than one that refuses to start, because the first looks healthy while
forwarding everything. Centrally, that is worse again — it is every agent at once.

**Two things a gateway deliberately cannot have**, and both raise at construction:

1. **A signing key.** ``SidecarConfig`` takes ``agent_name`` + ``identity_key_path`` and
   signs an ``actor_token`` per exchange. A gateway serving many agents holding all their
   private keys would be exactly the single component that can impersonate every one of
   them — the thing the identity/authorization split exists to prevent. The gateway relays
   agent-supplied identity headers instead (research.md R2).
2. **An empty route table.** Same rule as the sidecar: an empty map forwards nothing and
   silently blocks everything.

The route table is keyed by ``(agent, prefix)`` rather than ``prefix`` alone, because one
shared table serves many agents and ``/kb`` may mean different targets for different ones.
``agent=None`` is the any-agent fallback (research.md R4).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from agentic_auth.boundary.guarantee import Guarantee
from agentic_auth.oauth.validate import DEFAULT_ALGORITHMS, DEFAULT_LEEWAY_SECONDS, check_algorithms
from agentic_auth.sidecar.config import Upstream

ENV_PREFIX = "AGENTIC_AUTH_GATEWAY_"

# A route table key: (agent name or None for "any agent", path prefix).
RouteKey = tuple[str | None, str]


class GatewayConfigError(ValueError):
    """The gateway cannot be configured to enforce anything."""


@dataclass(frozen=True)
class GatewayConfig:
    pdp_url: str
    listen_addr: str = "0.0.0.0:8080"
    # (agent | None, prefix) -> upstream. Longest prefix wins; an agent-specific entry
    # beats the any-agent fallback for the same prefix.
    route_table: dict[RouteKey, Upstream] = field(default_factory=dict)
    observe_mode: bool = False
    request_timeout_seconds: float = 30.0
    # Bound on the whole decision. Past it the call is REFUSED, never retried: a slow
    # decision is no decision (FR-003). Defaults to the sidecar's 2s so the gateway is
    # not less available than a sidecar against the same control plane.
    decision_deadline_ms: int = 2000
    trace_path: str | None = None
    max_privileged_body_bytes: int = 1_048_576
    # What this gateway reports when it cannot verify relayed identity. `full` is only
    # honest when identity is off, or on and the agent supplied headers that verified.
    guarantee_level: str = Guarantee.FULL.value

    # -- 0.4.0: an OAuth 2.1 protected resource (feature 011, M1) ---------------------
    # Off by default. On, the proxy publishes Protected Resource Metadata, answers 401 with
    # a challenge, validates the inbound IdP token itself, and starts a session by calling
    # consent with it. The inbound token never goes upstream.
    oauth_resource_enabled: bool = False
    # This proxy's public URL: the PRM `resource`, and the audience inbound tokens must carry.
    resource_url: str = ""
    # The customer IdP: named in PRM `authorization_servers`, and the `iss` tokens must carry.
    idp_issuer: str = ""
    # Overrides the `jwks_uri` read from the IdP's discovery document at start-up.
    idp_jwks_url: str = ""
    idp_algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
    clock_leeway_seconds: int = DEFAULT_LEEWAY_SECONDS
    # Bearer for POST /v1/consent: the control plane's consent-only role, never admin.
    consent_token: str = field(default="", repr=False)
    session_cache_size: int = 10_000
    # The scope consent is asked for. Unset lets the control plane choose from the client
    # mapping (M4).
    consent_scope: str | None = None
    # Only for a control plane with verified consent off: consent gets the validated subject
    # as an *asserted* user_sub, and this scope. The weaker root, chosen explicitly.
    asserted_root_scope: str | None = None
    # AGENTIC_AUTH_DEV: allows an http://localhost resource URL, for local runs only.
    dev: bool = False

    @property
    def scopes_supported(self) -> tuple[str, ...]:
        """What PRM advertises: the data classes this proxy's routes carry (research R7)."""
        return tuple(
            sorted({u.data_class for u in self.route_table.values() if u.data_class is not None})
        )

    @property
    def host(self) -> str:
        return self.listen_addr.rsplit(":", 1)[0]

    @property
    def port(self) -> int:
        return int(self.listen_addr.rsplit(":", 1)[1])

    @property
    def control_plane_timeout_seconds(self) -> float:
        """The deadline, in the units the shared ``enforce()`` path expects.

        Expressed in milliseconds in configuration because operators reason about a
        decision budget in milliseconds, and as seconds here because ``httpx.Timeout``
        does. One source of truth, converted at the boundary.
        """
        return self.decision_deadline_ms / 1000.0

    def resolve(self, agent: str | None, path: str) -> tuple[str, Upstream] | None:
        """Longest-prefix match, agent-specific entries beating the any-agent fallback.

        ``agent`` comes from the presented token, never from configuration or a header.
        It is read *unverified* here, which is safe for the same reason
        ``_unverified_claims`` is: routing is not a decision. A lie picks a different
        target, and the PDP then refuses that target for this caller — so a lie buys a
        deny, never an allow (research.md R4).
        """
        best: tuple[str, Upstream] | None = None
        best_specific = False
        for (route_agent, prefix), upstream in self.route_table.items():
            if route_agent is not None and route_agent != agent:
                continue
            if not (path == prefix or path.startswith(prefix.rstrip("/") + "/")):
                continue
            specific = route_agent is not None
            if (
                best is None
                or len(prefix) > len(best[0])
                or (len(prefix) == len(best[0]) and specific and not best_specific)
            ):
                best, best_specific = (prefix, upstream), specific
        return best

    def validate(self) -> GatewayConfig:
        if not self.pdp_url:
            raise GatewayConfigError("pdp_url is required — a gateway with no PDP cannot enforce")
        if not self.route_table:
            raise GatewayConfigError(
                "route_table is required and must be non-empty — an empty table forwards "
                "nothing and silently blocks everything, for every agent at once"
            )
        if ":" not in self.listen_addr:
            raise GatewayConfigError(f"listen_addr must be host:port, got {self.listen_addr!r}")
        try:
            _ = self.port
        except ValueError as exc:
            raise GatewayConfigError(
                f"listen_addr port is not a number: {self.listen_addr!r}"
            ) from exc
        if self.decision_deadline_ms < 1:
            raise GatewayConfigError("decision_deadline_ms must be positive")
        if self.max_privileged_body_bytes < 1:
            raise GatewayConfigError("max_privileged_body_bytes must be positive")
        try:
            Guarantee(self.guarantee_level)
        except ValueError as exc:
            raise GatewayConfigError(
                f"guarantee_level must be one of {[g.value for g in Guarantee]}, "
                f"got {self.guarantee_level!r}"
            ) from exc
        if self.oauth_resource_enabled:
            self._validate_oauth_resource()
        return self

    def _validate_oauth_resource(self) -> None:
        """Feature 011 start-up refusals (FR-020). Each names the setting to fix."""
        for name in ("resource_url", "idp_issuer", "consent_token"):
            if not getattr(self, name):
                raise GatewayConfigError(
                    f"{ENV_PREFIX}OAUTH_RESOURCE_ENABLED requires {ENV_PREFIX}{name.upper()}"
                )
        url = self.resource_url
        local = url.startswith(("http://localhost", "http://127.0.0.1"))
        if not url.startswith("https://") and not (local and self.dev):
            hint = " (http://localhost is allowed with AGENTIC_AUTH_DEV=true)" if local else ""
            raise GatewayConfigError(
                f"{ENV_PREFIX}RESOURCE_URL must be an https URL, got {url!r}{hint}: it is the "
                "audience every inbound token must carry"
            )
        if self.observe_mode:
            # Observe mode forwards calls it decided not to allow, and with M1 there is no
            # legitimate token to forward for them: only the client's, which must never go
            # upstream (research R4).
            raise GatewayConfigError(
                f"{ENV_PREFIX}OBSERVE_MODE cannot be used with {ENV_PREFIX}OAUTH_RESOURCE_ENABLED:"
                " observe mode forwards would-be denials, and the only token it could forward "
                "is the client's. Roll out with M1 off first, then turn observe mode off."
            )
        try:
            check_algorithms(self.idp_algorithms)
        except ValueError as exc:
            raise GatewayConfigError(f"{ENV_PREFIX}IDP_ALGORITHMS: {exc}") from exc
        if not 0 <= self.clock_leeway_seconds <= 300:
            raise GatewayConfigError(f"{ENV_PREFIX}CLOCK_LEEWAY_SECONDS must be 0 to 300 seconds")
        if self.session_cache_size < 1:
            raise GatewayConfigError(f"{ENV_PREFIX}SESSION_CACHE_SIZE must be at least 1")
        if self.consent_scope and self.asserted_root_scope:
            raise GatewayConfigError(
                f"set {ENV_PREFIX}CONSENT_SCOPE or {ENV_PREFIX}ASSERTED_ROOT_SCOPE, not both: "
                "the second is for a control plane with verified consent off"
            )


def parse_route_table(raw: Any) -> dict[RouteKey, Upstream]:
    """Parse ``{"<agent>|<prefix>": <upstream>}`` into ``{(agent, prefix): Upstream}``.

    The separator is ``|`` because it cannot appear in an agent name (which matches
    ``AgentName``) and is not meaningful in a URL path, so the split is unambiguous. An
    empty agent means the any-agent fallback: ``"|/kb"``.
    """
    if not isinstance(raw, dict):
        raise GatewayConfigError("route_table must be a mapping of '<agent>|<prefix>' to upstream")
    table: dict[RouteKey, Upstream] = {}
    for key, value in raw.items():
        if "|" not in key:
            raise GatewayConfigError(
                f"route_table key {key!r} must be '<agent>|<prefix>'; use '|<prefix>' for "
                "an entry that applies to any agent"
            )
        agent, prefix = key.split("|", 1)
        if not prefix.startswith("/"):
            raise GatewayConfigError(f"route_table prefix {prefix!r} must start with '/'")
        table[(agent or None, prefix)] = Upstream.parse(prefix, value)
    return table


def _from_mapping(raw: dict[str, Any]) -> GatewayConfig:
    unknown = set(raw) - {
        "pdp_url",
        "listen_addr",
        "route_table",
        "observe_mode",
        "request_timeout_seconds",
        "decision_deadline_ms",
        "trace_path",
        "max_privileged_body_bytes",
        "guarantee_level",
        *_OAUTH_KEYS,
    }
    if unknown:
        # Named explicitly, because `agent_name`/`identity_key_path` are the plausible
        # copy-paste from a sidecar config and the reason they are absent is a security
        # property, not an oversight.
        if unknown & {"agent_name", "identity_key_path"}:
            raise GatewayConfigError(
                "a gateway has no signing key: it serves many agents, and holding their "
                "private keys would make it able to impersonate every one of them. "
                "Agents supply Agent-Identity and Actor-Token headers; the gateway "
                "relays them. Remove agent_name / identity_key_path."
            )
        raise GatewayConfigError(f"unknown configuration keys: {sorted(unknown)}")
    trace_path = raw.get("trace_path") or os.environ.get("AGENTIC_AUTH_TRACE_PATH") or None
    return GatewayConfig(
        pdp_url=str(raw.get("pdp_url", "")).rstrip("/"),
        listen_addr=str(raw.get("listen_addr", "0.0.0.0:8080")),
        route_table=parse_route_table(raw.get("route_table") or {}),
        observe_mode=bool(raw.get("observe_mode", False)),
        request_timeout_seconds=float(raw.get("request_timeout_seconds", 30.0)),
        decision_deadline_ms=int(raw.get("decision_deadline_ms", 2000)),
        trace_path=str(trace_path) if trace_path else None,
        max_privileged_body_bytes=int(raw.get("max_privileged_body_bytes", 1_048_576)),
        guarantee_level=str(raw.get("guarantee_level") or Guarantee.FULL.value),
        oauth_resource_enabled=_bool(raw.get("oauth_resource_enabled")),
        resource_url=str(raw.get("resource_url") or "").rstrip("/"),
        idp_issuer=str(raw.get("idp_issuer") or ""),
        idp_jwks_url=str(raw.get("idp_jwks_url") or ""),
        idp_algorithms=_list(raw.get("idp_algorithms")) or DEFAULT_ALGORITHMS,
        clock_leeway_seconds=int(raw.get("clock_leeway_seconds") or DEFAULT_LEEWAY_SECONDS),
        consent_token=str(raw.get("consent_token") or ""),
        session_cache_size=int(raw.get("session_cache_size") or 10_000),
        consent_scope=raw.get("consent_scope") or None,
        asserted_root_scope=raw.get("asserted_root_scope") or None,
        dev=_bool(raw.get("dev")) or _bool(os.environ.get("AGENTIC_AUTH_DEV")),
    )


_OAUTH_KEYS = (
    "oauth_resource_enabled",
    "resource_url",
    "idp_issuer",
    "idp_jwks_url",
    "idp_algorithms",
    "clock_leeway_seconds",
    "consent_token",
    "session_cache_size",
    "consent_scope",
    "asserted_root_scope",
    "dev",
)


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes")


def _list(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(v).strip() for v in value if str(v).strip())
    return tuple(v.strip() for v in str(value or "").split(",") if v.strip())


def load(path: str | os.PathLike[str] | None = None) -> GatewayConfig:
    """Load from a YAML/JSON file, or from ``AGENTIC_AUTH_GATEWAY_*`` environment vars."""
    if path is not None:
        from pathlib import Path

        import yaml

        raw = yaml.safe_load(Path(path).read_text()) or {}
        if not isinstance(raw, dict):
            raise GatewayConfigError(f"{path}: expected a mapping at the top level")
        return _from_mapping(raw).validate()

    env_table = os.environ.get(f"{ENV_PREFIX}ROUTE_TABLE", "")
    try:
        route_table = json.loads(env_table) if env_table else {}
    except json.JSONDecodeError as exc:
        raise GatewayConfigError(f"{ENV_PREFIX}ROUTE_TABLE is not valid JSON: {exc}") from exc

    return _from_mapping(
        {
            "pdp_url": os.environ.get(f"{ENV_PREFIX}PDP_URL", ""),
            "listen_addr": os.environ.get(f"{ENV_PREFIX}LISTEN_ADDR", "0.0.0.0:8080"),
            "route_table": route_table,
            "observe_mode": os.environ.get(f"{ENV_PREFIX}OBSERVE_MODE", "").lower()
            in ("1", "true", "yes"),
            "decision_deadline_ms": os.environ.get(f"{ENV_PREFIX}DECISION_DEADLINE_MS", "2000"),
            "trace_path": os.environ.get(f"{ENV_PREFIX}TRACE_PATH", ""),
            "guarantee_level": os.environ.get(f"{ENV_PREFIX}GUARANTEE_LEVEL", "full"),
            **{
                key: os.environ[f"{ENV_PREFIX}{key.upper()}"]
                for key in _OAUTH_KEYS
                if f"{ENV_PREFIX}{key.upper()}" in os.environ
            },
        }
    ).validate()
