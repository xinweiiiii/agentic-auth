"""Sidecar configuration.

Startup is deliberately strict. A sidecar that comes up but cannot enforce is worse than
one that refuses to start, because the first looks healthy while forwarding everything.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentic_auth.boundary.guarantee import Guarantee

ENV_PREFIX = "AGENTIC_AUTH_SIDECAR_"

# Reserved for the enforcement point's own routes (GET /__agentic/metrics, /__agentic/status).
# `upstream_map` prefixes are integrator-chosen and could legitimately be `/metrics`, so the
# telemetry routes live under a namespace no sensible upstream mapping would claim — and
# `validate()` refuses a mapping that would shadow it rather than silently losing either the
# proxy route or the metrics route.
RESERVED_PATH_PREFIX = "/__agentic"


class SidecarConfigError(ValueError):
    """The sidecar cannot be configured to enforce anything."""


@dataclass(frozen=True)
class Upstream:
    """One mapped route.

    ``target`` and ``data_class`` are what the policy is expressed in; a URL path alone
    cannot supply them. Either pin them here, or let an SDK-aware agent send them per
    request as ``X-Agentic-Target`` / ``X-Agentic-Data-Class``. If neither produces a
    value the call is blocked — guessing a data class would be inventing consent.
    """

    url: str
    target: str | None = None
    data_class: str | None = None

    @classmethod
    def parse(cls, prefix: str, raw: Any) -> Upstream:
        if isinstance(raw, str):
            return cls(url=raw.rstrip("/"))
        if not isinstance(raw, dict) or "url" not in raw:
            raise SidecarConfigError(
                f"upstream_map[{prefix!r}] must be a URL string or an object with a 'url'"
            )
        unknown = set(raw) - {"url", "target", "data_class"}
        if unknown:
            raise SidecarConfigError(
                f"upstream_map[{prefix!r}] has unknown keys: {sorted(unknown)}"
            )
        return cls(
            url=str(raw["url"]).rstrip("/"),
            target=raw.get("target"),
            data_class=raw.get("data_class"),
        )


@dataclass(frozen=True)
class SidecarConfig:
    pdp_url: str
    listen_addr: str = "127.0.0.1:8081"
    upstream_map: dict[str, Upstream] = field(default_factory=dict)
    # Decisions are made and recorded, but a deny does not block. A rollout aid.
    observe_mode: bool = False
    request_timeout_seconds: float = 30.0
    control_plane_timeout_seconds: float = 2.0
    # When set, append one edge event per call (contracts/edge-trace.schema.json). Passive:
    # it never changes what is forwarded or blocked.
    trace_path: str | None = None
    # Phase 4. Largest body the sidecar buffers to bind a privileged call; over the cap is
    # blocked, never forwarded unbound.
    max_privileged_body_bytes: int = 1_048_576
    # Phase 4 identity: both or neither. With a key the sidecar signs an actor_token at every
    # exchange and adds Agent-Identity on every forwarded call.
    agent_name: str | None = None
    identity_key_path: str | None = None
    # Phase 5. What this enforcement point reports on every decision. A sidecar is in the
    # call path and decides every hop, so `full` is accurate. It is configurable only so a
    # deployment that knows it is weaker can say so.
    guarantee_level: str = "full"
    # Phase 6. Per enforcement point, mirroring the control plane's settings —
    # there is deliberately no fleet-wide telemetry switch, for the same reason there is no
    # fleet-wide observe mode.
    telemetry_enabled: bool = False
    telemetry_key: str = ""
    telemetry_identity_disclosure: bool = False
    telemetry_allow_sample_ratio: float = 1.0

    @property
    def host(self) -> str:
        return self.listen_addr.rsplit(":", 1)[0]

    @property
    def port(self) -> int:
        return int(self.listen_addr.rsplit(":", 1)[1])

    def resolve(self, path: str) -> tuple[str, Upstream] | None:
        """Longest-prefix match, so ``/kb/deep`` wins over ``/kb`` when both are mapped."""
        best: tuple[str, Upstream] | None = None
        for prefix, upstream in self.upstream_map.items():
            matches = path == prefix or path.startswith(prefix.rstrip("/") + "/")
            if matches and (best is None or len(prefix) > len(best[0])):
                best = (prefix, upstream)
        return best

    def validate(self) -> SidecarConfig:
        if not self.pdp_url:
            raise SidecarConfigError("pdp_url is required — a sidecar with no PDP cannot enforce")
        if not self.upstream_map:
            raise SidecarConfigError(
                "upstream_map is required and must be non-empty — an empty map forwards nothing "
                "and silently blocks everything"
            )
        if ":" not in self.listen_addr:
            raise SidecarConfigError(f"listen_addr must be host:port, got {self.listen_addr!r}")
        try:
            _ = self.port
        except ValueError as exc:
            raise SidecarConfigError(
                f"listen_addr port is not a number: {self.listen_addr!r}"
            ) from exc
        if bool(self.agent_name) != bool(self.identity_key_path):
            raise SidecarConfigError(
                "agent_name and identity_key_path must be set together — an identity without "
                "a name, or a name without a key, cannot sign anything"
            )
        if self.identity_key_path and not Path(self.identity_key_path).is_file():
            raise SidecarConfigError(f"identity_key_path {self.identity_key_path!r} is not a file")
        if self.max_privileged_body_bytes < 1:
            raise SidecarConfigError("max_privileged_body_bytes must be positive")
        try:
            Guarantee(self.guarantee_level)
        except ValueError as exc:
            raise SidecarConfigError(
                f"guarantee_level must be one of {[g.value for g in Guarantee]}, "
                f"got {self.guarantee_level!r}"
            ) from exc
        shadowing = sorted(
            prefix
            for prefix in self.upstream_map
            if prefix == RESERVED_PATH_PREFIX
            or prefix.startswith(RESERVED_PATH_PREFIX + "/")
            or RESERVED_PATH_PREFIX.startswith(prefix.rstrip("/") + "/")
        )
        if shadowing:
            raise SidecarConfigError(
                f"upstream_map prefixes {shadowing} would shadow the reserved "
                f"{RESERVED_PATH_PREFIX!r} namespace, which serves this enforcement point's own "
                "metrics and status; a sidecar whose telemetry is unreachable cannot be "
                "monitored, and one whose proxy route is unreachable cannot enforce"
            )
        if self.telemetry_enabled and not self.telemetry_key:
            raise SidecarConfigError(
                "telemetry_enabled requires telemetry_key — without it, identity pseudonyms "
                "would be either plaintext or an unkeyed digest that is trivially reversible"
            )
        return self


def _from_mapping(raw: dict[str, Any]) -> SidecarConfig:
    unknown = set(raw) - {
        "pdp_url",
        "listen_addr",
        "upstream_map",
        "observe_mode",
        "request_timeout_seconds",
        "control_plane_timeout_seconds",
        "trace_path",
        "max_privileged_body_bytes",
        "agent_name",
        "identity_key_path",
        "guarantee_level",
        "telemetry_enabled",
        "telemetry_key",
        "telemetry_identity_disclosure",
        "telemetry_allow_sample_ratio",
    }
    if unknown:
        raise SidecarConfigError(f"unknown configuration keys: {sorted(unknown)}")
    # `agentic-auth drift record` exports AGENTIC_AUTH_TRACE_PATH to the test run it wraps,
    # so a sidecar started inside that run records even when its config file says nothing.
    trace_path = raw.get("trace_path") or os.environ.get("AGENTIC_AUTH_TRACE_PATH") or None
    return SidecarConfig(
        pdp_url=str(raw.get("pdp_url", "")).rstrip("/"),
        listen_addr=str(raw.get("listen_addr", "127.0.0.1:8081")),
        upstream_map={
            prefix: Upstream.parse(prefix, value)
            for prefix, value in (raw.get("upstream_map") or {}).items()
        },
        observe_mode=bool(raw.get("observe_mode", False)),
        request_timeout_seconds=float(raw.get("request_timeout_seconds", 30.0)),
        control_plane_timeout_seconds=float(raw.get("control_plane_timeout_seconds", 2.0)),
        trace_path=str(trace_path) if trace_path else None,
        max_privileged_body_bytes=int(raw.get("max_privileged_body_bytes", 1_048_576)),
        agent_name=raw.get("agent_name") or None,
        identity_key_path=raw.get("identity_key_path") or None,
        guarantee_level=str(raw.get("guarantee_level") or "full"),
        telemetry_enabled=bool(raw.get("telemetry_enabled", False)),
        telemetry_key=str(raw.get("telemetry_key") or ""),
        telemetry_identity_disclosure=bool(raw.get("telemetry_identity_disclosure", False)),
        telemetry_allow_sample_ratio=float(raw.get("telemetry_allow_sample_ratio", 1.0)),
    )


def load(path: str | Path | None = None) -> SidecarConfig:
    """Load from a YAML/JSON file, or from ``AGENTIC_AUTH_SIDECAR_*`` environment vars."""
    if path is not None:
        import yaml

        raw = yaml.safe_load(Path(path).read_text()) or {}
        if not isinstance(raw, dict):
            raise SidecarConfigError(f"{path}: expected a mapping at the top level")
        return _from_mapping(raw).validate()

    env_map = os.environ.get(f"{ENV_PREFIX}UPSTREAM_MAP", "")
    try:
        upstream_map = json.loads(env_map) if env_map else {}
    except json.JSONDecodeError as exc:
        raise SidecarConfigError(f"{ENV_PREFIX}UPSTREAM_MAP is not valid JSON: {exc}") from exc

    return _from_mapping(
        {
            "pdp_url": os.environ.get(f"{ENV_PREFIX}PDP_URL", ""),
            "listen_addr": os.environ.get(f"{ENV_PREFIX}LISTEN_ADDR", "127.0.0.1:8081"),
            "upstream_map": upstream_map,
            "observe_mode": os.environ.get(f"{ENV_PREFIX}OBSERVE_MODE", "").lower()
            in ("1", "true", "yes"),
            "trace_path": os.environ.get(f"{ENV_PREFIX}TRACE_PATH", ""),
            "max_privileged_body_bytes": os.environ.get(
                f"{ENV_PREFIX}MAX_PRIVILEGED_BODY_BYTES", "1048576"
            ),
            "agent_name": os.environ.get(f"{ENV_PREFIX}AGENT_NAME", ""),
            "identity_key_path": os.environ.get(f"{ENV_PREFIX}IDENTITY_KEY_PATH", ""),
            "guarantee_level": os.environ.get(f"{ENV_PREFIX}GUARANTEE_LEVEL", "full"),
            "telemetry_enabled": os.environ.get(f"{ENV_PREFIX}TELEMETRY_ENABLED", "").lower()
            in ("1", "true", "yes"),
            "telemetry_key": os.environ.get(f"{ENV_PREFIX}TELEMETRY_KEY", ""),
            "telemetry_identity_disclosure": os.environ.get(
                f"{ENV_PREFIX}TELEMETRY_IDENTITY_DISCLOSURE", ""
            ).lower()
            in ("1", "true", "yes"),
            "telemetry_allow_sample_ratio": os.environ.get(
                f"{ENV_PREFIX}TELEMETRY_ALLOW_SAMPLE_RATIO", "1.0"
            ),
        }
    ).validate()
