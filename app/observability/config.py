"""Configuration and the no-op fallback for the observability layer.

Three independent reasons the layer stays silent, and all three must be checked before anything
is exported:

1. ``telemetry_enabled`` is false — the default, so a Phase 1-5 deployment is unchanged.
2. The OpenTelemetry SDK is not installed. It is an optional extra (``pip install '.[otel]'``),
   imported lazily and never at module import time, so the control plane and the sidecar both
   start and serve without it.
3. ``telemetry_key`` is empty. This one is a *refusal*, not an absence: the key is what makes
   identity pseudonyms non-reversible, and exporting without it would mean either plaintext
   identities or an unkeyed digest that is recovered by brute force. We log once and export
   nothing rather than guess.

In all three cases the component keeps serving traffic. A guardrail that refused to start
because a collector was unreachable would be an availability regression caused by an
observability feature.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import lru_cache

logger = logging.getLogger(__name__)

# Why the layer is silent, for the one-time startup log and for GET /__agentic/status.
DISABLED_BY_SETTING = "disabled"
DISABLED_SDK_MISSING = "sdk_missing"
DISABLED_NO_KEY = "no_key"
ENABLED = "enabled"


@lru_cache(maxsize=1)
def sdk_available() -> bool:
    """Is the OpenTelemetry SDK importable? Cached, because the answer cannot change within a
    process and the import attempt is not free."""
    try:
        import opentelemetry.sdk.trace  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass(frozen=True)
class ObservabilityConfig:
    """Resolved telemetry configuration for one process."""

    enabled: bool
    key: bytes
    identity_disclosure: bool
    allow_sample_ratio: float
    service_name: str
    state: str

    @classmethod
    def resolve(
        cls,
        *,
        enabled: bool,
        key: str,
        identity_disclosure: bool,
        allow_sample_ratio: float,
        service_name: str,
    ) -> ObservabilityConfig:
        """Apply the three silencing rules above, in order, and report which one fired."""
        state = ENABLED
        if not enabled:
            state = DISABLED_BY_SETTING
        elif not sdk_available():
            state = DISABLED_SDK_MISSING
        elif not key:
            state = DISABLED_NO_KEY

        # Clamped rather than rejected: a nonsensical ratio should not stop a process from
        # starting, and both ends of the clamp are safe (1.0 keeps everything; 0.0 keeps every
        # refusal regardless, because refusals never consult this number).
        ratio = min(1.0, max(0.0, allow_sample_ratio))

        return cls(
            enabled=state == ENABLED,
            key=key.encode("utf-8"),
            identity_disclosure=identity_disclosure and state == ENABLED,
            allow_sample_ratio=ratio,
            service_name=service_name,
            state=state,
        )

    def log_state_once(self) -> None:
        """One line at startup saying what the layer is doing. Only the missing-key case is a
        warning: the other two are deliberate configurations, not faults."""
        if self.state == DISABLED_NO_KEY:
            logger.warning(
                "telemetry is enabled but AGENTIC_AUTH_TELEMETRY_KEY is empty; "
                "exporting nothing rather than exporting identities in the clear",
                extra={"authz.component": self.service_name},
            )
        elif self.state == DISABLED_SDK_MISSING:
            logger.info(
                "telemetry is enabled but the OpenTelemetry SDK is not installed; "
                "install the 'otel' extra to export traces and logs",
                extra={"authz.component": self.service_name},
            )
        elif self.state == ENABLED:
            logger.info(
                "telemetry enabled",
                extra={
                    "authz.component": self.service_name,
                    "authz.identity_disclosure": self.identity_disclosure,
                },
            )


def from_settings(service_name: str = "control_plane") -> ObservabilityConfig:
    """Resolve from ``app.config.Settings``. Imported here rather than at module scope so the
    sidecar, which has its own configuration, does not pull the control plane's settings in."""
    from app.config import get_settings

    s = get_settings()
    return ObservabilityConfig.resolve(
        enabled=s.telemetry_enabled,
        key=s.telemetry_key,
        identity_disclosure=s.telemetry_identity_disclosure,
        allow_sample_ratio=s.telemetry_allow_sample_ratio,
        service_name=service_name,
    )


DISABLED = ObservabilityConfig(
    enabled=False,
    key=b"",
    identity_disclosure=False,
    allow_sample_ratio=1.0,
    service_name="unconfigured",
    state=DISABLED_BY_SETTING,
)
