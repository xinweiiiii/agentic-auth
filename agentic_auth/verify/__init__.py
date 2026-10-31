"""Resource-side verification: identity AND grant AND, for privileged calls, transaction.

Importable with ``pyjwt[crypto]`` alone (``httpx`` only for the ``Http*`` stores). Nothing
here imports the control plane (``agentic_auth.services``, ``agentic_auth.api``,
``agentic_auth.models``), FastAPI,
SQLAlchemy or Redis at module level; ``tests/unit/test_verify_imports.py`` keeps it that
way. See ``docs/verifier-library.md``.

    verifier = Verifier(issuer_jwks=HttpJwks(url), anchors=HttpAnchors(...), replay=RedisReplay(r))
    await verifier.bootstrap()
    admission = verifier.admit(request.headers, target=..., params=body, privileged=True)
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from agentic_auth.verify.admit import Admission, admit
from agentic_auth.verify.anchors import (
    Anchor,
    AnchorStore,
    HttpAnchors,
    HttpJwks,
    JwksSource,
    StaticAnchors,
    StaticJwks,
)
from agentic_auth.verify.canonical import (
    CanonicalizationError,
    binding_document,
    binding_hash,
    canonical_json,
    select_binding,
)
from agentic_auth.verify.grants import VerificationFailed, VerifiedGrant, verify_grant
from agentic_auth.verify.identity import VerifiedIdentity, verify_identity
from agentic_auth.verify.replay import (
    InMemoryReplay,
    RedisReplay,
    ReplayStore,
    ReplayStoreUnavailable,
)
from agentic_auth.verify.transaction import VerifiedTransaction, verify_transaction


@runtime_checkable
class TelemetrySink(Protocol):
    """How an integrator gets the verifier's spans and events, without this package growing a
    dependency on OpenTelemetry.

    This package is importable with **only** ``pyjwt[crypto]``, which
    ``tests/unit/test_verify_imports.py`` enforces — so the seam is a ``Protocol``, not an
    import. The OTel-backed implementation lives in ``agentic_auth.observability``, which the
    integrator opts into; ``None`` means emit nothing, exactly as ``metrics_registry`` already
    works.

    It is a protocol for a second reason too. ``trace.set_tracer_provider()`` is process-global
    and warns-and-ignores on a second call, so a library that installs telemetry in a host it
    does not own either hijacks the host's pipeline or silently emits nothing. Accepting a sink
    the host constructed is the only correct option.
    """

    def span(self, name: str, attributes: Mapping[str, Any]) -> None:
        """Record one completed span. Must not raise."""

    def event(self, name: str, attributes: Mapping[str, Any]) -> None:
        """Record one point-in-time event. Must not raise."""


def _build_metrics(registry: Any) -> Any:
    """The verifier's own metric objects, defined here so this package never imports the
    control plane's ``agentic_auth.services.metrics``. Names mirror docs/contracts/metrics/."""
    from prometheus_client import Counter, Gauge

    class _Metrics:
        def __init__(self) -> None:
            self.admissions = Counter(
                "agentic_auth_admissions", "admit() outcomes", ["result"], registry=registry
            )
            self.transaction_rejections = Counter(
                "agentic_auth_transaction_rejections",
                "Transaction-token rejections by cause",
                ["cause"],
                registry=registry,
            )
            self.identity_view_age = Gauge(
                "agentic_auth_identity_view_age_seconds",
                "Seconds since the anchor view was last refreshed",
                registry=registry,
            )

    return _Metrics()


@dataclass
class Verifier:
    issuer_jwks: JwksSource
    anchors: AnchorStore
    replay: ReplayStore
    identity_required: bool = True
    freshness_seconds: int = 30
    issuer: str = "agentic-auth"
    leeway_seconds: int = 60
    metrics_registry: Any = None
    # Phase 6. Supplied by the integrator; None means emit nothing. The verifier
    # never constructs one, and never touches process-global telemetry.
    telemetry: TelemetrySink | None = None
    _metrics: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.metrics_registry is not None:
            self._metrics = _build_metrics(self.metrics_registry)

    async def bootstrap(self) -> None:
        """Fetch issuer keys and anchors once, then start refreshing. Raises on failure."""
        if isinstance(self.issuer_jwks, HttpJwks):
            await self.issuer_jwks.refresh()
        if isinstance(self.anchors, HttpAnchors):
            self.anchors.freshness_seconds = self.freshness_seconds
            await self.anchors.bootstrap()
            self.anchors.start()

    async def close(self) -> None:
        if isinstance(self.anchors, HttpAnchors):
            await self.anchors.stop()

    def admit(
        self,
        headers: Mapping[str, str],
        *,
        target: str,
        params: Mapping[str, Any] | None = None,
        privileged: bool = False,
    ) -> Admission:
        if self._metrics is not None and isinstance(self.anchors, HttpAnchors):
            age = self.anchors.age_seconds()
            if age is not None:
                self._metrics.identity_view_age.set(age)
        admission = admit(
            headers,
            target=target,
            params=params,
            privileged=privileged,
            issuer_jwks=self.issuer_jwks,
            anchors=self.anchors,
            replay=self.replay,
            identity_required=self.identity_required,
            freshness_seconds=self.freshness_seconds,
            issuer=self.issuer,
            leeway_seconds=self.leeway_seconds,
            metrics=self._metrics,
        )
        self._emit(admission, target=target, privileged=privileged)
        return admission

    def _emit(self, admission: Admission, *, target: str, privileged: bool) -> None:
        """Hand one span to the integrator's sink, if they supplied one.

        Carries the outcome and the reason, and deliberately **not** the target: a target is an
        identity, and identities stay behind the audit-reader check unless the deployment opted
        in. A failing sink is swallowed — telemetry must never be the reason a resource server
        refuses a legitimate call, or admits an illegitimate one.
        """
        if self.telemetry is None:
            return
        with contextlib.suppress(Exception):  # pragma: no cover - never fatal
            self.telemetry.span(
                "verify.admit",
                {
                    "authz.outcome": "allow" if admission.admitted else "deny",
                    "authz.deny_reason": getattr(admission, "reason", None),
                    "authz.privileged": privileged,
                },
            )


__all__ = [
    "Admission",
    "TelemetrySink",
    "Anchor",
    "AnchorStore",
    "CanonicalizationError",
    "HttpAnchors",
    "HttpJwks",
    "InMemoryReplay",
    "JwksSource",
    "RedisReplay",
    "ReplayStore",
    "ReplayStoreUnavailable",
    "StaticAnchors",
    "StaticJwks",
    "VerificationFailed",
    "VerifiedGrant",
    "VerifiedIdentity",
    "VerifiedTransaction",
    "Verifier",
    "admit",
    "binding_document",
    "binding_hash",
    "canonical_json",
    "select_binding",
    "verify_grant",
    "verify_identity",
    "verify_transaction",
]
