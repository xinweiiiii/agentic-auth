"""The whole control plane inside your process, for development and testing.

    from agentic_auth.embedded import EmbeddedControlPlane

    async with EmbeddedControlPlane.open("manifests/", override_reason="local") as cp:
        client = cp.client()
        session = await client.consent(scope="bank-assistant", user_sub="user:alice")
        ...

This is the real control plane, not a model of it: the same FastAPI app, routes, PDP, token
profile and audit writer as a deployment, reached through an in-process transport instead of
a socket, on SQLite instead of PostgreSQL and an in-process Redis instead of a server.
``cp.client()`` returns the same ``AgenticAuthClient`` you would point at a deployed control
plane, so moving between the two changes only how the client is constructed. The conformance
suite (tests/conformance) holds the two to identical decisions.

**Development and testing only.** The signing keys and the policy decision point run in the
same process as the agent they constrain, so the agent's own code could reach the keys that
grant its authority. Every instance says so when it starts, and every decision it records
carries ``deployment: embedded``. Deploy the control plane — with the sidecar, gateway or
boundary adapter in front of your agents — for anything real.
"""

from __future__ import annotations

from agentic_auth._extras import require_extra

require_extra(
    "agentic_auth.embedded", "embedded", "fastapi", "sqlalchemy", "aiosqlite", "fakeredis"
)

import logging
import os
import secrets
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any

import httpx
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fakeredis import FakeServer
from fakeredis.aioredis import FakeRedis
from prometheus_client import CollectorRegistry

from agentic_auth.config import Settings
from agentic_auth.embedded import idp as _idp
from agentic_auth.embedded._transport import CAPABILITIES, HostRouter
from agentic_auth.embedded.capabilities import capability_app
from agentic_auth.embedded.store import (
    MEMORY,
    StoreHandle,
    StoreLocked,
    StoreVersionMismatch,
    open_store,
    remember_issuer_key,
)
from agentic_auth.runtime import Runtime, use_runtime
from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.sdk import AgenticAuthClient, AgentKey, HttpAnchors, HttpJwks, InMemoryReplay
from agentic_auth.sdk.errors import ManifestRejected, PolicyDenied
from agentic_auth.services.metrics import build_control_plane_metrics
from agentic_auth.services.tokens.keys import IssuerKey, _thumbprint, load_or_generate
from agentic_auth.verify import Verifier

logger = logging.getLogger(__name__)

HOST = "control-plane.embedded.invalid"
BASE_URL = f"http://{HOST}"

BANNER = (
    "embedded control plane: development and testing only — signing keys and policy "
    "decisions run inside this process (store={store})"
)


class _EmbeddedSettings(Settings):
    """Settings from constructor arguments only. An embedded instance must never pick up
    the host process's AGENTIC_AUTH_* environment, which may belong to a real deployment."""

    @classmethod
    def settings_customise_sources(  # type: ignore[override]
        cls, settings_cls: type[Settings], init_settings: Any, **_: Any
    ) -> tuple[Any, ...]:
        return (init_settings,)


ManifestSource = (
    str | os.PathLike[str] | Sequence[str | os.PathLike[str]] | Mapping[str, Mapping[str, Any]]
)


def _manifests_from(sources: ManifestSource) -> dict[str, AgentManifest]:
    """Files or directories of YAML/JSON manifests (the formats the CLI and drift check
    take), or manifest documents keyed by agent name."""
    from agentic_auth.services.drift import load_manifest_dirs

    if isinstance(sources, Mapping):
        return {name: AgentManifest.model_validate(doc) for name, doc in sources.items()}
    paths = [sources] if isinstance(sources, (str, os.PathLike)) else list(sources)
    found: dict[str, AgentManifest] = {}
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            loaded = load_manifest_dirs([path])
            if loaded.errors:
                details = "; ".join(f"{e.code} {e.path or ''} {e.message}" for e in loaded.errors)
                raise ValueError(f"could not load manifests from {path}: {details}")
            found.update(loaded.manifests)
        else:
            manifest = AgentManifest.model_validate(yaml.safe_load(path.read_text("utf-8")))
            found[manifest.metadata.agent] = manifest
    return found


class EmbeddedControlPlane:
    """One self-contained control plane: its own keys, store, sessions and audit log."""

    deployment = "embedded"

    def __init__(
        self,
        *,
        runtime: Runtime,
        store: StoreHandle,
        router: HostRouter,
        idp: _idp.TestIdp,
    ) -> None:
        self._runtime = runtime
        self._store = store
        self._router = router
        self._idp = idp
        self._closed = False

    # -- lifecycle -------------------------------------------------------------------

    @classmethod
    def open(
        cls,
        manifests: ManifestSource | None = None,
        *,
        store: str | os.PathLike[str] = MEMORY,
        override_reason: str | None = None,
        capabilities: Mapping[str, Mapping[str, Any]] | None = None,
        identity_required: bool = False,
        **settings: Any,
    ) -> _Opening:
        """``async with EmbeddedControlPlane.open(...) as cp:`` — see :meth:`start`."""
        return _Opening(
            cls.start(
                manifests,
                store=store,
                override_reason=override_reason,
                capabilities=capabilities,
                identity_required=identity_required,
                **settings,
            )
        )

    @classmethod
    async def start(
        cls,
        manifests: ManifestSource | None = None,
        *,
        store: str | os.PathLike[str] = MEMORY,
        override_reason: str | None = None,
        capabilities: Mapping[str, Mapping[str, Any]] | None = None,
        identity_required: bool = False,
        **settings: Any,
    ) -> EmbeddedControlPlane:
        """Start an instance; pair with :meth:`aclose`. For notebooks and fixtures that cannot
        hold an ``async with`` open.

        ``store`` is ``":memory:"`` (a temporary store, deleted on close) or a file path (kept,
        and refused if another process has it open). ``capabilities`` are the RFC 9728
        documents manifests reconcile against, keyed by tool host; without one, a tool's host
        is unreachable and its manifest needs ``override_reason``. Any other keyword is a
        control-plane setting (``Settings`` field), e.g. ``step_up_enabled=True``.
        """
        handle = await open_store(store)
        try:
            instance = await cls._assemble(
                handle,
                capabilities=capabilities or {},
                identity_required=identity_required,
                settings=settings,
            )
        except BaseException:
            await handle.close()
            raise
        logger.warning(BANNER.format(store=os.fspath(store)))
        if manifests is not None:
            try:
                await instance.register(manifests, override_reason=override_reason)
            except BaseException:
                await instance.aclose()
                raise
        return instance

    @classmethod
    async def _assemble(
        cls,
        handle: StoreHandle,
        *,
        capabilities: Mapping[str, Mapping[str, Any]],
        identity_required: bool,
        settings: Mapping[str, Any],
    ) -> EmbeddedControlPlane:
        if handle.issuer_private_key:
            issuer_key = load_or_generate(handle.issuer_private_key)
        else:
            private = Ed25519PrivateKey.generate()
            issuer_key = IssuerKey(private_key=private, kid=_thumbprint(private.public_key()))
            await remember_issuer_key(handle, issuer_key.private_pem().decode())

        config = _EmbeddedSettings(
            # Informational only: the engine below is what the instance uses.
            database_url=f"sqlite+aiosqlite:///{handle.path}",
            redis_url="redis://embedded.invalid/0",
            # Per-instance bearers. Nothing outside this object ever needs them.
            admin_token=secrets.token_urlsafe(32),
            audit_read_token=secrets.token_urlsafe(32),
            enroll_token=secrets.token_urlsafe(32),
            principal_idp_issuer=_idp.ISSUER,
            principal_idp_jwks_url=f"{_idp.ISSUER}/.well-known/jwks.json",
            principal_idp_audience=_idp.AUDIENCE,
            principal_binding_claim=_idp.BINDING_CLAIM,
            identity_required=identity_required,
            telemetry_enabled=False,
            **settings,
        )

        router = HostRouter()
        http = httpx.AsyncClient(transport=router, timeout=httpx.Timeout(10.0))
        runtime = Runtime(
            settings=config,
            engine=handle.engine,
            sessionmaker=handle.sessionmaker,
            redis=FakeRedis(server=FakeServer(), decode_responses=True),
            issuer_key=issuer_key,
            metrics=build_control_plane_metrics(CollectorRegistry()),
            http=http,
            deployment="embedded",
            superseded_before=handle.opened_at if handle.durable else None,
        )
        test_idp = _idp.TestIdp()

        from agentic_auth.main import create_app
        from agentic_auth.services.anchors import AnchorCache
        from agentic_auth.services.revocation import RevocationService

        with use_runtime(runtime):
            router.mount(HOST, create_app(runtime))
            router.mount(CAPABILITIES, capability_app(capabilities))
            router.mount(_idp.HOST, test_idp.app())
            # What the server's startup does: rebuild the revoked-agents set from the table,
            # so a durable store reopened with an empty Redis is never more permissive.
            async with runtime.sessionmaker() as session:
                await RevocationService(AnchorCache(runtime.redis)).rebuild(session, runtime.redis)

        return cls(runtime=runtime, store=handle, router=router, idp=test_idp)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._runtime.http.aclose()
        await self._runtime.redis.aclose()
        await self._store.close()

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("embedded control plane is closed")

    # -- what callers use -------------------------------------------------------------

    @property
    def store(self) -> Path | None:
        """The store's file, for a durable store; ``None`` for a temporary one."""
        return self._store.path if self._store.durable else None

    @property
    def http(self) -> httpx.AsyncClient:
        """The in-process HTTP client. Reaches the control plane, the capability source,
        the test identity provider and anything :meth:`mount` adds — and nothing else."""
        return self._runtime.http

    def client(
        self,
        agent_name: str | None = None,
        *,
        key: AgentKey | None = None,
        trace_path: str | os.PathLike[str] | None = None,
    ) -> AgenticAuthClient:
        """The same SDK client a deployment uses, wired to this instance. With ``agent_name``
        and ``key``, it presents that agent's identity on every exchange and call."""
        self._check_open()
        settings = self._runtime.settings
        return AgenticAuthClient(
            BASE_URL,
            admin_token=settings.admin_token,
            audit_token=settings.audit_read_token,
            client=self._runtime.http,
            identity_key=key,
            agent_name=agent_name if key else None,
            trace_path=os.fspath(trace_path) if trace_path else None,
        )

    async def register(
        self,
        manifests: ManifestSource,
        *,
        override_reason: str | None = None,
    ) -> list[Any]:
        """Register every manifest, downstream agents first. Raises ``ManifestRejected`` with
        the reconciliation diff, exactly as the admin API does."""
        from agentic_auth.services.drift import registration_order

        self._check_open()
        found = _manifests_from(manifests)
        admin = self.client().admin
        return [
            await admin.register_agent(
                name, found[name].canonical_doc(), override_reason=override_reason
            )
            for name in registration_order(found)
        ]

    def jwks(self) -> dict[str, Any]:
        """The public key every grant this instance issues is signed with."""
        return {"keys": [self._runtime.issuer_key.public_jwk()]}

    async def verifier(self, *, agents: Iterable[str] = (), **kwargs: Any) -> Verifier:
        """A resource-side verifier that trusts *this* instance's grants and the identities
        of ``agents`` — bootstrapped, then offline like any other. A token from a different
        instance does not verify against it."""
        self._check_open()
        settings = self._runtime.settings
        freshness = kwargs.pop("freshness_seconds", settings.revocation_freshness_seconds)
        verifier = Verifier(
            issuer_jwks=HttpJwks(f"{BASE_URL}/.well-known/jwks.json", client=self.http),
            anchors=HttpAnchors(
                base_url=BASE_URL,
                token=settings.audit_read_token,
                agents=list(agents),
                freshness_seconds=freshness,
                client=self.http,
            ),
            replay=kwargs.pop("replay", None) or InMemoryReplay(),
            freshness_seconds=freshness,
            **kwargs,
        )
        await verifier.bootstrap()
        return verifier

    async def enroll_test_principal(
        self, agent_name: str, key: AgentKey, *, principal: str = "user:test"
    ) -> dict[str, Any]:
        """Enroll ``agent_name`` bound to ``principal`` at the built-in test identity
        provider. The binding is labelled test-only in the principal assertion."""
        self._check_open()
        client = self.client()
        agent_id = await client.admin.agent_id(agent_name)
        return await client.enroll(
            agent_id,
            key=key,
            agent_name=agent_name,
            principal_assertion=self._idp.mint(agent=agent_name, sub=principal),
            enroll_token=self._runtime.settings.enroll_token,
        )

    @property
    def admin_token(self) -> str:
        """This instance's admin bearer. In-process only; generated per instance."""
        return self._runtime.settings.admin_token

    @property
    def audit_token(self) -> str:
        """This instance's read-only audit and identity bearer."""
        return self._runtime.settings.audit_read_token

    @property
    def enroll_token(self) -> str:
        """This instance's enrollment bearer."""
        return self._runtime.settings.enroll_token

    @property
    def idp(self) -> _idp.TestIdp:
        """The built-in test identity provider: ``cp.idp.mint(agent=..., sub=...)``."""
        return self._idp

    def configure(self, **settings: Any) -> dict[str, Any]:
        """Change control-plane settings for the rest of the run, as a redeploy would.
        Returns what changed, ``{name: {"from": old, "to": new}}``."""
        self._check_open()
        current = self._runtime.settings
        changed: dict[str, Any] = {}
        for name, value in settings.items():
            if name not in type(current).model_fields:
                raise AttributeError(f"unknown setting {name!r}")
            changed[name] = {"from": getattr(current, name), "to": value}
            setattr(current, name, value)
        return changed

    def mount(self, host: str, app: Any) -> None:
        """Serve an ASGI app (a tool server, say) at ``https://{host}`` on :attr:`http`."""
        self._check_open()
        self._router.mount(host, app)

    def cut(self, host: str = HOST) -> None:
        """Make a host unreachable, the way an outage does — the control plane by default."""
        self._router.cut.add(host)

    def restore(self, host: str = HOST) -> None:
        self._router.cut.discard(host)

    async def export(self, path: str | os.PathLike[str]) -> Path:
        """Write an export bundle for moving to a deployed control plane."""
        from agentic_auth.embedded.export import export_bundle

        self._check_open()
        return await export_bundle(self._runtime, Path(path))


class _Opening:
    """What :meth:`EmbeddedControlPlane.open` returns: an async context manager."""

    def __init__(self, starting: Any) -> None:
        self._starting = starting
        self._instance: EmbeddedControlPlane | None = None

    async def __aenter__(self) -> EmbeddedControlPlane:
        self._instance = await self._starting
        return self._instance

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._instance is not None:
            await self._instance.aclose()

    def __await__(self) -> Any:
        raise TypeError(
            "use `async with EmbeddedControlPlane.open(...) as cp`, "
            "or `cp = await EmbeddedControlPlane.start(...)`"
        )


__all__ = [
    "BASE_URL",
    "HOST",
    "EmbeddedControlPlane",
    "ManifestRejected",
    "PolicyDenied",
    "StoreLocked",
    "StoreVersionMismatch",
]
