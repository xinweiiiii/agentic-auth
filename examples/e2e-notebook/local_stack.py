"""The whole deployment, in one process, for the walkthrough notebook.

What a customer would run as four things — a control plane, an MCP capability source, a
protected tool server, and the company IdP — this module runs as four ASGI apps behind one
``httpx`` transport that routes by host. No ports are opened and nothing is mocked: the
control plane is the real FastAPI app on a real PostgreSQL and Redis, the tool server is
guarded by the real ``agentic_auth.verify``, and every decision is really recorded.

Only two things are stand-ins for infrastructure a customer already owns:

* :class:`CapabilitySource` — the ``/.well-known/oauth-protected-resource`` documents that
  real MCP servers publish (RFC 9728). Manifest reconciliation reads these.
* :class:`FakeIdp` — the human identity provider that enrollment binds an agent to.

Requires ``docker compose up -d`` (PostgreSQL + Redis) and nothing else. The notebook gets
its own database and Redis index, so it never touches development data.

    stack = await LocalStack.start()
    client = stack.client("balance-agent", key=key)      # an SDK client for one agent
    tools = await stack.tool_server(agents=[...])        # a resource guarded by agentic_auth.verify
    await stack.aclose()
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

BACKEND = pathlib.Path(__file__).resolve().parents[2]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

# -- configuration, before anything reads it ------------------------------------------
#
# Settings are cached process-wide, so they have to be in the environment before the first
# `get_settings()`. A dedicated database and Redis index keep the notebook isolated.

DATABASE = "agentic_auth_notebook"
OWNER_URL = f"postgresql+asyncpg://app:app@localhost:5432/{DATABASE}"
REDIS_URL = "redis://localhost:6379/9"

CONTROL_PLANE = "http://control-plane.local"
IDP_ISSUER = "https://idp.local"
ADMIN_TOKEN = "notebook-admin"
AUDIT_TOKEN = "notebook-audit-reader"
ENROLL_TOKEN = "notebook-enroller"

os.environ.update(
    {
        "AGENTIC_AUTH_DATABASE_URL": OWNER_URL,
        "AGENTIC_AUTH_REDIS_URL": REDIS_URL,
        "AGENTIC_AUTH_ADMIN_TOKEN": ADMIN_TOKEN,
        "AGENTIC_AUTH_AUDIT_READ_TOKEN": AUDIT_TOKEN,
        "AGENTIC_AUTH_ENROLL_TOKEN": ENROLL_TOKEN,
        "AGENTIC_AUTH_PRINCIPAL_IDP_ISSUER": IDP_ISSUER,
        "AGENTIC_AUTH_PRINCIPAL_IDP_JWKS_URL": f"{IDP_ISSUER}/.well-known/jwks.json",
        "AGENTIC_AUTH_PRINCIPAL_IDP_AUDIENCE": "agentic-auth",
        "AGENTIC_AUTH_PRINCIPAL_BINDING_CLAIM": "agent",
        # Phase 4 controls. identity_required starts OFF, the way a rollout starts: the
        # notebook turns it on once the fleet has enrolled.
        "AGENTIC_AUTH_TRANSACTION_TOKENS_ENABLED": "true",
        "AGENTIC_AUTH_TAINT_ENFORCEMENT_ENABLED": "true",
        "AGENTIC_AUTH_IDENTITY_REQUIRED": "false",
        "AGENTIC_AUTH_REVOCATION_FRESHNESS_SECONDS": "30",
    }
)

import httpx  # noqa: E402
import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from httpx import ASGITransport  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402

from agentic_auth.config import get_settings  # noqa: E402
from agentic_auth.sdk import (  # noqa: E402
    Admission,
    AgenticAuthClient,
    AgentKey,
    HttpAnchors,
    HttpJwks,
    InMemoryReplay,
    Verifier,
)

get_settings.cache_clear()

WELL_KNOWN = "/.well-known/oauth-protected-resource"


# -- the MCP capability source ----------------------------------------------------------


class CapabilitySource:
    """What each tool host advertises about itself (RFC 9728).

    Manifest reconciliation compares a declaration against exactly this. A host that is
    unreachable is not a pass: it produces a ``DISCOVERY_UNAVAILABLE`` diff, which is why
    ``down.internal`` is here.
    """

    DOCUMENTS: dict[str, dict[str, Any]] = {
        "kb.internal": {
            "resource": "https://kb.internal",
            "scopes_supported": ["kb.public", "kb.internal"],
            "tools": {
                "search": {"data_classes": ["kb.public", "kb.internal"], "privileged": False}
            },
        },
        "accounts.internal": {
            "resource": "https://accounts.internal",
            "scopes_supported": ["account.read", "account.write"],
            "tools": {
                "read_balance": {"data_classes": ["account.read"], "privileged": False},
                "terminate_account": {"data_classes": ["account.write"], "privileged": True},
            },
        },
        "ledger.internal": {
            "resource": "https://ledger.internal",
            "scopes_supported": ["ledger.read"],
            "tools": {"read_ledger": {"data_classes": ["ledger.read"], "privileged": False}},
        },
    }
    DOWN_HOST = "down.internal"

    def app(self) -> Starlette:
        async def document(request: Request) -> JSONResponse:
            host = request.headers.get("host", "").split(":")[0]
            if host == self.DOWN_HOST:
                return JSONResponse({"error": "unavailable"}, status_code=503)
            doc = self.DOCUMENTS.get(host)
            if doc is None:
                return JSONResponse({"error": "not found"}, status_code=404)
            return JSONResponse(doc)

        return Starlette(routes=[Route(WELL_KNOWN, document)])


# -- the company IdP ---------------------------------------------------------------------


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass
class FakeIdp:
    """The human identity provider enrollment binds an agent to.

    An agent's enrollment carries an ID token from here naming the agent it belongs to.
    Without one — or with one naming a different agent — the agent is *quarantined*:
    registered, identified, and authorized for nothing.
    """

    key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    kid: str = "idp-key-1"
    issuer: str = IDP_ISSUER
    audience: str = "agentic-auth"
    binding_claim: str = "agent"
    down: bool = False

    def jwks(self) -> dict[str, Any]:
        raw = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": _b64url(raw),
                    "kid": self.kid,
                    "alg": "EdDSA",
                    "use": "sig",
                }
            ]
        }

    def mint(self, *, agent: str | None, sub: str = "alice", expires_in: int = 300) -> str:
        """An ID token for ``sub``, naming ``agent`` in the binding claim."""
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": sub,
            "aud": self.audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
            "jti": str(uuid.uuid4()),
        }
        if agent is not None:
            claims[self.binding_claim] = f"agent://{agent}"
        pem = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": self.kid})

    def app(self) -> Starlette:
        async def jwks(_: Request) -> JSONResponse:
            if self.down:
                return JSONResponse({"error": "unavailable"}, status_code=503)
            return JSONResponse(self.jwks())

        return Starlette(routes=[Route("/.well-known/jwks.json", jwks)])


# -- the protected tool server -----------------------------------------------------------


@dataclass
class ToolCallLog:
    """What the tool server saw. ``executed`` only ever gains an entry for a call that was
    admitted, which is how the notebook shows that a refusal ran nothing."""

    admissions: list[tuple[str, Admission]] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)

    @property
    def last(self) -> Admission:
        if not self.admissions:
            raise AssertionError("the tool server saw no calls")
        return self.admissions[-1][1]

    def reasons(self) -> list[str | None]:
        return [a.reason for _, a in self.admissions]

    def clear(self) -> None:
        self.admissions.clear()
        self.executed.clear()


@dataclass
class ToolServer:
    """A customer's own MCP tool host, guarded by the SDK's verifier."""

    url: str
    http: httpx.AsyncClient
    log: ToolCallLog
    verifier: Verifier

    async def read_balance(self, grant_headers: dict[str, str]) -> httpx.Response:
        return await self.http.post(f"{self.url}/tools/read_balance", headers=grant_headers)

    async def terminate_account(
        self, grant_headers: dict[str, str], params: dict[str, Any]
    ) -> httpx.Response:
        return await self.http.post(
            f"{self.url}/tools/terminate_account", headers=grant_headers, json=params
        )

    async def aclose(self) -> None:
        await self.verifier.close()
        await self.http.aclose()


READ_BALANCE = "mcp://accounts.internal/read_balance"
TERMINATE_ACCOUNT = "mcp://accounts.internal/terminate_account"


def _tool_app(verifier: Verifier) -> tuple[Starlette, ToolCallLog]:
    """Two tools, one ordinary and one privileged, both admitted by ``Verifier.admit``.

    This is the whole resource-side integration: parse the body for a privileged tool,
    call ``admit``, and refuse with its reason. There is no path here that runs the tool
    on identity alone, and none that runs a privileged tool without its transaction token.
    """
    log = ToolCallLog()

    async def guarded(request: Request, *, target: str, privileged: bool) -> JSONResponse:
        params: dict[str, Any] | None = None
        if privileged:
            raw = await request.body()
            try:
                parsed = json.loads(raw or b"{}")
            except ValueError:
                parsed = None
            params = parsed if isinstance(parsed, dict) else None

        admission = verifier.admit(
            request.headers, target=target, params=params, privileged=privileged
        )
        log.admissions.append((target, admission))
        if not admission.ok:
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "code": "not_admitted",
                        "reason": admission.reason,
                        "message": admission.detail or admission.reason,
                        "details": admission.details,
                    }
                },
            )
        log.executed.append(target)
        return JSONResponse(
            {
                "ok": True,
                "target": target,
                "agent": admission.identity.agent if admission.identity else None,
                "action_id": admission.grant.action_id if admission.grant else None,
            }
        )

    async def read_balance(request: Request) -> JSONResponse:
        return await guarded(request, target=READ_BALANCE, privileged=False)

    async def terminate_account(request: Request) -> JSONResponse:
        return await guarded(request, target=TERMINATE_ACCOUNT, privileged=True)

    routes = [
        Route("/tools/read_balance", read_balance, methods=["GET", "POST"]),
        Route("/tools/terminate_account", terminate_account, methods=["POST"]),
    ]
    return Starlette(routes=routes), log


# -- routing -----------------------------------------------------------------------------


class _HostRouter(httpx.AsyncBaseTransport):
    """One transport, four services, routed by host — and cuttable.

    ``cut`` is how the notebook shows fail-closed behaviour: the control plane becomes
    unreachable exactly as it would in an outage, with everything else still up.
    """

    def __init__(self) -> None:
        self.routes: dict[str, httpx.AsyncBaseTransport] = {}
        self.cut: set[str] = set()
        self.calls: dict[str, int] = {}

    def mount(self, host: str, app: Any) -> None:
        self.routes[host] = ASGITransport(app=app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host in self.cut:
            raise httpx.ConnectError(f"{host} is unreachable")
        # A tool host serves its own capability document and its tools; discovery wins on
        # the well-known path, exactly as it does for a real MCP server.
        if request.url.path == WELL_KNOWN:
            host = "capability-source"
        transport = self.routes.get(host)
        if transport is None:
            raise httpx.ConnectError(f"nothing is listening on {host}")
        self.calls[host] = self.calls.get(host, 0) + 1
        return await transport.handle_async_request(request)


# -- the stack ----------------------------------------------------------------------------


@dataclass
class LocalStack:
    http: httpx.AsyncClient
    router: _HostRouter
    idp: FakeIdp
    capabilities: CapabilitySource
    control_plane_url: str = CONTROL_PLANE
    admin_token: str = ADMIN_TOKEN
    audit_token: str = AUDIT_TOKEN
    enroll_token: str = ENROLL_TOKEN
    _servers: list[ToolServer] = field(default_factory=list)

    # -- lifecycle -------------------------------------------------------------

    @classmethod
    async def start(cls, *, reset: bool = True) -> LocalStack:
        """Bring the stack up: database, Redis index, and the four services."""
        await _ensure_database(reset=reset)
        writer_url = await _prepare_schema()
        if writer_url:
            # Run the control plane as the least-privileged role it runs as in production,
            # so the append-only audit guarantee is the real one and not an honour system.
            os.environ["AGENTIC_AUTH_DATABASE_URL"] = writer_url
            get_settings.cache_clear()

        from agentic_auth.redis import get_redis

        if reset:
            await get_redis().flushdb()

        router = _HostRouter()
        http = httpx.AsyncClient(transport=router, timeout=httpx.Timeout(10.0))
        idp, capabilities = FakeIdp(), CapabilitySource()

        router.mount("capability-source", capabilities.app())
        router.mount("idp.local", idp.app())
        router.mount("control-plane.local", _control_plane(http))

        # The principal binder fetches the IdP's keys through the same transport.
        from agentic_auth.services import principal

        principal.jwks_http_client = lambda: http

        return cls(http=http, router=router, idp=idp, capabilities=capabilities)

    async def aclose(self) -> None:
        for server in self._servers:
            await server.aclose()
        await self.http.aclose()
        from agentic_auth.db import get_engine
        from agentic_auth.redis import get_redis

        await get_redis().aclose()
        await get_engine().dispose()

    # -- what the notebook uses ------------------------------------------------

    def client(
        self,
        agent: str | None = None,
        *,
        key: AgentKey | None = None,
        trace_path: str | os.PathLike[str] | None = None,
    ) -> AgenticAuthClient:
        """An SDK client. Pass ``agent`` and ``key`` for an enrolled agent's own client —
        it then signs the proof of possession on every exchange and the identity assertion
        every call carries."""
        return AgenticAuthClient(
            self.control_plane_url,
            admin_token=self.admin_token,
            audit_token=self.audit_token,
            client=self.http,
            identity_key=key,
            agent_name=agent if key else None,
            trace_path=os.fspath(trace_path) if trace_path else None,
        )

    async def tool_server(
        self,
        *,
        agents: list[str],
        identity_required: bool = True,
        freshness_seconds: int = 30,
        host: str = "accounts.internal",
    ) -> ToolServer:
        """A protected tool host, bootstrapped from the control plane and then offline.

        It holds the read-only identity bearer, never the admin token: a resource server
        cannot list agents and does not need to.
        """
        anchors = HttpAnchors(
            base_url=self.control_plane_url,
            token=self.audit_token,
            agents=agents,
            freshness_seconds=freshness_seconds,
            client=self.http,
        )
        verifier = Verifier(
            issuer_jwks=HttpJwks(
                f"{self.control_plane_url}/.well-known/jwks.json", client=self.http
            ),
            anchors=anchors,
            replay=InMemoryReplay(),
            identity_required=identity_required,
            freshness_seconds=freshness_seconds,
        )
        await verifier.bootstrap()
        app, log = _tool_app(verifier)
        self.router.mount(host, app)
        server = ToolServer(url=f"https://{host}", http=self.http, log=log, verifier=verifier)
        self._servers.append(server)
        return server

    def flags(self, **values: Any) -> dict[str, Any]:
        """Flip a control-plane setting for the rest of the run, as a redeploy would.

        Returns what changed, so a notebook cell shows it rather than claiming it.
        """
        settings = get_settings()
        changed: dict[str, Any] = {}
        for name, value in values.items():
            if not hasattr(settings, name):
                raise AttributeError(f"unknown setting {name!r}")
            changed[name] = {"from": getattr(settings, name), "to": value}
            setattr(settings, name, value)
        return changed

    def cut(self, host: str = "control-plane.local") -> None:
        """Make a host unreachable, the way an outage does."""
        self.cut_hosts.add(host)

    @property
    def cut_hosts(self) -> set[str]:
        return self.router.cut

    def restore(self, host: str = "control-plane.local") -> None:
        self.router.cut.discard(host)

    async def audit_rows_are_append_only(self) -> dict[str, Any]:
        """Try to rewrite a recorded decision as the service's own role, and report what
        the database said. A successful UPDATE here would mean the guarantee is not real."""
        settings = get_settings()
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        try:
            async with engine.begin() as conn:
                role = await conn.scalar(text("SELECT current_user"))
                rows = await conn.scalar(text("SELECT count(*) FROM audit_decisions"))
                try:
                    await conn.execute(text("UPDATE audit_decisions SET outcome = 'allow'"))
                    return {"role": role, "rows": rows, "update": "ACCEPTED"}
                except Exception as exc:  # the expected path
                    return {
                        "role": role,
                        "rows": rows,
                        "update": "REFUSED",
                        "error": type(exc).__name__,
                        "detail": str(getattr(exc, "orig", exc)).strip().splitlines()[0],
                    }
        finally:
            await engine.dispose()


def _control_plane(http: httpx.AsyncClient) -> Any:
    """The real FastAPI app, with capability discovery pointed at the local source."""
    from agentic_auth.api import service_deps
    from agentic_auth.main import create_app
    from agentic_auth.services.discovery import DiscoveryClient
    from agentic_auth.services.manifest_service import ManifestService

    app = create_app()

    async def manifest_service() -> Any:
        yield ManifestService(discovery=DiscoveryClient(client=http))

    app.dependency_overrides[service_deps.get_manifest_service] = manifest_service
    return app


# -- database bootstrap -------------------------------------------------------------------


async def _ensure_database(*, reset: bool) -> None:
    """The notebook's own database, from scratch.

    Dropped and recreated rather than emptied, so every run starts on exactly the schema
    the migrations define. A database left over from before a migration is the one state
    that cannot be cleaned up in place, and silently keeping the old shape is worse than
    the second it costs to rebuild. ``FORCE`` closes a kernel still holding it open.
    """
    target = make_url(OWNER_URL)
    engine = create_async_engine(
        target.set(database="postgres"), poolclass=NullPool, isolation_level="AUTOCOMMIT"
    )
    try:
        async with engine.connect() as conn:
            if reset:
                await conn.execute(
                    text(f'DROP DATABASE IF EXISTS "{target.database}" WITH (FORCE)')
                )
            exists = await conn.scalar(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": target.database},
            )
            if not exists:
                await conn.execute(text(f'CREATE DATABASE "{target.database}"'))
    finally:
        await engine.dispose()


async def _prepare_schema() -> str | None:
    """Migrate the schema as the owner, then grant the runtime role what it may do.

    Returns the URL of the least-privileged login role, or ``None`` if it could not be
    created — in which case the control plane runs as the owner and the append-only check
    will say so instead of proving it.
    """
    from agentic_auth.models.audit_decision import WRITER_GRANTS_SQL, WRITER_ROLE_SQL
    from agentic_auth.models.transaction_token import WRITER_GRANTS_SQL_0004

    # The schema comes from the project's own migrations, exactly as a deployment gets it.
    # `create_all` would be simpler and wrong: it creates missing tables but never alters
    # an existing one, so a database left over from before a migration would quietly keep
    # the old shape and fail on the first insert of a new column. Run in a subprocess
    # because Alembic's env.py drives its own event loop.
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND,
        env={**os.environ, "AGENTIC_AUTH_DATABASE_URL": OWNER_URL},
        check=True,
        capture_output=True,
    )

    engine = create_async_engine(OWNER_URL, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(WRITER_ROLE_SQL))
            await conn.execute(
                text(
                    "DO $$ BEGIN "
                    "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agentic_auth_app') "
                    "THEN CREATE ROLE agentic_auth_app LOGIN; END IF; END $$"
                )
            )
            # Idempotent, and tolerant of a role an earlier example already created with a
            # different password or without the writer grant.
            await conn.execute(text("ALTER ROLE agentic_auth_app LOGIN PASSWORD 'app'"))
            await conn.execute(text("GRANT agentic_auth_writer TO agentic_auth_app"))
            for statement in (*WRITER_GRANTS_SQL, *WRITER_GRANTS_SQL_0004):
                await conn.execute(text(statement))
    except Exception as exc:
        # Loud, not silent: the control plane will then run as the table owner, and the
        # append-only check in §14 will say so rather than appear to prove something.
        print(f"could not prepare the least-privileged role ({type(exc).__name__}: {exc});")
        print("the control plane will run as the owner and §14 cannot prove append-only.")
        return None
    finally:
        await engine.dispose()
    # `str(URL)` masks the password; the connection needs it in full.
    return (
        make_url(OWNER_URL)
        .set(username="agentic_auth_app", password="app")
        .render_as_string(hide_password=False)
    )


__all__ = [
    "ADMIN_TOKEN",
    "AUDIT_TOKEN",
    "CONTROL_PLANE",
    "ENROLL_TOKEN",
    "READ_BALANCE",
    "TERMINATE_ACCOUNT",
    "CapabilitySource",
    "FakeIdp",
    "LocalStack",
    "ToolCallLog",
    "ToolServer",
]
