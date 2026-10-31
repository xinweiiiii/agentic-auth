"""The whole deployment, in one process, for the walkthrough notebook.

What a customer runs as four things — a control plane, an MCP capability source, a
protected tool server, and the company IdP — runs here inside the notebook's own process,
on ``agentic_auth.embedded``: the real control plane (same app, PDP, token exchange and
audit log as a deployment) on SQLite and an in-process Redis, reached through an in-process
transport. No ports are opened and nothing needs installing beyond ``authzai[notebook]``:
no Docker, no PostgreSQL, no Redis server.

Two things are stand-ins for infrastructure a customer already owns:

* the RFC 9728 capability documents real MCP servers publish (``DOCUMENTS`` below), which
  manifest reconciliation reads;
* the human identity provider enrollment binds an agent to (``stack.idp``).

    stack = await LocalStack.start()
    client = stack.client("balance-agent", key=key)      # an SDK client for one agent
    tools = await stack.tool_server(agents=[...])        # a resource guarded by agentic_auth.verify
    await stack.aclose()

The embedded control plane is for development and testing only — signing keys and policy
decisions run in the same process as the agents. That is exactly right for a walkthrough
and exactly wrong for production.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
from sqlalchemy import text
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from agentic_auth.embedded import BASE_URL, HOST, EmbeddedControlPlane
from agentic_auth.embedded.idp import TestIdp
from agentic_auth.sdk import Admission, AgenticAuthClient, AgentKey
from agentic_auth.verify import Verifier

CONTROL_PLANE = BASE_URL

# -- the MCP capability source -----------------------------------------------------------
#
# What each tool host advertises about itself (RFC 9728). Manifest reconciliation compares a
# declaration against exactly this. A host with no document is unreachable, not a pass: it
# produces a DISCOVERY_UNAVAILABLE diff, which is what ``down.internal`` demonstrates.

DOCUMENTS: dict[str, dict[str, Any]] = {
    "kb.internal": {
        "resource": "https://kb.internal",
        "scopes_supported": ["kb.public", "kb.internal"],
        "tools": {"search": {"data_classes": ["kb.public", "kb.internal"], "privileged": False}},
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


# -- the stack ----------------------------------------------------------------------------


@dataclass
class LocalStack:
    cp: EmbeddedControlPlane
    _servers: list[ToolServer] = field(default_factory=list)

    # -- lifecycle -------------------------------------------------------------

    @classmethod
    async def start(cls) -> LocalStack:
        """Bring the stack up: a fresh embedded control plane, with the capability documents
        and the test identity provider behind its in-process transport."""
        return cls(cp=await EmbeddedControlPlane.start(capabilities=DOCUMENTS))

    async def aclose(self) -> None:
        for server in self._servers:
            await server.aclose()
        await self.cp.aclose()

    # -- what the notebook uses ------------------------------------------------

    @property
    def control_plane_url(self) -> str:
        return CONTROL_PLANE

    @property
    def http(self) -> httpx.AsyncClient:
        return self.cp.http

    @property
    def idp(self) -> TestIdp:
        return self.cp.idp

    @property
    def enroll_token(self) -> str:
        return self.cp.enroll_token

    def client(
        self,
        agent: str | None = None,
        *,
        key: AgentKey | None = None,
        trace_path: str | None = None,
    ) -> AgenticAuthClient:
        """An SDK client. Pass ``agent`` and ``key`` for an enrolled agent's own client —
        it then signs the proof of possession on every exchange and the identity assertion
        every call carries."""
        return self.cp.client(agent, key=key, trace_path=trace_path)

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
        verifier = await self.cp.verifier(
            agents=agents,
            identity_required=identity_required,
            freshness_seconds=freshness_seconds,
        )
        app, log = _tool_app(verifier)
        self.cp.mount(host, app)
        server = ToolServer(url=f"https://{host}", http=self.cp.http, log=log, verifier=verifier)
        self._servers.append(server)
        return server

    def flags(self, **values: Any) -> dict[str, Any]:
        """Flip a control-plane setting for the rest of the run, as a redeploy would.

        Returns what changed, so a notebook cell shows it rather than claiming it.
        """
        return self.cp.configure(**values)

    def cut(self, host: str = HOST) -> None:
        """Make a host unreachable, the way an outage does — the control plane by default."""
        self.cp.cut(host)

    def restore(self, host: str = HOST) -> None:
        self.cp.restore(host)

    async def audit_rows_are_append_only(self) -> dict[str, Any]:
        """Try to rewrite a recorded decision directly in the store, and report what the
        database said. A successful UPDATE here would mean the guarantee is not real."""
        engine = self.cp._store.engine
        async with engine.connect() as conn:
            rows = await conn.scalar(text("SELECT count(*) FROM audit_decisions"))
        try:
            async with engine.begin() as conn:
                await conn.execute(text("UPDATE audit_decisions SET outcome = 'allow'"))
            return {"rows": rows, "update": "ACCEPTED"}
        except Exception as exc:  # the expected path
            return {
                "rows": rows,
                "update": "REFUSED",
                "error": type(exc).__name__,
                "detail": str(getattr(exc, "orig", exc)).strip().splitlines()[0],
            }


__all__ = [
    "CONTROL_PLANE",
    "DOCUMENTS",
    "READ_BALANCE",
    "TERMINATE_ACCOUNT",
    "LocalStack",
    "ToolCallLog",
    "ToolServer",
]
