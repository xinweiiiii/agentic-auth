"""A tool server behind ``RequireAgenticAuth`` — the Phase 5 middleware form (US2).

Phase 4's ``tests/fixtures/resource/server.py`` calls ``admit()`` by hand inside each
route. This one adds the middleware instead, so the tests prove the *middleware* admits
and refuses correctly rather than proving ``admit()`` again.

Three routes, chosen so one fixture covers the whole story:

- ``/read_balance`` — guarded, ordinary.
- ``/terminate_account`` — guarded, privileged: needs a call-bound authority bound to the
  parameters actually presented.
- ``/public/health`` — **not** guarded. The guard is opt-in per resource, and an
  unprotected route in the same app must be untouched by it (spec story 2 scenario 8).

Handlers record what they executed, so "was it refused?" is asserted against whether the
tool actually ran, not inferred from a status code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from agentic_auth.boundary.resource import RequireAgenticAuth
from agentic_auth.verify import Admission, Verifier

READ_BALANCE = "mcp://accounts.internal/read_balance"
TERMINATE_ACCOUNT = "mcp://accounts.internal/terminate_account"

_PATHS = {
    "/read_balance": READ_BALANCE,
    "/terminate_account": TERMINATE_ACCOUNT,
}


@dataclass
class GuardRecorder:
    admissions: list[tuple[str, Admission]] = field(default_factory=list)
    #: Tools that actually ran. Empty means the guard stopped everything.
    executed: list[str] = field(default_factory=list)
    #: Bodies as the handler received them, to prove the buffered body is replayed intact.
    bodies: list[bytes] = field(default_factory=list)

    @property
    def last(self) -> tuple[str, Admission]:
        if not self.admissions:
            raise AssertionError("the guard saw no requests")
        return self.admissions[-1]

    def reasons(self) -> list[str | None]:
        return [a.reason for _, a in self.admissions]


def build_guarded_resource(
    verifier: Verifier, *, max_body_bytes: int = 1_048_576
) -> tuple[Starlette, GuardRecorder]:
    rec = GuardRecorder()

    async def read_balance(request: Request) -> JSONResponse:
        rec.executed.append(READ_BALANCE)
        rec.bodies.append(await request.body())
        return JSONResponse({"balance": 4200})

    async def terminate_account(request: Request) -> JSONResponse:
        rec.executed.append(TERMINATE_ACCOUNT)
        # Reading the body here proves the guard replayed the bytes it bound, rather than
        # consuming the stream and leaving the handler with nothing.
        rec.bodies.append(await request.body())
        return JSONResponse({"closed": True})

    async def health(_request: Request) -> JSONResponse:
        rec.executed.append("public")
        return JSONResponse({"ok": True})

    app = Starlette(
        routes=[
            Route("/read_balance", read_balance, methods=["GET", "POST"]),
            Route("/terminate_account", terminate_account, methods=["POST"]),
            Route("/public/health", health, methods=["GET"]),
        ]
    )
    app.add_middleware(
        RequireAgenticAuth,
        verifier=verifier,
        # Returning None leaves a route unguarded — that is how opt-in is expressed.
        target_for=lambda scope: _PATHS.get(scope["path"]),
        privileged={TERMINATE_ACCOUNT},
        max_body_bytes=max_body_bytes,
        on_admission=lambda admission, target: rec.admissions.append((target, admission)),
    )
    return app, rec


__all__ = [
    "READ_BALANCE",
    "TERMINATE_ACCOUNT",
    "GuardRecorder",
    "build_guarded_resource",
]
