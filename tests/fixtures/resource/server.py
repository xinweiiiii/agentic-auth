"""A protected tool server that admits calls with ``app.verify``.

Two tools: ``read_balance`` (ordinary) and ``terminate_account`` (privileged). Every
request is decided by ``Verifier.admit()`` and recorded, so tests can assert the exact
reason a presentation was refused and that nothing ran when it was.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.verify import Admission, Verifier

READ_BALANCE = "mcp://accounts.internal/read_balance"
TERMINATE_ACCOUNT = "mcp://accounts.internal/terminate_account"


@dataclass
class ResourceRecorder:
    admissions: list[tuple[str, Admission]] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)

    def clear(self) -> None:
        self.admissions.clear()
        self.executed.clear()

    @property
    def last(self) -> tuple[str, Admission]:
        if not self.admissions:
            raise AssertionError("the resource saw no requests")
        return self.admissions[-1]

    def reasons(self) -> list[str | None]:
        return [a.reason for _, a in self.admissions]


def build_resource(verifier: Verifier) -> tuple[Starlette, ResourceRecorder]:
    rec = ResourceRecorder()

    async def guarded(request: Request, *, target: str, privileged: bool) -> JSONResponse:
        params: dict[str, Any] | None = None
        if privileged:
            body = await request.body()
            try:
                parsed = json.loads(body or b"{}")
            except ValueError:
                parsed = None
            params = parsed if isinstance(parsed, dict) else None
        admission = verifier.admit(
            request.headers, target=target, params=params, privileged=privileged
        )
        rec.admissions.append((target, admission))
        if not admission.ok:
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "code": "not_admitted",
                        "message": admission.detail or admission.reason,
                        "details": admission.details,
                    }
                },
            )
        rec.executed.append(target)
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

    async def terminate(request: Request) -> JSONResponse:
        return await guarded(request, target=TERMINATE_ACCOUNT, privileged=True)

    app = Starlette(
        routes=[
            Route("/tools/read_balance", read_balance, methods=["GET", "POST"]),
            Route("/tools/terminate_account", terminate, methods=["POST"]),
        ]
    )
    return app, rec
