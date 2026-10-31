"""Tools that record and perform nothing — the sandbox's whole safety property (US6).

FR-032 says every attempted call is allowed and recorded, and no real system of record
is reachable. This fixture is the second half of that: every route returns a plausible
answer and touches nothing. ``performed`` stays empty forever, which is what tests
assert instead of trying to prove a negative about the outside world.

That is also the honest bound on sandbox risk (research.md R11). We are not claiming
container isolation; we are claiming the only things reachable from here are these, and
these do nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


@dataclass
class MockToolRecorder:
    #: Every call attempted, in order: (tool ref, params).
    attempted: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    #: Deliberately never appended to. A mock that performed something would make the
    #: sandbox's safety claim false, so the assertion is that this stays empty.
    performed: list[str] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return [ref for ref, _ in self.attempted]


def build_mock_tools(refs: list[str]) -> tuple[Starlette, MockToolRecorder]:
    """One route per tool ref. A ref not listed here is simply unreachable — which is
    how the sandbox bounds what an unknown agent can touch."""
    rec = MockToolRecorder()

    def handler(ref: str):
        async def route(request: Request) -> JSONResponse:
            try:
                params = await request.json()
            except Exception:
                params = {}
            rec.attempted.append((ref, params if isinstance(params, dict) else {}))
            # Records, returns, performs nothing.
            return JSONResponse({"ok": True, "mock": True, "tool": ref})

        return route

    routes = [
        Route(f"/{ref.rsplit('/', 1)[-1]}", handler(ref), methods=["GET", "POST"]) for ref in refs
    ]
    return Starlette(routes=routes), rec
