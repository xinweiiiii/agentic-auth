"""A local upstream that records every request it receives.

Sidecar tests assert two things this makes possible: *which* token arrived (it must be the
narrowed one, never the presented one), and that a blocked call delivered **nothing**.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


@dataclass
class Recorder:
    requests: list[dict[str, Any]] = field(default_factory=list)

    def clear(self) -> None:
        self.requests.clear()

    @property
    def count(self) -> int:
        return len(self.requests)

    @property
    def last(self) -> dict[str, Any]:
        if not self.requests:
            raise AssertionError("upstream received no requests")
        return self.requests[-1]

    def tokens(self) -> list[str]:
        return [r["token"] for r in self.requests]


def build_upstream(recorder: Recorder | None = None) -> tuple[Starlette, Recorder]:
    rec = recorder or Recorder()

    async def handler(request: Request) -> JSONResponse:
        auth = request.headers.get("authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        body = await request.body()
        rec.requests.append(
            {
                "method": request.method,
                "path": request.url.path,
                "query": str(request.url.query),
                "token": token,
                "headers": dict(request.headers),
                "body": body.decode() if body else "",
            }
        )
        # Echo the token back so a test can decode what actually arrived.
        return JSONResponse({"ok": True, "received_token": token, "path": request.url.path})

    app = Starlette(
        routes=[Route("/{path:path}", handler, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])]
    )
    return app, rec


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="Local upstream fixture")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    app, _ = build_upstream()
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
