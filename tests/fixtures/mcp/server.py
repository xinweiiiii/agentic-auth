"""A minimal MCP-shaped server, for testing the connector proxy (US4).

Not an MCP implementation — just enough of the streamable-HTTP JSON-RPC shape that the
proxy's three behaviours can be exercised honestly: relay, filter, and decide.

It has **its own bearer auth**, deliberately. That is how the tests assert the proxy
passes the upstream's handshake through rather than re-implementing it (research.md R8),
and how they assert the agent never receives the upstream's credential.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

#: What the upstream itself requires. The agent never learns this value.
UPSTREAM_TOKEN = "upstream-only-secret"

TOOLS = [
    {"name": "search", "description": "search the knowledge base"},
    {"name": "read_balance", "description": "read an account balance"},
    {"name": "terminate_account", "description": "close an account"},
]


@dataclass
class McpRecorder:
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    #: Authorization values the upstream actually received, so a test can prove the
    #: narrowed token arrived rather than the one the agent presented.
    authorizations: list[str] = field(default_factory=list)
    headers: list[dict[str, str]] = field(default_factory=list)

    @property
    def last_tool(self) -> str:
        if not self.calls:
            raise AssertionError("the upstream saw no tools/call")
        return self.calls[-1][0]


def build_mcp_server(*, require_token: bool = False) -> tuple[Starlette, McpRecorder]:
    rec = McpRecorder()

    async def rpc(request: Request) -> JSONResponse:
        body = await request.json()
        method = body.get("method")
        request_id = body.get("id")
        auth = request.headers.get("authorization", "")
        rec.authorizations.append(auth)
        rec.headers.append(dict(request.headers))

        if require_token and auth != f"Bearer {UPSTREAM_TOKEN}":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32001, "message": "upstream refused: bad token"},
                }
            )

        if method == "initialize":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"protocolVersion": "2025-06-18", "serverInfo": {"name": "fake"}},
                }
            )
        if method == "tools/list":
            return JSONResponse(
                {"jsonrpc": "2.0", "id": request_id, "result": {"tools": list(TOOLS)}}
            )
        if method == "tools/call":
            params = body.get("params") or {}
            rec.calls.append((params.get("name", ""), params.get("arguments") or {}))
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": "real result"}]},
                }
            )
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"no such method {method!r}"},
            }
        )

    return Starlette(routes=[Route("/{path:path}", rpc, methods=["POST"])]), rec
