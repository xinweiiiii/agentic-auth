"""In-process fake MCP capability source(s) serving RFC 9728 metadata.

One ASGI app answers for many authorities; it picks the resource document by the request
``Host`` header. Unknown hosts 404; the special host ``down.internal`` returns 503 so tests
can exercise the ``DISCOVERY_UNAVAILABLE`` path.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

# authority host -> protected-resource-metadata document
RESOURCES: dict[str, dict] = {
    "kb.internal": {
        "resource": "https://kb.internal",
        "scopes_supported": ["kb.public", "kb.internal"],
        "tools": {
            "search": {"data_classes": ["kb.public", "kb.internal"], "privileged": False},
        },
    },
    "accounts.internal": {
        "resource": "https://accounts.internal",
        "scopes_supported": ["account.read", "account.write"],
        "tools": {
            "read_account": {"data_classes": ["account.read"], "privileged": False},
            "close_account": {"data_classes": ["account.write"], "privileged": True},
            # Phase 3 bank scenario (tests/fixtures/bank.py).
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


async def _well_known(request: Request) -> JSONResponse:
    host = request.headers.get("host", "").split(":")[0]
    if host == DOWN_HOST:
        return JSONResponse({"error": "unavailable"}, status_code=503)
    doc = RESOURCES.get(host)
    if doc is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(doc)


fake_discovery_app = Starlette(routes=[Route("/.well-known/oauth-protected-resource", _well_known)])
