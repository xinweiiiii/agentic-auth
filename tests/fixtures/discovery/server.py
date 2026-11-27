"""In-process fake MCP capability source(s) serving RFC 9728 metadata.

One ASGI app answers for many authorities; it picks the resource document by the request
``Host`` header. Unknown hosts 404; the special host ``down.internal`` returns 503 so tests
can exercise the ``DISCOVERY_UNAVAILABLE`` path.

Feature 011 (M3): the PRM documents name authorization servers, and the same app serves their
RFC 8414 metadata by host. ``payments.internal``'s authorization server lists fewer scopes
than the resource advertises, ``ledger.internal`` names none, ``asdown.internal`` names one
that is down, and ``noscopes.internal``'s omits ``scopes_supported``. Discovery ignores these
fields unless ``as_metadata_enabled`` is on.
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
        "authorization_servers": ["https://as.kb.internal"],
        "scopes_supported": ["kb.public", "kb.internal"],
        "tools": {
            "search": {"data_classes": ["kb.public", "kb.internal"], "privileged": False},
        },
    },
    "accounts.internal": {
        "resource": "https://accounts.internal",
        "authorization_servers": ["https://as.accounts.internal"],
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
    "asdown.internal": {
        "resource": "https://asdown.internal",
        "authorization_servers": ["https://down.internal"],
        "scopes_supported": ["notes.read"],
        "tools": {"read_notes": {"data_classes": ["notes.read"], "privileged": False}},
    },
    "payments.internal": {
        "resource": "https://payments.internal",
        "authorization_servers": ["https://as.payments.internal"],
        "scopes_supported": ["payments.read", "payments.write"],
        "tools": {
            "refund": {"data_classes": ["payments.read", "payments.write"], "privileged": False}
        },
    },
    "noscopes.internal": {
        "resource": "https://noscopes.internal",
        "authorization_servers": ["https://as.noscopes.internal"],
        "scopes_supported": ["wiki.read"],
        "tools": {"read_wiki": {"data_classes": ["wiki.read"], "privileged": False}},
    },
}

# authorization server host -> RFC 8414 metadata
AUTHORIZATION_SERVERS: dict[str, dict] = {
    "as.kb.internal": {
        "issuer": "https://as.kb.internal",
        "scopes_supported": ["kb.public", "kb.internal"],
    },
    "as.accounts.internal": {
        "issuer": "https://as.accounts.internal",
        "scopes_supported": ["account.read", "account.write"],
    },
    # Narrower than its resource: payments.write is advertised by the tool, not issued here.
    "as.payments.internal": {
        "issuer": "https://as.payments.internal",
        "scopes_supported": ["payments.read"],
    },
    "as.noscopes.internal": {"issuer": "https://as.noscopes.internal"},
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


async def _authorization_server(request: Request) -> JSONResponse:
    host = request.headers.get("host", "").split(":")[0]
    if host == DOWN_HOST:
        return JSONResponse({"error": "unavailable"}, status_code=503)
    doc = AUTHORIZATION_SERVERS.get(host)
    if doc is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(doc)


fake_discovery_app = Starlette(
    routes=[
        Route("/.well-known/oauth-protected-resource", _well_known),
        Route("/.well-known/oauth-authorization-server", _authorization_server),
        Route("/.well-known/openid-configuration", _authorization_server),
    ]
)
