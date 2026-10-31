"""Standalone RFC 9728 capability source for local end-to-end testing.

Not part of the shipped control plane — a throwaway server you run alongside
`agentic_auth.main:app` so `POST /v1/agents` does a genuine network round trip to a capability
source instead of the in-process fake used by the test suite
(`tests/fixtures/discovery/server.py`).

Usage (see https://authzai.dev/tutorials/enroll-your-first-agent for the full walkthrough):

    uvicorn scripts.mock_discovery_server:app \\
        --host 127.0.0.1 --port 8443 \\
        --ssl-certfile /tmp/e2e-cert.pem --ssl-keyfile /tmp/e2e-key.pem

Then point manifest tool refs at it directly by IP, e.g.
``mcp://127.0.0.1:8443/search`` — no `/etc/hosts` edit or real DNS name needed.
"""

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

# Every tool this server will vouch for. Add entries here to exercise more of the
# reconciler (e.g. add a tool with no `data_classes` to trigger UNKNOWN_TOOL for any
# ref your manifest declares that isn't listed).
DOC = {
    "resource": "https://127.0.0.1:8443",
    "scopes_supported": [
        "kb.public",
        "kb.internal",
        "account.read",
        "account.write",
        "ledger.read",
    ],
    "tools": {
        "search": {"data_classes": ["kb.public", "kb.internal"], "privileged": False},
        "read_account": {"data_classes": ["account.read"], "privileged": False},
        "close_account": {"data_classes": ["account.write"], "privileged": True},
        "read_ledger": {"data_classes": ["ledger.read"], "privileged": False},
    },
}


async def well_known(_: Request) -> JSONResponse:
    return JSONResponse(DOC)


app = Starlette(routes=[Route("/.well-known/oauth-protected-resource", well_known)])
