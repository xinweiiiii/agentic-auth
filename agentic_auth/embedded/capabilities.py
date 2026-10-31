"""The RFC 9728 documents an embedded instance reconciles manifests against.

A real deployment fetches ``/.well-known/oauth-protected-resource`` from each MCP server a
manifest names. An embedded instance has no network, so it is handed the documents instead,
keyed by host. A host with no document is *unreachable*, not empty: reconciliation reports
discovery as unavailable and the manifest needs a recorded override reason, exactly the rule
the server applies when a tool host is down.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from agentic_auth.embedded._transport import WELL_KNOWN


def capability_app(documents: Mapping[str, Mapping[str, Any]]) -> Starlette:
    docs = {host: dict(doc) for host, doc in documents.items()}

    async def document(request: Request) -> JSONResponse:
        host = request.headers.get("host", "").split(":")[0]
        doc = docs.get(host)
        if doc is None:
            # Indistinguishable, to the discovery client, from a host that is down.
            return JSONResponse({"error": "unavailable"}, status_code=503)
        return JSONResponse(doc)

    return Starlette(routes=[Route(WELL_KNOWN, document)])
