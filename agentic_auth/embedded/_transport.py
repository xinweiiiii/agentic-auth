"""One ``httpx`` transport, several in-process services, routed by host. No sockets.

The embedded control plane, the capability documents its manifests reconcile against, the
test identity provider and any tool server a test mounts all live behind this. A request for
a host nothing is mounted on fails exactly as an unreachable network host does, so every
"discovery unavailable" and "control plane down" path is the real one.
"""

from __future__ import annotations

from typing import Any

import httpx

WELL_KNOWN = "/.well-known/oauth-protected-resource"
CAPABILITIES = "capabilities.embedded.invalid"


class HostRouter(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.routes: dict[str, httpx.AsyncBaseTransport] = {}
        # Hosts made unreachable on purpose, the way an outage does (fail-closed demos).
        self.cut: set[str] = set()

    def mount(self, host: str, app: Any) -> None:
        self.routes[host] = httpx.ASGITransport(app=app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host in self.cut:
            raise httpx.ConnectError(f"{host} is unreachable", request=request)
        # Every tool host's RFC 9728 document is served by the capability source — including
        # a host with a tool server mounted, which answers only for its tools. That is what
        # a real MCP server looks like from outside: one host, both paths.
        if request.url.path == WELL_KNOWN:
            host = CAPABILITIES
        transport = self.routes.get(host)
        if transport is None:
            raise httpx.ConnectError(f"nothing is listening on {host}", request=request)
        return await transport.handle_async_request(request)
