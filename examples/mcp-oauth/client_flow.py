"""A standard MCP client's authorization flow — with no Agentic Auth code in it.

This is what any client following the MCP 2026-07-28 authorization spec does, and the point
of the example: nothing here imports or knows about Agentic Auth. It calls the server, is
challenged, follows the challenge to the Protected Resource Metadata, finds the
authorization server there, signs the user in, and calls again with the token.

``sign_in`` stands for the login. A real client runs the OAuth 2.1 authorization code flow
with PKCE against the authorization server's ``authorization_endpoint`` here; the example
hands it a function that returns the token that login would produce.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

SignIn = Callable[[dict[str, Any], str, list[str]], Awaitable[str]]


def _param(challenge: str, name: str) -> str | None:
    match = re.search(rf'{name}="([^"]*)"', challenge)
    return match.group(1) if match else None


async def call_tool(
    http: httpx.AsyncClient, server_url: str, tool: str, sign_in: SignIn, *, log=print
) -> dict[str, Any]:
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool}}

    first = await http.post(server_url, json=rpc)
    log(f"1. call without a token          -> {first.status_code}")
    if first.status_code != 401:
        return first.json()

    challenge = first.headers["www-authenticate"]
    metadata_url = _param(challenge, "resource_metadata")
    assert metadata_url, "a 401 from an MCP server must point at its resource metadata"
    resource = (await http.get(metadata_url)).json()
    authorization_server = resource["authorization_servers"][0]
    log(f"2. protected resource metadata   -> authorization server {authorization_server}")

    issuer = httpx.URL(authorization_server)
    discovery = f"{issuer.scheme}://{issuer.netloc.decode()}/.well-known/oauth-authorization-server"
    server_metadata = (await http.get(discovery)).json()
    log(f"3. authorization server metadata -> issuer {server_metadata['issuer']}")

    token = await sign_in(server_metadata, resource["resource"], resource["scopes_supported"])
    log("4. user signed in                -> access token for " + resource["resource"])

    second = await http.post(server_url, json=rpc, headers={"Authorization": f"Bearer {token}"})
    log(f"5. call with the token           -> {second.status_code}")
    return second.json()
