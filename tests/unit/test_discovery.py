"""DiscoveryClient — RFC 9728 fetch, mcp:// mapping, failure handling."""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport

from agentic_auth.services.discovery import DiscoveryClient, authority_for, tool_name
from tests.fixtures.discovery.server import fake_discovery_app


@pytest.mark.parametrize(
    ("ref", "authority", "name"),
    [
        ("mcp://kb.internal/search", "https://kb.internal", "search"),
        ("mcp://kb.internal:8443/search", "https://kb.internal:8443", "search"),
        ("mcp://accounts.internal/read_account", "https://accounts.internal", "read_account"),
    ],
)
def test_authority_and_tool_mapping(ref: str, authority: str, name: str) -> None:
    assert authority_for(ref) == authority
    assert tool_name(ref) == name


async def _discover(authorities: set[str]) -> dict:
    http = httpx.AsyncClient(transport=ASGITransport(app=fake_discovery_app))
    client = DiscoveryClient(client=http)
    try:
        return await client.discover(authorities)
    finally:
        await http.aclose()


async def test_discovers_known_authority() -> None:
    results = await _discover({"https://kb.internal"})
    r = results["https://kb.internal"]
    assert r.ok
    assert r.resource is not None
    assert "search" in r.resource.tools


async def test_unknown_authority_marked_unavailable() -> None:
    results = await _discover({"https://nope.internal"})
    assert results["https://nope.internal"].ok is False
    assert "404" in results["https://nope.internal"].error


async def test_down_authority_marked_unavailable() -> None:
    results = await _discover({"https://down.internal"})
    assert results["https://down.internal"].ok is False
    assert "503" in results["https://down.internal"].error
