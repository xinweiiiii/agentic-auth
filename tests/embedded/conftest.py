"""The embedded control plane on its own: no PostgreSQL, no Redis, no network.

These are the tests a release runs against the built wheel, on a runner with nothing else
installed — so nothing here may reach the root conftest's database fixtures.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio

from agentic_auth.embedded import EmbeddedControlPlane
from tests.fixtures.discovery.server import RESOURCES


@pytest_asyncio.fixture(autouse=True)
async def _clean() -> AsyncIterator[None]:
    """Shadows the root conftest's PostgreSQL cleanup; every instance here owns its store."""
    yield


@pytest_asyncio.fixture
async def cp() -> AsyncIterator[EmbeddedControlPlane]:
    async with EmbeddedControlPlane.open(capabilities=RESOURCES) as instance:
        yield instance
