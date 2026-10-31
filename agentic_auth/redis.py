"""Async Redis client — used only as the immutable compiled-DAG cache."""

from __future__ import annotations

from redis.asyncio import Redis, from_url

from agentic_auth import runtime
from agentic_auth.config import get_settings

_client: Redis | None = None


def get_redis() -> Redis:
    current = runtime.override()
    if current is not None:
        return current.redis
    global _client
    if _client is None:
        _client = from_url(get_settings().redis_url, decode_responses=True)
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
