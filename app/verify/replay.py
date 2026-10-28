"""Single-use stores for transaction tokens at the resource side.

``claim(key, ttl)`` is atomic: the first caller gets ``True``, everyone after ``False``. A
store that cannot answer raises, and the verifier refuses — a replay guard that quietly
degrades is worse than one that says so (spec FR-009).
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only; app.verify must not import redis
    from redis import Redis


class ReplayStoreUnavailable(RuntimeError):
    """The store could not be consulted. Always a refusal."""


class ReplayStore(Protocol):
    def claim(self, key: str, ttl_seconds: int) -> bool:
        """``True`` if this is the first claim of ``key``; raises ``ReplayStoreUnavailable``."""
        ...


class InMemoryReplay:
    """Single-process store with expiry. Fine for one resource server instance; use
    :class:`RedisReplay` behind more than one."""

    def __init__(self, clock: Any = time.monotonic) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def claim(self, key: str, ttl_seconds: int) -> bool:
        now = self._clock()
        with self._lock:
            expired = [k for k, until in self._seen.items() if until <= now]
            for k in expired:
                del self._seen[k]
            if key in self._seen:
                return False
            self._seen[key] = now + max(ttl_seconds, 1)
            return True


class RedisReplay:
    """``SET NX EX`` on a synchronous redis client (any object with a compatible ``set``)."""

    def __init__(self, client: Redis | Any) -> None:
        self._client = client

    def claim(self, key: str, ttl_seconds: int) -> bool:
        try:
            claimed = self._client.set(key, "1", ex=max(ttl_seconds, 1), nx=True)
        except Exception as exc:
            raise ReplayStoreUnavailable(f"replay store unreachable: {exc}") from exc
        return bool(claimed)


def txn_key(jti: str) -> str:
    return f"txn:{jti}"


__all__ = ["InMemoryReplay", "RedisReplay", "ReplayStore", "ReplayStoreUnavailable", "txn_key"]
