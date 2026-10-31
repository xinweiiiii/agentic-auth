"""Which control plane this code is running for.

The control plane keeps its collaborators in process-wide accessors: ``get_settings()``,
``get_engine()``, ``get_redis()``, ``get_issuer_key()``, ``get_metrics()``. A deployed control
plane is one per process, and those accessors are exactly right for it.

The embedded control plane (``agentic_auth.embedded``) breaks that assumption on purpose:
two instances in one test process must not share a signing key, a database or an audit log
(FR-016). So each accessor first asks ``override()`` whether the current task is running on
behalf of an embedded instance, and only otherwise falls back to the process-wide value.

The override travels in a ``ContextVar``, so it follows ``await``, ``asyncio.create_task`` and
Starlette background tasks, and is set per request by the embedded app's middleware. Outside
that, it is ``None`` and every accessor behaves exactly as it always has.

Stdlib only at import time: ``agentic_auth.config`` imports this module.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    import httpx
    from redis.asyncio import Redis
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

    from agentic_auth.config import Settings
    from agentic_auth.services.metrics import ControlPlaneMetrics
    from agentic_auth.services.tokens.keys import IssuerKey

Deployment = Literal["server", "embedded"]


@dataclass
class Runtime:
    """Everything the process-wide accessors would otherwise hand out, for one instance."""

    settings: Settings
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    redis: Redis
    issuer_key: IssuerKey
    metrics: ControlPlaneMetrics
    # The one HTTP client this instance uses for outbound calls it makes on its own behalf:
    # capability discovery and the identity provider's JWKS. Routed in-process, never a socket.
    http: httpx.AsyncClient
    deployment: Deployment = "embedded"
    # Sessions created before this moment are refused (SESSION_SUPERSEDED). Set when a
    # durable store is reopened: the taint marks and replay records that protected those
    # sessions lived in memory and are gone, so honouring them would fail open.
    superseded_before: datetime | None = None
    # Built lazily inside the runtime, because constructing one reads get_issuer_key().
    _token_profile: Any = field(default=None, repr=False)


_current: ContextVar[Runtime | None] = ContextVar("agentic_auth_runtime", default=None)


def override() -> Runtime | None:
    """The embedded instance the current task runs for, or ``None`` for the process default."""
    return _current.get()


def deployment() -> Deployment:
    current = _current.get()
    return current.deployment if current is not None else "server"


@contextlib.contextmanager
def use_runtime(runtime: Runtime) -> Iterator[Runtime]:
    token = _current.set(runtime)
    try:
        yield runtime
    finally:
        _current.reset(token)
