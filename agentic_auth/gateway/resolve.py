"""Route resolution for the shared gateway.

The sidecar resolves a route from its own single-agent config. A gateway serves many
agents from one table, so resolution needs an agent — and **the agent comes from the
presented token, never from configuration and never from a request header**.

Reading the token unverified for this is safe, and for exactly the reason
``agentic_auth.sidecar.enforce._unverified_claims`` documents: routing is not a decision. A lie
here picks a different target, and the PDP then refuses that target for this caller,
because it verifies the signature and checks ``caller`` against it. A lie buys a deny,
never an allow. Trusting an ``X-Agentic-Agent`` header instead would be a different and
much worse thing — centrally, it would let any agent claim any other's routes.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from collections.abc import Mapping

from starlette.responses import JSONResponse

from agentic_auth.gateway.config import GatewayConfig
from agentic_auth.sidecar import deny
from agentic_auth.sidecar.config import Upstream
from agentic_auth.sidecar.enforce import (
    DATA_CLASS_HEADER,
    TARGET_HEADER,
    _has_traversal,
)

logger = logging.getLogger(__name__)


def agent_of(token: str) -> str | None:
    """Who holds this token: the agent it was issued to once delegation has begun, or the
    consenting human under the root grant.

    Never the ``act`` link — that is the *previous* actor, not the current one. Reading
    the caller off ``act`` would let a delegator's identity stand in for its delegate's,
    which is a privilege escalation rather than a naming quibble. Mirrors the rule in
    ``agentic_auth.sidecar.enforce`` and in ``pdp.decide``.
    """
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    except (IndexError, ValueError, binascii.Error, UnicodeDecodeError):
        return None
    holder = claims.get("aud") if claims.get("act") else claims.get("sub")
    return holder if isinstance(holder, str) and holder else None


def agent_name(holder: str | None) -> str | None:
    """The bare agent name for route lookup. ``user:alice`` under a root grant has no
    agent-specific routes, so it resolves against the any-agent fallback only."""
    if holder is None or not holder.startswith("agent://"):
        return None
    return holder.removeprefix("agent://")


def resolve(
    config: GatewayConfig,
    *,
    agent: str | None,
    path: str,
    headers: Mapping[str, str],
) -> tuple[str, Upstream, str, str] | JSONResponse:
    """``(prefix, upstream, target, data_class)``, or a refusal.

    Three ways this refuses, all of them closed:

    - **Path traversal.** The matched prefix selects which policy target the call is
      authorized against, and the same prefix is then stripped to build the upstream URL.
      A dot segment makes those two disagree — ``/kb/../admin`` authorized as ``/kb`` and
      delivered to ``/admin``. Rejected rather than normalised, because normalising would
      silently change which prefix matched.
    - **No route.** Nothing in the table matches for this agent.
    - **No target or data class.** Neither the table nor the headers supplied one.
      Guessing a data class would be inventing consent.
    """
    if _has_traversal(path):
        return deny.not_mapped(path)

    match = config.resolve(agent, path)
    if match is None:
        return deny.not_mapped(path)
    prefix, upstream = match

    target = upstream.target or headers.get(TARGET_HEADER)
    data_class = upstream.data_class or headers.get(DATA_CLASS_HEADER)
    if not target or not data_class:
        return deny.target_unresolved(path)
    return prefix, upstream, target, data_class


__all__ = ["agent_of", "agent_name", "resolve"]
