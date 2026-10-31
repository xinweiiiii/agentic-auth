"""Per-hop context.

The delegation chain and the depth are **read from the token**, never tracked alongside
it. There is no counter to increment and no list to append to, so a client cannot drift
out of sync with the signed truth — which is the whole point of deriving depth from
``act`` in the first place.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

SESSION_HEADER = "X-Agentic-Session"


def _claims(token: str) -> dict[str, Any]:
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=="))
    except (IndexError, ValueError, binascii.Error, UnicodeDecodeError):
        return {}


@dataclass(frozen=True)
class HopContext:
    """What travels between hops: the session and the current token — plus, within a hop,
    the taint this context has accumulated. The token's own ``taint`` claim is the
    floor; ``tainted()`` can only raise it."""

    session_id: str
    token: str
    _taint: str | None = None

    @property
    def taint(self) -> str | None:
        """``trusted_internal`` | ``untrusted_external`` | ``None`` (nothing known)."""
        claim = self.claims.get("taint")
        labels = [x for x in (claim, self._taint) if x]
        if not labels:
            return None
        return "untrusted_external" if "untrusted_external" in labels else "trusted_internal"

    def tainted(self, trust: str, source_ref: str | None = None) -> HopContext:
        """A copy whose taint is at least ``trust``. Monotonic: never lowers."""
        if trust not in ("trusted_internal", "untrusted_external"):
            raise ValueError(f"unknown trust class {trust!r}")
        current = self.taint
        if current == "untrusted_external" or trust == "trusted_internal":
            return HopContext(self.session_id, self.token, current)
        return HopContext(self.session_id, self.token, trust)

    @property
    def claims(self) -> dict[str, Any]:
        return _claims(self.token)

    @property
    def act_chain(self) -> list[str]:
        """``[human, first delegate, ..., current actor]``."""
        c = self.claims
        actors: list[str] = []
        act = c.get("act")
        while isinstance(act, dict):
            actors.append(act.get("sub", ""))
            act = act.get("act")
        return [c.get("sub", ""), *reversed(actors)]

    @property
    def hop(self) -> int:
        """Depth of the hop this token is being presented for."""
        return len(self.act_chain)

    @property
    def caller(self) -> str:
        """Who holds this token: the agent it was issued to, or the human at the root."""
        c = self.claims
        return c.get("aud", "") if c.get("act") else c.get("sub", "")

    def headers(self) -> dict[str, str]:
        """The complete propagation format. The chain and depth ride inside the signed
        token; the session id is a convenience so the next hop can look up its session
        before parsing a token it has not yet verified.

        Nothing security-relevant travels in a header — a forged session id that
        disagrees with the token's own is a deny.
        """
        return {"Authorization": f"Bearer {self.token}", SESSION_HEADER: self.session_id}

    def advanced(self, token: str) -> HopContext:
        """The context for the next hop. Same session, new narrowed token. The new token's
        ``taint`` claim carries the delegator's taint downstream; nothing else is copied."""
        return HopContext(session_id=self.session_id, token=token)
