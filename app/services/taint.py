"""Provenance taint — derived by the control plane, never trusted from the agent.

The PDP decides every call, so it knows when a caller reaches for a source its pinned
manifest does not trust. That moment marks the caller's context — and every ancestor
context, whose owners will consume the result on the way back — in a per-session Redis
HASH. The effective taint of a decision is the maximum of the presented token's signed
``taint`` claim, the agent-reported label (additive only), and that mark
(https://authzai.dev/explanation/the-taint-and-provenance-model).

The pure functions here take a :class:`PolicyIndex` and plain values; :class:`TaintStore`
is the only I/O.
"""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from app.schemas.authorize import Taint
from app.services.policy_loader import PolicyIndex

SENTINEL = "*"
"""Marks the whole session: an ancestor's ``jti`` was unknown (a chain written by Phase 3),
so the fail-closed reading is that every context in the session may have consumed it."""


class TaintStoreUnavailable(RuntimeError):
    """The taint set could not be read or written. The caller decides: a protected target
    is refused ``PDP_UNAVAILABLE``; an unprotected one proceeds with taint unknown."""


# -- pure ------------------------------------------------------------------------------


def classify_source(policy: PolicyIndex, agent: str, target: str) -> Taint:
    """What a result from ``target`` is worth to ``agent``: trusted only if a glob says so."""
    return (
        Taint.TRUSTED_INTERNAL
        if policy.is_trusted_source(agent, target)
        else Taint.UNTRUSTED_EXTERNAL
    )


def is_protected(policy: PolicyIndex, agent: str, target: str, data_class: str) -> bool:
    return policy.is_protected(agent, target, data_class)


def effective_taint(token_taint: Taint | None, request_taint: Taint | None, marked: bool) -> Taint:
    """``max`` over the three inputs. Never lowers: a missing input is trusted, an untrusted
    input anywhere wins."""
    if (
        token_taint is Taint.UNTRUSTED_EXTERNAL
        or request_taint is Taint.UNTRUSTED_EXTERNAL
        or marked
    ):
        return Taint.UNTRUSTED_EXTERNAL
    return Taint.TRUSTED_INTERNAL


def ancestors_of(parent_chain: Iterable[Mapping[str, Any]] | None, own_jti: str) -> set[str]:
    """Every context that will consume this call's result: this one and each ancestor hop's
    ``subject_jti``. An ancestor written before Phase 4 has none, and yields the sentinel."""
    contexts = {own_jti}
    for entry in parent_chain or ():
        jti = entry.get("subject_jti")
        contexts.add(jti if isinstance(jti, str) and jti else SENTINEL)
    return contexts


@dataclass(frozen=True)
class Mark:
    """One recorded mark: which context, the source that introduced the taint, the decision
    whose allow introduced it, and when.

    The action id matters once: the exchange that spends THAT decision must not see the mark
    its own allow created (the result is not consumed until the call is made), while every
    later decision in the context must. Marks are stored one per ``(context, action)`` so an
    exclusion never hides a mark some other decision left.
    """

    context: str
    source: str
    action_id: str | None
    ts: float

    @property
    def field(self) -> str:
        return f"{self.context}|{self.action_id or '-'}"

    def encode(self) -> str:
        return json.dumps({"source": self.source, "ts": self.ts}, separators=(",", ":"))

    @staticmethod
    def decode(field: str, raw: str) -> Mark:
        context, _, action = field.partition("|")
        action_id = action if action and action != "-" else None
        try:
            data = json.loads(raw)
            return Mark(context, str(data["source"]), action_id, float(data.get("ts", 0.0)))
        except (ValueError, KeyError, TypeError):
            return Mark(context, str(raw), action_id, 0.0)  # a pre-JSON value: source alone


@dataclass(frozen=True)
class Marked:
    """What the store knows about one presented context."""

    tainted: bool
    source: str | None

    @staticmethod
    def of(marks: Iterable[Mark], jti: str, *, exclude_action_id: str | None = None) -> Marked:
        relevant = [
            m
            for m in marks
            if m.context in (jti, SENTINEL)
            and not (exclude_action_id is not None and m.action_id == exclude_action_id)
        ]
        if not relevant:
            return Marked(False, None)
        # The source named is the one that introduced the taint: the earliest exact mark,
        # or the earliest sentinel when nothing exact exists.
        exact = [m for m in relevant if m.context == jti]
        chosen = min(exact or relevant, key=lambda m: m.ts)
        return Marked(True, chosen.source)


# -- the store -----------------------------------------------------------------------------


def taint_key(session_id: str) -> str:
    return f"taint:{session_id}"


class TaintStore:
    def __init__(self, redis: Redis | None) -> None:
        self._redis = redis

    async def marked(self, session_id: str) -> list[Mark]:
        """Every mark in the session."""
        if self._redis is None:
            raise TaintStoreUnavailable("no taint store configured")
        try:
            raw = await self._redis.hgetall(taint_key(session_id))
        except Exception as exc:
            raise TaintStoreUnavailable(f"taint store unreachable: {exc}") from exc
        out: list[Mark] = []
        for k, v in (raw or {}).items():
            field = k.decode() if isinstance(k, bytes) else k
            value = v.decode() if isinstance(v, bytes) else v
            out.append(Mark.decode(field, value))
        return out

    async def mark(
        self,
        session_id: str,
        contexts: Iterable[str],
        source: str,
        *,
        action_id: str | None,
        ttl_seconds: int,
    ) -> None:
        """Mark every context in ``contexts`` as having consumed ``source`` through the
        decision ``action_id``. One field per (context, action); ``HSETNX`` keeps the first
        timestamp if the same decision marks twice."""
        if self._redis is None:
            raise TaintStoreUnavailable("no taint store configured")
        key = taint_key(session_id)
        now = time.time()
        try:
            pipe = self._redis.pipeline(transaction=True)
            for ctx in contexts:
                mark = Mark(ctx, source, action_id, now)
                pipe.hsetnx(key, mark.field, mark.encode())
            pipe.expire(key, max(int(ttl_seconds), 1))
            await pipe.execute()
        except Exception as exc:
            raise TaintStoreUnavailable(f"taint store unreachable: {exc}") from exc

    async def clear(self, session_id: str) -> None:  # tests only
        if self._redis is None:
            return
        with contextlib.suppress(Exception):
            await self._redis.delete(taint_key(session_id))


__all__ = [
    "SENTINEL",
    "Mark",
    "Marked",
    "TaintStore",
    "TaintStoreUnavailable",
    "ancestors_of",
    "classify_source",
    "effective_taint",
    "is_protected",
    "taint_key",
]
