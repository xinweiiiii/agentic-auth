"""The nested ``act`` claim — the only module that parses it.

Per RFC 8693 §4.1 the chain nests inside-out: the outermost ``act`` is the current actor
and the innermost is the first delegate. ``sub`` never moves — it stays the consenting
human at every depth.

Delegation depth is read from here and nowhere else. A caller-supplied hop count is a
number the attacker controls; ``act`` sits inside a signed envelope, so under-reporting
depth requires forging a signature.
"""

from __future__ import annotations

from typing import Any

MAX_DEPTH = 32  # a chain deeper than any legal hop budget is malformed, not slow

# `mutmut run` leaves 5 equivalent mutants in `depth()`, all inside the `extra = ...`
# expression that only builds the text of a MalformedActChain message. The guard above it
# — `set(node) - {"sub", "act"}` — is the behaviour, and mutating it is killed. Every
# mutant that changes whether a chain is rejected, or the depth reported, is killed.


class MalformedActChain(ValueError):
    """The presented ``act`` claim is not a well-formed delegation chain."""


def nest(act: dict[str, Any] | None, agent: str) -> dict[str, Any]:
    """Add ``agent`` as the new outermost actor."""
    if not agent:
        raise MalformedActChain("actor must be a non-empty identifier")
    return {"sub": agent} if act is None else {"sub": agent, "act": act}


def depth(act: dict[str, Any] | None) -> int:
    """Nesting count. Absent -> 0 (the root grant), {sub} -> 1, {sub, act:{sub}} -> 2."""
    n = 0
    node = act
    while node is not None:
        if not isinstance(node, dict):
            raise MalformedActChain(f"act link is {type(node).__name__}, expected object")
        sub = node.get("sub")
        if not isinstance(sub, str) or not sub:
            raise MalformedActChain("act link is missing a non-empty 'sub'")
        if set(node) - {"sub", "act"}:
            extra = sorted(set(node) - {"sub", "act"})
            raise MalformedActChain(f"unexpected keys in act link: {extra}")
        n += 1
        if n > MAX_DEPTH:
            raise MalformedActChain(f"act chain deeper than {MAX_DEPTH}")
        node = node.get("act")
    return n


def walk(act: dict[str, Any] | None, sub: str) -> list[str]:
    """The chain in delegation order: ``[human, first delegate, ..., current actor]``."""
    actors: list[str] = []
    node = act
    while node is not None:
        depth(node)  # validate this link before trusting it
        actors.append(node["sub"])
        node = node.get("act")
    return [sub, *reversed(actors)]


def hop_of(act: dict[str, Any] | None) -> int:
    """The hop a token carrying this chain was issued for. Root grant is hop 1."""
    return depth(act) + 1


def current_actor(act: dict[str, Any] | None, sub: str) -> str:
    """Who is presenting this token: the outermost actor, or the human at the root."""
    if act is None:
        return sub
    depth(act)
    return act["sub"]
