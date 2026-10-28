"""Short-lived decision cache.

The policy version is **inside the key**, so invalidation is structural: a session pinned
to version 42 can never read a version 43 entry, and there is no invalidation event to
forget. This mirrors Phase 1's immutable ``dag:{scope}:{version}`` keys, where the same
trick made invalidation a non-problem.

Only decisions are cached. Tokens are always minted fresh — a cached token would break
single-hop binding, which is the one thing the whole phase is for.
"""

from __future__ import annotations

import contextlib
import hashlib
import json

from redis.asyncio import Redis

from app.config import get_settings
from app.schemas.authorize import AuthorizeRequest, DenyReason, Taint
from app.services.pdp import Decision


def key(
    request: AuthorizeRequest,
    *,
    policy_version: int,
    hop: int,
    act_chain: list[str],
    taint: Taint | None = None,
    revoked: frozenset[str] = frozenset(),
    consented_data_classes: frozenset[str] | None = None,
    step_up: frozenset[str] = frozenset(),
) -> str:
    """Every input `decide()` reads, hashed into one unambiguous key.

    Two things this must not get wrong.

    **The chain is part of the decision.** `decide()` builds `path_so_far` from the
    delegation chain and looks up `budget_for_path(full_path)`, so the same
    (caller, target, data_class, hop) can be allowed via one route and denied via
    another — fan-out is ordinary DAG shape, and both routes live in one session.
    Omitting the chain would serve the allow for the wrong path.

    **Concatenation is ambiguous.** Targets are URIs full of colons, so a `":".join`
    lets `(target="mcp://kb", data_class="x:read")` and `(target="mcp://kb:x",
    data_class="read")` produce the same key. JSON-encoding the parts first removes
    the ambiguity; hashing keeps the key a bounded length.

    `policy_version` stays in the plaintext prefix so structural invalidation — a
    pinned session can never read another version's entry — is still greppable in a
    running Redis.
    """
    canonical = json.dumps(
        [
            policy_version,
            request.session_id,
            request.caller,
            request.target,
            request.data_class,
            hop,
            act_chain,
            # Phase 4: both are decision inputs, so a context that became tainted, or an
            # agent that was revoked, can never read an earlier allow.
            taint.value if taint else None,
            sorted(revoked),
            # Phase 5: both are decision inputs too. Without `step_up` in the key, a
            # session a human has just widened would read back the deny it was widened
            # past — the cache would undo the consent. `None` and the empty set are
            # deliberately distinct: None means "everything the policy declares".
            None if consented_data_classes is None else sorted(consented_data_classes),
            sorted(step_up),
        ],
        separators=(",", ":"),
    )
    return f"pdp:{policy_version}:{hashlib.sha256(canonical.encode()).hexdigest()}"


async def get(redis: Redis | None, cache_key: str) -> Decision | None:
    """A miss, a malformed entry, or an outage all return ``None`` — the caller then
    evaluates fully. Slower, never wrong, and never an allow a fresh evaluation would
    refuse."""
    if redis is None:
        return None
    try:
        raw = await redis.get(cache_key)
    except Exception:
        return None
    if raw is None:
        return None
    try:
        d = json.loads(raw)
        return Decision(
            outcome=d["outcome"],
            hop=d["hop"],
            reason=DenyReason(d["reason"]) if d.get("reason") else None,
            message=d.get("message"),
            privileged=bool(d.get("privileged", False)),
            transaction_required=bool(d.get("transaction_required", False)),
            taint=Taint(d["taint"]) if d.get("taint") else None,
        )
    except (ValueError, KeyError, TypeError):
        return None


async def put(redis: Redis | None, cache_key: str, decision: Decision) -> None:
    """Best effort. A cache that cannot be written is a slower system, not a wrong one."""
    if redis is None:
        return
    payload = json.dumps(
        {
            "outcome": decision.outcome,
            "hop": decision.hop,
            "reason": decision.reason.value if decision.reason else None,
            "message": decision.message,
            "privileged": decision.privileged,
            "transaction_required": decision.transaction_required,
            "taint": decision.taint.value if decision.taint else None,
        }
    )
    with contextlib.suppress(Exception):
        await redis.set(cache_key, payload, ex=get_settings().decision_cache_ttl_seconds)
