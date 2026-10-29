"""Single-use guard on the *decision* an exchange spends.

A hop token is bound to one target (``aud``), one data class (``scope``) and one depth
(``hop``). Phase 2 added a fourth binding, one *use per token*. Phase 4 moves it to one
*use per recorded allow decision* (``spent:{action_id}``): an agent may exchange the same
delegation token for as many calls as the PDP records allows for, and each recorded allow
still mints exactly one token.
The theft case the per-token guard partly covered is closed properly by proof of
possession at the exchange.

If the guard cannot be written the exchange fails closed. The other bindings and a
60-second lifetime still hold, but a guarantee that quietly degrades is worse than one
that refuses, because nothing downstream can tell the difference.
"""

from __future__ import annotations

from redis.asyncio import Redis


class ReplayGuardUnavailable(RuntimeError):
    """The single-use guard could not be applied. Always fatal to the exchange."""


class TokenAlreadyExchanged(RuntimeError):
    """This subject token was already spent."""


def spent_key(action_id: object) -> str:
    """One exchange per recorded allow decision."""
    return f"spent:{action_id}"


async def consume(
    redis: Redis | None, key: str, *, ttl_seconds: int, subject_jti: str | None = None
) -> None:
    """Claim ``key`` exactly once, or raise.

    ``subject_jti`` only shapes the error text, which the sidecar and SDK surface to the
    agent: the token is fine, but this decision has already been spent.
    """
    if redis is None:
        raise ReplayGuardUnavailable("no replay store configured")
    try:
        # SET NX is the atomic claim: the first caller wins, everyone after sees None.
        claimed = await redis.set(key, "1", ex=max(ttl_seconds, 1), nx=True)
    except Exception as exc:
        raise ReplayGuardUnavailable(f"replay store unreachable: {exc}") from exc
    if not claimed:
        who = subject_jti or key
        raise TokenAlreadyExchanged(
            f"subject token {who} has already been exchanged for this decision"
        )
