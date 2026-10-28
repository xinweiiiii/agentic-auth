"""The decision cache (T063).

One property matters above the rest: a cached decision can never leak across policy
versions, and no cache path can turn a deny into an allow.
"""

from __future__ import annotations

import pytest

from app.boundary.guarantee import Guarantee
from app.schemas.authorize import AuthorizeRequest, DenyReason
from app.services import decision_cache
from app.services.pdp import Decision

CHAIN = ["user:alice", "agent://root"]

ALLOW = Decision(outcome="allow", hop=2)
DENY = Decision(
    outcome="deny", hop=2, reason=DenyReason.EDGE_NOT_IN_DAG, message="not a declared edge"
)


def _req(**overrides) -> AuthorizeRequest:
    return AuthorizeRequest(
        **{
            "session_id": "s1",
            "caller": "agent://a",
            "target": "mcp://kb.internal/search",
            "data_class": "kb.public",
            "guarantee": Guarantee.FULL,
            **overrides,
        }
    )


# -- key construction --------------------------------------------------------


def test_the_policy_version_is_in_the_key() -> None:
    """Structural invalidation: there is no event to forget. The version stays in the
    plaintext prefix so it is greppable in a running Redis."""
    k42 = decision_cache.key(_req(), policy_version=42, hop=2, act_chain=CHAIN)
    k43 = decision_cache.key(_req(), policy_version=43, hop=2, act_chain=CHAIN)
    assert k42 != k43
    assert k42.startswith("pdp:42:")
    assert k43.startswith("pdp:43:")


def test_the_delegation_chain_is_part_of_the_key() -> None:
    """`decide()` reads the chain: it builds the path and looks up that path's effective
    budget. Two routes to the same agent at the same depth are different decisions, so
    they must not share a cache entry."""
    via_a = decision_cache.key(
        _req(), policy_version=1, hop=3, act_chain=["user:alice", "agent://root", "agent://a"]
    )
    via_b = decision_cache.key(
        _req(), policy_version=1, hop=3, act_chain=["user:alice", "agent://root", "agent://b"]
    )
    assert via_a != via_b


def test_chain_order_matters() -> None:
    same_agents_different_route = decision_cache.key(
        _req(), policy_version=1, hop=3, act_chain=["user:alice", "agent://b", "agent://a"]
    )
    original = decision_cache.key(
        _req(), policy_version=1, hop=3, act_chain=["user:alice", "agent://a", "agent://b"]
    )
    assert same_agents_different_route != original


def test_colons_in_values_cannot_collide() -> None:
    """Targets are URIs full of colons, so a delimiter-joined key is ambiguous:
    (target='mcp://kb', data_class='x:read') and (target='mcp://kb:x', data_class='read')
    would otherwise produce the same string."""
    a = decision_cache.key(
        _req(target="mcp://kb", data_class="x:read"), policy_version=1, hop=2, act_chain=CHAIN
    )
    b = decision_cache.key(
        _req(target="mcp://kb:x", data_class="read"), policy_version=1, hop=2, act_chain=CHAIN
    )
    assert a != b


@pytest.mark.parametrize(
    "overrides",
    [
        {"session_id": "other"},
        {"caller": "agent://b"},
        {"target": "mcp://kb.internal/other"},
        {"data_class": "kb.internal"},
    ],
)
def test_every_decision_input_participates_in_the_key(overrides) -> None:
    base = decision_cache.key(_req(), policy_version=1, hop=2, act_chain=CHAIN)
    assert decision_cache.key(_req(**overrides), policy_version=1, hop=2, act_chain=CHAIN) != base


def test_hop_participates_in_the_key() -> None:
    """The same call at a different depth is a different decision."""
    assert decision_cache.key(
        _req(), policy_version=1, hop=2, act_chain=CHAIN
    ) != decision_cache.key(_req(), policy_version=1, hop=3, act_chain=CHAIN)


# -- round trip --------------------------------------------------------------


async def test_a_decision_round_trips(redis_client) -> None:
    k = decision_cache.key(_req(), policy_version=1, hop=2, act_chain=CHAIN)
    await decision_cache.put(redis_client, k, DENY)

    cached = await decision_cache.get(redis_client, k)
    assert cached == DENY
    assert cached.reason is DenyReason.EDGE_NOT_IN_DAG
    assert cached.recoverable is False


async def test_a_version_pinned_session_cannot_read_another_versions_entry(
    redis_client,
) -> None:
    """FR-036, as a structural fact rather than an invalidation routine."""
    await decision_cache.put(
        redis_client, decision_cache.key(_req(), policy_version=42, hop=2, act_chain=CHAIN), ALLOW
    )
    assert (
        await decision_cache.get(
            redis_client, decision_cache.key(_req(), policy_version=43, hop=2, act_chain=CHAIN)
        )
        is None
    )


async def test_a_miss_returns_none(redis_client) -> None:
    assert await decision_cache.get(redis_client, "pdp:1:nothing:here:at:all:1") is None


async def test_a_malformed_entry_is_treated_as_a_miss(redis_client) -> None:
    """A corrupt entry must not become an allow, or a decision at all."""
    k = decision_cache.key(_req(), policy_version=1, hop=2, act_chain=CHAIN)
    await redis_client.set(k, "not json")
    assert await decision_cache.get(redis_client, k) is None

    await redis_client.set(k, '{"outcome": "allow"}')  # missing `hop`
    assert await decision_cache.get(redis_client, k) is None


# -- outages -----------------------------------------------------------------


class _DeadRedis:
    async def get(self, *_a, **_k):
        raise ConnectionError("redis is down")

    async def set(self, *_a, **_k):
        raise ConnectionError("redis is down")


async def test_a_read_outage_is_a_miss_not_a_decision() -> None:
    assert await decision_cache.get(_DeadRedis(), "pdp:1:a:b:c:d:1") is None


async def test_a_write_outage_does_not_raise() -> None:
    """A cache that cannot be written is a slower system, not a broken one."""
    await decision_cache.put(_DeadRedis(), "pdp:1:a:b:c:d:1", ALLOW)


async def test_no_redis_configured_is_a_miss() -> None:
    assert await decision_cache.get(None, "pdp:1:a:b:c:d:1") is None
    await decision_cache.put(None, "pdp:1:a:b:c:d:1", ALLOW)


# -- the cache is not a decision maker ---------------------------------------


async def test_the_cache_never_manufactures_an_allow(redis_client) -> None:
    """Every path that is not an exact hit returns None, so the caller must evaluate."""
    k = decision_cache.key(_req(), policy_version=1, hop=2, act_chain=CHAIN)
    await decision_cache.put(redis_client, k, DENY)

    for bad_key in (
        decision_cache.key(_req(), policy_version=2, hop=2, act_chain=CHAIN),
        decision_cache.key(_req(caller="agent://other"), policy_version=1, hop=2, act_chain=CHAIN),
        decision_cache.key(_req(), policy_version=1, hop=3, act_chain=CHAIN),
    ):
        assert await decision_cache.get(redis_client, bad_key) is None

    assert (await decision_cache.get(redis_client, k)).outcome == "deny"
