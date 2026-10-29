"""The nested ``act`` claim and the depth derived from it.

This module is the single place delegation depth comes from, so these tests are the
guard: an agent that under-reports its depth must gain no additional hops.
"""

from __future__ import annotations

import pytest

from app.services.tokens.act_chain import (
    MAX_DEPTH,
    MalformedActChain,
    current_actor,
    depth,
    hop_of,
    nest,
    walk,
)

USER = "user:alice"


def _chain(*agents: str) -> dict | None:
    act = None
    for a in agents:
        act = nest(act, a)
    return act


def test_nesting_is_inside_out() -> None:
    """RFC 8693 §4.1: outermost is the current actor, innermost the first delegate."""
    act = _chain("agent://a", "agent://b", "agent://c")
    assert act == {
        "sub": "agent://c",
        "act": {"sub": "agent://b", "act": {"sub": "agent://a"}},
    }


@pytest.mark.parametrize(
    ("agents", "expected_depth", "expected_hop"),
    [
        ((), 0, 1),  # root grant — the human only
        (("agent://a",), 1, 2),
        (("agent://a", "agent://b"), 2, 3),
        (("agent://a", "agent://b", "agent://c"), 3, 4),
    ],
)
def test_depth_and_hop_for_each_chain_length(
    agents: tuple[str, ...], expected_depth: int, expected_hop: int
) -> None:
    act = _chain(*agents)
    assert depth(act) == expected_depth
    assert hop_of(act) == expected_hop


def test_walk_returns_delegation_order_rooted_at_the_human() -> None:
    act = _chain("agent://a", "agent://b", "agent://c")
    assert walk(act, USER) == [USER, "agent://a", "agent://b", "agent://c"]


def test_walk_of_root_grant_is_just_the_human() -> None:
    assert walk(None, USER) == [USER]


def test_current_actor_is_the_outermost_link() -> None:
    assert current_actor(_chain("agent://a", "agent://b"), USER) == "agent://b"
    assert current_actor(None, USER) == USER


def test_sub_never_moves_down_the_chain() -> None:
    """The consenting human stays `sub` at every depth — agents only ever appear in act."""
    act = _chain("agent://a", "agent://b", "agent://c")
    chain = walk(act, USER)
    assert chain[0] == USER
    assert USER not in chain[1:]


# -- malformed chains are rejected, never silently shortened -----------------


def test_link_without_sub_is_rejected() -> None:
    with pytest.raises(MalformedActChain, match="sub"):
        depth({"act": {"sub": "agent://a"}})


def test_link_with_empty_sub_is_rejected() -> None:
    with pytest.raises(MalformedActChain, match="sub"):
        depth({"sub": ""})


def test_non_object_link_is_rejected() -> None:
    with pytest.raises(MalformedActChain, match="expected object"):
        depth({"sub": "agent://a", "act": "agent://b"})


def test_unexpected_keys_are_rejected() -> None:
    """A forger padding the chain with extra keys does not get a pass."""
    with pytest.raises(MalformedActChain, match="unexpected keys"):
        depth({"sub": "agent://a", "hop": 1})


def test_absurdly_deep_chain_is_rejected_rather_than_walked() -> None:
    act: dict = {"sub": "agent://a"}
    for _ in range(40):
        act = {"sub": "agent://x", "act": act}
    with pytest.raises(MalformedActChain, match="deeper than"):
        depth(act)


def test_nest_rejects_an_empty_actor() -> None:
    with pytest.raises(MalformedActChain):
        nest(None, "")


def test_a_truncated_chain_reports_its_real_shorter_depth() -> None:
    """Stripping links lowers the depth — which is exactly why the chain must be signed.

    Integrity comes from the signature (see test_token_profile.py), not from this module.
    What is pinned here is that depth always reflects the chain actually presented.
    """
    full = _chain("agent://a", "agent://b", "agent://c")
    truncated = full["act"]
    assert depth(full) == 3
    assert depth(truncated) == 2


def test_a_chain_exactly_at_the_depth_cap_is_accepted() -> None:
    """The cap is a ceiling, not a fence one short of it."""
    act: dict = {"sub": "agent://a"}
    for _ in range(MAX_DEPTH - 1):
        act = {"sub": "agent://x", "act": act}
    assert depth(act) == MAX_DEPTH


def test_one_link_past_the_cap_is_rejected() -> None:
    act: dict = {"sub": "agent://a"}
    for _ in range(MAX_DEPTH):
        act = {"sub": "agent://x", "act": act}
    with pytest.raises(MalformedActChain, match="deeper than"):
        depth(act)


def test_walk_validates_every_link_not_just_the_first() -> None:
    """A forger who keeps the outer link well-formed gains nothing."""
    corrupt = {"sub": "agent://b", "act": {"no_sub": "agent://a"}}
    with pytest.raises(MalformedActChain):
        walk(corrupt, USER)


def test_current_actor_validates_the_chain_it_reads() -> None:
    with pytest.raises(MalformedActChain):
        current_actor({"sub": "agent://b", "act": "not-an-object"}, USER)
