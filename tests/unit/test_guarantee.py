"""The guarantee vocabulary.

Small module, but it carries FR-016 through FR-021, so the tests are about the properties
rather than the plumbing: every level is ordered, the ordering is the one the contract
states, and nothing defaults.
"""

from __future__ import annotations

import itertools

import pytest

from app.boundary.guarantee import (
    STRENGTH,
    Guarantee,
    is_degrade,
    strongest,
    weakest,
)


def test_exactly_four_levels() -> None:
    """FR-016. A fifth level is a contract change, not an implementation detail."""
    assert {g.value for g in Guarantee} == {"full", "connector", "network", "consent_only"}


def test_every_level_has_a_strength() -> None:
    """A member without a strength would sort as weakest by accident. For a field whose
    job is honesty, silently understating is still wrong."""
    assert set(Guarantee) == set(STRENGTH)


def test_ordering_matches_the_contract() -> None:
    """contracts/guarantee-level.md §1: full > connector > network > consent_only."""
    assert (
        STRENGTH[Guarantee.FULL]
        > STRENGTH[Guarantee.CONNECTOR]
        > STRENGTH[Guarantee.NETWORK]
        > STRENGTH[Guarantee.CONSENT_ONLY]
    )


@pytest.mark.parametrize("a,b", list(itertools.product(Guarantee, repeat=2)))
def test_strongest_over_every_pair(a: Guarantee, b: Guarantee) -> None:
    result = strongest(a, b)
    assert result in (a, b)
    assert STRENGTH[result] == max(STRENGTH[a], STRENGTH[b])


@pytest.mark.parametrize("a,b", list(itertools.product(Guarantee, repeat=2)))
def test_weakest_over_every_pair(a: Guarantee, b: Guarantee) -> None:
    result = weakest(a, b)
    assert result in (a, b)
    assert STRENGTH[result] == min(STRENGTH[a], STRENGTH[b])


def test_strongest_of_one_is_itself() -> None:
    for level in Guarantee:
        assert strongest(level) is level


def test_the_worked_example_from_the_contract() -> None:
    """A connector proxy in front of a tool that also has a resource guard: the recorded
    level is `full`, because the guard genuinely did verify identity, grant and binding
    (FR-020)."""
    assert strongest(Guarantee.CONNECTOR, Guarantee.FULL) is Guarantee.FULL


def test_strongest_of_nothing_raises() -> None:
    """A decision with no guarantee level must not be emitted (FR-018). Returning a
    default here would be exactly the silent claim the field exists to prevent."""
    with pytest.raises(ValueError, match="at least one level"):
        strongest()


def test_weakest_of_nothing_raises() -> None:
    with pytest.raises(ValueError, match="at least one level"):
        weakest()


def test_an_unknown_string_raises_rather_than_defaulting() -> None:
    with pytest.raises(ValueError):
        Guarantee("mostly")


def test_degrade_is_directional() -> None:
    assert is_degrade(Guarantee.FULL, Guarantee.CONSENT_ONLY) is True
    assert is_degrade(Guarantee.FULL, Guarantee.CONNECTOR) is True
    assert is_degrade(Guarantee.CONSENT_ONLY, Guarantee.FULL) is False


def test_no_change_is_not_a_degrade() -> None:
    """A deployment that starts weak is a configuration, reported on every response from
    the first one — not an event."""
    for level in Guarantee:
        assert is_degrade(level, level) is False


def test_levels_are_plain_strings() -> None:
    """StrEnum, so a level serializes into JSON and into a text column without a
    conversion step that could be forgotten on one path."""
    assert Guarantee.CONSENT_ONLY == "consent_only"
    assert f"{Guarantee.FULL}" == "full"
