"""Identity pseudonyms in traces and logs (spec 007 FR-023, FR-023b).

contracts/pseudonymisation.md §5. The property that matters is the second one: a plain digest of
an agent name is recovered by brute force in seconds, because the name space is small and
enumerable. Only a keyed MAC — with a secret the telemetry backend does not hold — makes the
pseudonym non-reversible.
"""

from __future__ import annotations

import pytest

from app.observability.ids import PSEUDONYM_HEX_LEN, pseudonym, session_trace_id

KEY = b"0123456789abcdef0123456789abcdef"
OTHER_KEY = b"fedcba9876543210fedcba9876543210"


# -- shape ---------------------------------------------------------------------------------


def test_pseudonym_is_32_hex_chars() -> None:
    value = pseudonym("agent", "agent://billing-writer", KEY)
    assert len(value) == PSEUDONYM_HEX_LEN == 32
    assert all(c in "0123456789abcdef" for c in value)


# -- known answers: the function cannot change silently -------------------------------------


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("agent", "agent://billing-writer"),
        ("agent", "agent://router"),
        ("chain", "user:alice>agent://router>agent://billing-writer"),
    ],
)
def test_known_answer_vectors(kind: str, value: str) -> None:
    """Pinned against an independent HMAC computation, so a refactor that changes the
    construction (dropping the domain prefix, switching digest, changing truncation) fails."""
    import hashlib
    import hmac

    framed = f"{len(kind)}:{kind}:{value}"  # length-prefixed, so the encoding is injective
    expected = hmac.new(KEY, framed.encode(), hashlib.sha256).hexdigest()[:32]
    assert pseudonym(kind, value, KEY) == expected


# -- stability (FR-023b: "stable within a deployment") --------------------------------------


def test_stable_for_same_key_and_input() -> None:
    assert pseudonym("agent", "agent://router", KEY) == pseudonym("agent", "agent://router", KEY)


def test_stable_across_fresh_module_imports() -> None:
    """Two processes in one deployment must agree, so the function may hold no per-process
    state (no random salt, no instance counter)."""
    import importlib

    import app.observability.ids as ids

    first = ids.pseudonym("agent", "agent://router", KEY)
    importlib.reload(ids)
    assert ids.pseudonym("agent", "agent://router", KEY) == first


# -- non-reversibility (FR-023b) ------------------------------------------------------------


def test_different_keys_give_different_pseudonyms() -> None:
    """The whole point of keying: telemetry alone is not enough to recover the identity."""
    assert pseudonym("agent", "agent://router", KEY) != pseudonym(
        "agent", "agent://router", OTHER_KEY
    )


def test_pseudonym_does_not_contain_the_plaintext() -> None:
    assert "router" not in pseudonym("agent", "agent://router", KEY)


# -- domain separation ----------------------------------------------------------------------


def test_kinds_are_domain_separated() -> None:
    """`agent:agent://x` and `target:agent://x` must differ, so a target URI and an agent name
    that happen to share text do not collide into one pseudonym."""
    assert pseudonym("agent", "agent://x", KEY) != pseudonym("target", "agent://x", KEY)


def test_kind_prefix_cannot_be_forged_by_value() -> None:
    """A value containing the separator must not be able to impersonate another kind."""
    assert pseudonym("agent", "x:y", KEY) != pseudonym("agent:x", "y", KEY)


# -- collisions at the SC-007 scale ---------------------------------------------------------


def test_no_collisions_across_many_agents_and_sessions() -> None:
    agents = {pseudonym("agent", f"agent://a{i}", KEY) for i in range(5000)}
    assert len(agents) == 5000
    sessions = {session_trace_id(f"00000000-0000-4000-8000-{i:012d}", KEY) for i in range(5000)}
    assert len(sessions) == 5000


# -- an empty key is a programming error, not a silent unkeyed digest -----------------------


def test_empty_key_is_refused() -> None:
    """ObservabilityConfig refuses to enable without a key; this is the belt-and-braces check
    so no code path can reach an unkeyed digest."""
    with pytest.raises(ValueError, match="telemetry key"):
        pseudonym("agent", "agent://router", b"")
