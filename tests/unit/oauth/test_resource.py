"""The protected-resource pieces: metadata, challenges, the session cache (feature 011, M1)."""

from __future__ import annotations

import hashlib

import pytest

from agentic_auth.oauth.resource import (
    SessionCache,
    SessionEntry,
    challenge,
    metadata_paths,
    protected_resource_metadata,
)

RESOURCE = "https://mcp-proxy.example.com"
IDP = "https://idp.example.com"


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


# -- protected resource metadata (RFC 9728) -------------------------------------------------


def test_the_metadata_names_the_resource_its_idp_and_its_scopes() -> None:
    doc = protected_resource_metadata(
        RESOURCE, IDP, scopes=["kb.public", "account.read", "kb.public"]
    )
    assert doc == {
        "resource": RESOURCE,
        "authorization_servers": [IDP],
        "scopes_supported": ["account.read", "kb.public"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Agentic Auth protected resource",
    }


def test_the_metadata_is_served_at_the_root_and_the_path_suffixed_url() -> None:
    assert metadata_paths(RESOURCE) == ["/.well-known/oauth-protected-resource"]
    assert metadata_paths(f"{RESOURCE}/mcp") == [
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource",
    ]


# -- WWW-Authenticate (RFC 6750 §3, RFC 9728 §5.1) -----------------------------------------


def test_a_missing_token_challenge_points_at_the_metadata() -> None:
    header = challenge(RESOURCE, scopes=["kb.public", "account.read"])
    assert header == (
        'Bearer resource_metadata="https://mcp-proxy.example.com/.well-known/'
        'oauth-protected-resource", scope="account.read kb.public"'
    )


def test_an_invalid_token_challenge_names_the_check_and_still_points_at_metadata() -> None:
    header = challenge(RESOURCE, scopes=[], error="invalid_token", description="expired")
    assert header.startswith('Bearer error="invalid_token", error_description="expired"')
    assert 'resource_metadata="' in header
    assert "scope=" not in header  # nothing to advertise


def test_an_insufficient_scope_challenge_names_the_needed_scope() -> None:
    header = challenge(f"{RESOURCE}/mcp", scopes=["kb.internal"], error="insufficient_scope")
    assert 'error="insufficient_scope"' in header
    assert 'scope="kb.internal"' in header
    assert (
        'resource_metadata="https://mcp-proxy.example.com/.well-known/'
        'oauth-protected-resource/mcp"' in header
    )


@pytest.mark.parametrize("bad", ['x"y', "a\\b", "new\nline"])
def test_challenge_values_cannot_break_out_of_their_quotes(bad) -> None:
    with pytest.raises(ValueError):
        challenge(RESOURCE, scopes=[bad])


# -- the session cache ----------------------------------------------------------------------


def _entry(expires_at: float, session: str = "s1") -> SessionEntry:
    return SessionEntry(root_grant=f"grant-{session}", session_id=session, expires_at=expires_at)


def test_an_entry_is_found_by_the_tokens_hash_until_it_expires() -> None:
    clock = Clock()
    cache = SessionCache(max_entries=10, clock=clock)
    cache.put("token-a", _entry(clock.now + 60))

    assert cache.get("token-a").session_id == "s1"
    assert cache.get("token-b") is None
    assert all("token-a" not in key for key in cache.hashes())
    assert hashlib.sha256(b"token-a").hexdigest() in cache.hashes()

    clock.now += 61
    assert cache.get("token-a") is None
    assert len(cache) == 0


def test_the_least_recently_used_entry_is_evicted_at_capacity() -> None:
    clock = Clock()
    cache = SessionCache(max_entries=2, clock=clock)
    cache.put("a", _entry(clock.now + 60, "sa"))
    cache.put("b", _entry(clock.now + 60, "sb"))
    cache.get("a")  # a is now the most recent
    cache.put("c", _entry(clock.now + 60, "sc"))

    assert cache.get("b") is None
    assert cache.get("a").session_id == "sa"
    assert cache.get("c").session_id == "sc"


def test_an_already_expired_entry_is_not_stored() -> None:
    clock = Clock()
    cache = SessionCache(max_entries=2, clock=clock)
    cache.put("a", _entry(clock.now - 1))
    assert cache.get("a") is None and len(cache) == 0


def test_the_cache_needs_room_for_one_entry() -> None:
    with pytest.raises(ValueError):
        SessionCache(max_entries=0)
