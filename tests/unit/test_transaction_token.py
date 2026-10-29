"""Minting and verifying transaction tokens through the profile."""

from __future__ import annotations

from datetime import UTC, datetime

import jwt
import pytest

from app.schemas.authorize import Taint
from app.services.tokens.act_chain import nest
from app.services.tokens.jwt_profile import JwtTokenProfile, TokenVerificationError
from app.services.tokens.keys import load_or_generate
from app.services.tokens.profile import TRANSACTION_TYP

USER = "user:alice"
TARGET = "mcp://accounts.internal/terminate_account"
ACTION_ID = "7c1e0000-0000-4000-8000-000000000001"
PARAMS_HASH = "K3sQqEXAMPLEhashEXAMPLEhashEXAMPLEhashEXAMPLE"


@pytest.fixture(scope="module")
def profile() -> JwtTokenProfile:
    return JwtTokenProfile(load_or_generate(), issuer="agentic-auth", ttl_seconds=60)


@pytest.fixture
def hop(profile: JwtTokenProfile):
    raw = profile.mint_hop_token(
        sub=USER,
        target=TARGET,
        data_class="account.write",
        session_id="s1",
        policy_version=3,
        hop=3,
        act=nest(nest(None, "agent://balance-agent"), "agent://support-agent"),
        action_id=ACTION_ID,
        taint=Taint.TRUSTED_INTERNAL,
    )
    return profile.verify(raw, audience=TARGET)


def test_round_trip_copies_the_hop_token_facts(profile, hop) -> None:
    raw = profile.mint_transaction_token(hop=hop, params_hash=PARAMS_HASH, binding=["/account_id"])
    assert jwt.get_unverified_header(raw)["typ"] == TRANSACTION_TYP

    v = profile.verify_transaction_token(raw, audience=TARGET)
    assert (v.sub, v.aud, v.session_id, v.action_id, v.hop) == (USER, TARGET, "s1", ACTION_ID, 3)
    assert v.act == hop.act
    assert v.taint is Taint.TRUSTED_INTERNAL
    assert v.params_hash == PARAMS_HASH
    assert v.binding == ["/account_id"]
    assert v.jti and v.expires_at > datetime.now(UTC)


def test_lifetime_is_the_transaction_ttl_not_the_hop_ttl(profile, hop, flags) -> None:
    flags(transaction_token_ttl_seconds=17)
    raw = profile.mint_transaction_token(hop=hop, params_hash=PARAMS_HASH, binding=None)
    claims = jwt.decode(raw, options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 17
    assert claims["txn"] == claims["jti"]
    assert claims["azd"] == {
        "target": TARGET,
        "params_hash": PARAMS_HASH,
        "hash_alg": "sha-256",
        "canon": "rfc8785",
        "binding": None,
    }


def test_a_hop_token_is_refused_where_a_transaction_token_is_expected(profile, hop) -> None:
    with pytest.raises(TokenVerificationError, match="typ"):
        profile.verify_transaction_token(hop.raw, audience=TARGET)


def test_a_transaction_token_is_refused_where_a_hop_token_is_expected(profile, hop) -> None:
    """The reverse confusion is refused on `typ`, before any claim is read — not merely
    because some hop-token claim happens to be missing."""
    raw = profile.mint_transaction_token(hop=hop, params_hash=PARAMS_HASH, binding=None)
    with pytest.raises(TokenVerificationError, match="typ"):
        profile.verify(raw, audience=TARGET)


def test_wrong_audience_is_refused(profile, hop) -> None:
    raw = profile.mint_transaction_token(hop=hop, params_hash=PARAMS_HASH, binding=None)
    with pytest.raises(TokenVerificationError):
        profile.verify_transaction_token(raw, audience="mcp://accounts.internal/read_balance")


def test_expired_is_refused(hop) -> None:
    expired = JwtTokenProfile(load_or_generate(), issuer="agentic-auth", ttl_seconds=60)
    from app.config import get_settings

    settings = get_settings()
    previous = settings.transaction_token_ttl_seconds
    settings.transaction_token_ttl_seconds = -3600
    try:
        raw = expired.mint_transaction_token(hop=hop, params_hash=PARAMS_HASH, binding=None)
    finally:
        settings.transaction_token_ttl_seconds = previous
    with pytest.raises(TokenVerificationError):
        expired.verify_transaction_token(raw, audience=TARGET)


def test_forged_by_another_key_is_refused(profile, hop) -> None:
    forger = JwtTokenProfile(load_or_generate(), issuer="agentic-auth", ttl_seconds=60)
    raw = forger.mint_transaction_token(hop=hop, params_hash=PARAMS_HASH, binding=None)
    with pytest.raises(TokenVerificationError):
        profile.verify_transaction_token(raw, audience=TARGET)


def test_unsupported_binding_algorithm_is_refused(profile, hop) -> None:
    raw = profile.mint_transaction_token(hop=hop, params_hash=PARAMS_HASH, binding=None)
    claims = jwt.decode(raw, options={"verify_signature": False})
    claims["azd"]["canon"] = "my-own-thing"
    tampered = profile._mint(
        {k: v for k, v in claims.items() if k not in ("iss", "iat", "exp")},
        typ=TRANSACTION_TYP,
    )
    with pytest.raises(TokenVerificationError, match="unsupported"):
        profile.verify_transaction_token(tampered, audience=TARGET)
