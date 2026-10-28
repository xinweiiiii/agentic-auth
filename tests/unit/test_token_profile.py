"""Minting and verifying hop tokens (T022).

The verification order under test is the one in ``contracts/hop-token.md``. Every case
here is a rejection that must happen *before* any claim is trusted.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.services.tokens.act_chain import nest
from app.services.tokens.jwt_profile import ALGORITHM, JwtTokenProfile, TokenVerificationError
from app.services.tokens.keys import load_or_generate

USER = "user:alice"
TARGET = "mcp://kb.internal/search"
ACTION_ID = "7c1e0000-0000-4000-8000-000000000001"


@pytest.fixture(scope="module")
def profile() -> JwtTokenProfile:
    return JwtTokenProfile(load_or_generate(), issuer="agentic-auth", ttl_seconds=60)


@pytest.fixture(scope="module")
def other_profile() -> JwtTokenProfile:
    """A different issuer key — stands in for a forger."""
    return JwtTokenProfile(load_or_generate(), issuer="agentic-auth", ttl_seconds=60)


def _hop_token(profile: JwtTokenProfile, *, hop: int = 2, act=None, target: str = TARGET) -> str:
    return profile.mint_hop_token(
        sub=USER,
        target=target,
        data_class="kb.read",
        session_id="s1",
        policy_version=42,
        hop=hop,
        act=act if act is not None else nest(None, "agent://orchestrator"),
        action_id=ACTION_ID,
    )


# -- round trip --------------------------------------------------------------


def test_root_grant_round_trips(profile: JwtTokenProfile) -> None:
    raw = profile.mint_root_grant(
        sub=USER, scope="orchestrator", session_id="s1", policy_version=42
    )
    v = profile.verify(raw, audience="orchestrator")
    assert (v.sub, v.hop, v.act, v.scope) == (USER, 1, None, "orchestrator")
    assert v.actor == USER and v.act_chain == [USER]


def test_hop_token_round_trips(profile: JwtTokenProfile) -> None:
    v = profile.verify(_hop_token(profile), audience=TARGET)
    assert v.sub == USER  # the human never changes
    assert v.aud == TARGET
    assert v.scope == "kb.read"
    assert v.hop == 2
    assert v.act_chain == [USER, "agent://orchestrator"]
    assert v.expires_at > datetime.now(UTC)


def test_hop_token_names_the_decision_that_authorized_it(profile: JwtTokenProfile) -> None:
    """The next hop's audit row links to its parent through this claim (Phase 3)."""
    assert profile.verify(_hop_token(profile), audience=TARGET).action_id == ACTION_ID


def test_root_grant_names_no_decision(profile: JwtTokenProfile) -> None:
    raw = profile.mint_root_grant(sub=USER, scope="orchestrator", session_id="s1", policy_version=1)
    assert profile.verify(raw).action_id is None


@pytest.mark.parametrize("bad", ["not-a-uuid", 42])
def test_a_malformed_action_id_is_rejected(profile: JwtTokenProfile, bad) -> None:
    now = datetime.now(UTC)
    raw = jwt.encode(
        {
            "iss": "agentic-auth",
            "sub": USER,
            "aud": TARGET,
            "scope": "kb.read",
            "session_id": "s1",
            "policy_version": 42,
            "hop": 1,
            "action_id": bad,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=60)).timestamp()),
            "jti": "j1",
        },
        profile._key.private_pem(),
        algorithm=ALGORITHM,
        headers={"kid": profile._key.kid},
    )
    with pytest.raises(TokenVerificationError, match="action_id"):
        profile.verify(raw, audience=TARGET)


def test_header_carries_kid(profile: JwtTokenProfile) -> None:
    header = jwt.get_unverified_header(_hop_token(profile))
    assert header["alg"] == ALGORITHM
    assert header["kid"] == profile._key.kid


# -- rejections --------------------------------------------------------------


def test_signature_from_another_key_is_rejected(
    profile: JwtTokenProfile, other_profile: JwtTokenProfile
) -> None:
    forged = _hop_token(other_profile)
    with pytest.raises(TokenVerificationError):
        profile.verify(forged, audience=TARGET)


def test_tampered_payload_is_rejected(profile: JwtTokenProfile) -> None:
    head, payload, sig = _hop_token(profile).split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["scope"] = "accounts.write"  # widen it
    swapped = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    with pytest.raises(TokenVerificationError):
        profile.verify(f"{head}.{swapped}.{sig}", audience=TARGET)


def test_alg_none_is_rejected(profile: JwtTokenProfile) -> None:
    unsigned = jwt.encode({"sub": USER}, key="", algorithm="none")
    with pytest.raises(TokenVerificationError, match="unexpected alg"):
        profile.verify(unsigned, audience=TARGET)


def test_unknown_kid_is_rejected(profile: JwtTokenProfile) -> None:
    raw = jwt.encode(
        {"sub": USER, "aud": TARGET, "iss": "agentic-auth"},
        profile._key.private_pem(),
        algorithm=ALGORITHM,
        headers={"kid": "not-our-key"},
    )
    with pytest.raises(TokenVerificationError, match="unknown kid"):
        profile.verify(raw, audience=TARGET)


def test_expired_token_is_rejected(profile: JwtTokenProfile) -> None:
    expired = JwtTokenProfile(profile._key, issuer="agentic-auth", ttl_seconds=-3600)
    with pytest.raises(TokenVerificationError):
        profile.verify(_hop_token(expired), audience=TARGET)


def test_wrong_audience_is_rejected(profile: JwtTokenProfile) -> None:
    """This is what makes a hop token non-transferable."""
    with pytest.raises(TokenVerificationError):
        profile.verify(_hop_token(profile), audience="mcp://accounts.internal/read")


def test_wrong_issuer_is_rejected(profile: JwtTokenProfile) -> None:
    impostor = JwtTokenProfile(profile._key, issuer="someone-else", ttl_seconds=60)
    with pytest.raises(TokenVerificationError):
        profile.verify(_hop_token(impostor), audience=TARGET)


def test_hop_claim_disagreeing_with_act_depth_is_rejected(profile: JwtTokenProfile) -> None:
    """A hand-assembled token that under-reports its depth. SC-010."""
    deep = nest(nest(nest(None, "agent://a"), "agent://b"), "agent://c")
    lying = _hop_token(profile, hop=2, act=deep)  # act depth 3 -> hop should be 4
    with pytest.raises(TokenVerificationError, match="disagrees with act depth"):
        profile.verify(lying, audience=TARGET)


def test_malformed_act_chain_is_rejected(profile: JwtTokenProfile) -> None:
    raw = jwt.encode(
        {
            "iss": "agentic-auth",
            "sub": USER,
            "aud": TARGET,
            "scope": "kb.read",
            "session_id": "s1",
            "policy_version": 42,
            "hop": 2,
            "act": {"nope": "agent://a"},
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(seconds=60)).timestamp()),
            "jti": "j1",
        },
        profile._key.private_pem(),
        algorithm=ALGORITHM,
        headers={"kid": profile._key.kid},
    )
    with pytest.raises(TokenVerificationError, match="act chain"):
        profile.verify(raw, audience=TARGET)


@pytest.mark.parametrize("missing", ["scope", "session_id", "policy_version", "hop"])
def test_missing_required_runtime_claim_is_rejected(profile: JwtTokenProfile, missing: str) -> None:
    claims = {
        "iss": "agentic-auth",
        "sub": USER,
        "aud": TARGET,
        "scope": "kb.read",
        "session_id": "s1",
        "policy_version": 42,
        "hop": 1,
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(seconds=60)).timestamp()),
        "jti": "j1",
    }
    del claims[missing]
    raw = jwt.encode(
        claims, profile._key.private_pem(), algorithm=ALGORITHM, headers={"kid": profile._key.kid}
    )
    with pytest.raises(TokenVerificationError, match=missing):
        profile.verify(raw, audience=TARGET)


def test_garbage_is_rejected(profile: JwtTokenProfile) -> None:
    with pytest.raises(TokenVerificationError):
        profile.verify("not-a-token", audience=TARGET)


# -- jwks --------------------------------------------------------------------


def test_jwks_publishes_a_verifiable_public_key(profile: JwtTokenProfile) -> None:
    jwk = profile._key.public_jwk()
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and jwk["use"] == "sig"
    assert jwk["alg"] == ALGORITHM
    assert jwk["kid"] == profile._key.kid
    assert "d" not in jwk  # never leak the private half


# -- Phase 4: the taint claim -----------------------------------------------------


def test_hop_token_carries_the_effective_taint(profile: JwtTokenProfile) -> None:
    from app.schemas.authorize import Taint

    raw = profile.mint_hop_token(
        sub=USER,
        target=TARGET,
        data_class="kb.read",
        session_id="s1",
        policy_version=42,
        hop=2,
        act=nest(None, "agent://orchestrator"),
        action_id=ACTION_ID,
        taint=Taint.UNTRUSTED_EXTERNAL,
    )
    assert profile.verify(raw, audience=TARGET).taint is Taint.UNTRUSTED_EXTERNAL


def test_taint_is_absent_by_default_and_reads_as_none(profile: JwtTokenProfile) -> None:
    v = profile.verify(_hop_token(profile), audience=TARGET)
    assert v.taint is None
    root = profile.mint_root_grant(
        sub=USER, scope="orchestrator", session_id="s1", policy_version=1
    )
    assert profile.verify(root).taint is None


def test_an_unknown_taint_value_is_rejected(profile: JwtTokenProfile) -> None:
    """A hand-assembled token with a made-up class must not verify."""
    from tests.fixtures.tokens import issuer_key

    key = issuer_key()
    p = JwtTokenProfile(key, issuer="agentic-auth", ttl_seconds=60)
    raw = p._mint(
        {
            "sub": USER,
            "aud": TARGET,
            "resource": TARGET,
            "scope": "kb.read",
            "session_id": "s1",
            "policy_version": 1,
            "hop": 1,
            "taint": "mostly_fine",
        }
    )
    with pytest.raises(TokenVerificationError, match="taint"):
        p.verify(raw, audience=TARGET)
