"""``AgentKey``: the agent's Ed25519 key and the three small tokens it signs (US4, T057)."""

from __future__ import annotations

import jwt
import pytest

from app.sdk.identity import AgentKey, sha256_b64url, thumbprint_of_jwk


def test_round_trips_through_pem(tmp_path) -> None:
    key = AgentKey.generate(kid="k1")
    path = tmp_path / "agent.pem"
    key.save(path)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    loaded = AgentKey.load(path, kid="k1")
    assert loaded.jwk() == key.jwk()
    assert AgentKey.load(path.read_text(), kid="k1").thumbprint() == key.thumbprint()


def test_jwk_is_okp_ed25519_public_only() -> None:
    jwk = AgentKey.generate().jwk()
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and jwk["alg"] == "EdDSA"
    assert "d" not in jwk


def test_thumbprint_is_of_the_key_not_the_kid() -> None:
    key = AgentKey.generate(kid="alpha")
    same_key_other_kid = AgentKey.load(key._private_pem().decode(), kid="beta")
    assert key.thumbprint() == same_key_other_kid.thumbprint() == thumbprint_of_jwk(key.jwk())
    assert key.kid != same_key_other_kid.kid


def test_repr_hides_the_key() -> None:
    key = AgentKey.generate(kid="k1")
    text = repr(key)
    assert "k1" in text and "PRIVATE" not in text and "-----" not in text


def _verify(token: str, key: AgentKey, **kwargs):
    return jwt.decode(token, jwt.PyJWK(key.jwk()).key, algorithms=["EdDSA"], **kwargs)


def test_challenge_response_names_agent_nonce_and_audience() -> None:
    key = AgentKey.generate()
    claims = _verify(key.sign_challenge("support-agent", "n0nce"), key, audience="agentic-auth")
    assert claims["iss"] == claims["sub"] == "agent://support-agent"
    assert claims["nonce"] == "n0nce"
    assert claims["exp"] - claims["iat"] <= 120


def test_actor_token_binds_the_exact_subject_token() -> None:
    key = AgentKey.generate()
    subject = "aaa.bbb.ccc"
    claims = _verify(key.actor_token("support-agent", subject), key, audience="agentic-auth")
    assert claims["st_hash"] == sha256_b64url(subject)
    assert claims["st_hash"] != sha256_b64url(subject + "x")
    assert claims["exp"] - claims["iat"] <= 60 and claims["jti"]


def test_identity_assertion_binds_the_exact_grant_and_the_target() -> None:
    key = AgentKey.generate()
    grant = "ggg.hhh.iii"
    target = "mcp://accounts.internal/terminate_account"
    claims = _verify(key.identity_assertion("support-agent", grant, target), key, audience=target)
    assert claims["grant_hash"] == sha256_b64url(grant)
    assert claims["sub"] == "agent://support-agent"


def test_a_token_signed_by_another_key_does_not_verify() -> None:
    key, other = AgentKey.generate(), AgentKey.generate()
    token = key.actor_token("support-agent", "st")
    with pytest.raises(jwt.PyJWTError):
        _verify(token, other, audience="agentic-auth")


def test_non_ed25519_pem_is_refused() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    with pytest.raises(ValueError, match="Ed25519"):
        AgentKey.load(rsa_pem)


def test_identity_document_shape() -> None:
    key = AgentKey.generate(kid="k1")
    doc = key.identity_document(
        "support-agent", claims={"runtime": "k8s"}, principal_assertion="a.b.c"
    )
    assert doc["sub"] == "agent://support-agent"
    assert doc["jwks"]["keys"] == [key.jwk()]
    assert doc["claims"] == {"runtime": "k8s"} and doc["principal_assertion"] == "a.b.c"
    assert "principal_assertion" not in key.identity_document("support-agent")
