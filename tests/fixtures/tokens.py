"""Signed-token builders, including the malformed variants the verifier must reject."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from agentic_auth.services.tokens.act_chain import nest
from agentic_auth.services.tokens.jwt_profile import JwtTokenProfile
from agentic_auth.services.tokens.keys import ALGORITHM, IssuerKey, load_or_generate

USER = "user:alice"


def issuer_key() -> IssuerKey:
    return load_or_generate()


def profile(key: IssuerKey | None = None, *, ttl_seconds: int = 60) -> JwtTokenProfile:
    return JwtTokenProfile(key or issuer_key(), issuer="agentic-auth", ttl_seconds=ttl_seconds)


def act_for(*agents: str) -> dict[str, Any] | None:
    """Build a chain from delegation order: ``act_for("a", "b")`` -> b acting for a."""
    act = None
    for agent in agents:
        act = nest(act, agent if agent.startswith("agent://") else f"agent://{agent}")
    return act


def root_grant(
    p: JwtTokenProfile, *, scope: str = "orchestrator", session_id: str = "s1", version: int = 1
) -> str:
    return p.mint_root_grant(sub=USER, scope=scope, session_id=session_id, policy_version=version)


def hop_token(
    p: JwtTokenProfile,
    *,
    target: str,
    data_class: str = "kb.public",
    session_id: str = "s1",
    version: int = 1,
    delegates: tuple[str, ...] = (),
    action_id: str | None = None,
    taint: Any = None,
) -> str:
    """A token for the hop *after* ``delegates`` — hop = len(delegates) + 1."""
    act = act_for(*delegates)
    return p.mint_hop_token(
        sub=USER,
        target=target,
        data_class=data_class,
        session_id=session_id,
        policy_version=version,
        hop=len(delegates) + 1,
        act=act,
        action_id=action_id or str(uuid.uuid4()),
        taint=taint,
    )


# -- tokens that must be rejected -------------------------------------------


def raw_claims(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=="))


def tampered(token: str, **overrides: Any) -> str:
    """Rewrite claims and keep the original signature — must fail verification."""
    head, payload, sig = token.split(".")
    claims = {**raw_claims(token), **overrides}
    swapped = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{head}.{swapped}.{sig}"


def forged(key: IssuerKey, claims: dict[str, Any]) -> str:
    """Correctly signed by the WRONG key."""
    now = datetime.now(UTC)
    body = {
        "iss": "agentic-auth",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=60)).timestamp()),
        "jti": "forged",
        **claims,
    }
    return jwt.encode(body, key.private_pem(), algorithm=ALGORITHM, headers={"kid": key.kid})


def expired(key: IssuerKey, *, target: str, delegates: tuple[str, ...] = ()) -> str:
    return hop_token(profile(key, ttl_seconds=-3600), target=target, delegates=delegates)


def understating_hop(p: JwtTokenProfile, *, target: str, delegates: tuple[str, ...]) -> str:
    """Deep act chain, small `hop` claim — the depth under-reporting attack, minted directly."""
    return p.mint_hop_token(
        sub=USER,
        target=target,
        data_class="kb.public",
        session_id="s1",
        policy_version=1,
        hop=1,
        act=act_for(*delegates),
        action_id=str(uuid.uuid4()),
    )
