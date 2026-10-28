"""PyJWT + Ed25519 implementation of :class:`TokenProfile`.

The verification order in :meth:`JwtTokenProfile.verify` is the one specified in
``contracts/hop-token.md``. Every step is mandatory and every failure is a rejection —
there is no partial acceptance, and no claim may be read before all steps pass.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from app.config import get_settings
from app.schemas.authorize import Taint
from app.services.tokens.act_chain import MalformedActChain, hop_of
from app.services.tokens.keys import ALGORITHM, IssuerKey, get_issuer_key
from app.services.tokens.profile import (
    TRANSACTION_TYP,
    TokenProfile,
    VerifiedToken,
    VerifiedTransaction,
)

LEEWAY_SECONDS = 60


class TokenVerificationError(Exception):
    """The presented token cannot be trusted. Always terminal — never retried, never
    downgraded to a partial acceptance."""


class JwtTokenProfile(TokenProfile):
    def __init__(
        self,
        key: IssuerKey | None = None,
        *,
        issuer: str | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        settings = get_settings()
        self._key = key or get_issuer_key()
        self._issuer = issuer or settings.issuer
        self._ttl = ttl_seconds or settings.hop_token_ttl_seconds

    # -- issuance ---------------------------------------------------------

    def _mint(
        self,
        claims: dict[str, Any],
        *,
        ttl_seconds: int | None = None,
        typ: str | None = None,
    ) -> str:
        now = datetime.now(UTC)
        payload = {
            "iss": self._issuer,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds or self._ttl)).timestamp()),
            "jti": str(uuid.uuid4()),
            **claims,
        }
        headers: dict[str, Any] = {"kid": self._key.kid}
        if typ is not None:
            headers["typ"] = typ
        return jwt.encode(payload, self._key.private_pem(), algorithm=ALGORITHM, headers=headers)

    def mint_root_grant(self, *, sub: str, scope: str, session_id: str, policy_version: int) -> str:
        # aud is the consented scope, not a concrete target: the root grant is the only
        # token that names a scope, and it is never presentable to a resource server.
        return self._mint(
            {
                "sub": sub,
                "aud": scope,
                "scope": scope,
                "resource": scope,
                "session_id": session_id,
                "policy_version": policy_version,
                "hop": 1,
            }
        )

    def mint_hop_token(
        self,
        *,
        sub: str,
        target: str,
        data_class: str,
        session_id: str,
        policy_version: int,
        hop: int,
        act: dict[str, Any] | None,
        action_id: str,
        taint: Taint | None = None,
    ) -> str:
        claims: dict[str, Any] = {
            "sub": sub,
            "aud": target,
            "resource": target,
            "scope": data_class,
            "session_id": session_id,
            "policy_version": policy_version,
            "hop": hop,
            "action_id": action_id,
        }
        if act is not None:
            claims["act"] = act
        if taint is not None:
            claims["taint"] = taint.value
        return self._mint(claims)

    # -- verification -----------------------------------------------------

    def verify(self, token: str, *, audience: str | None = None) -> VerifiedToken:
        # 1. Signature against the kid-named key, algorithm pinned. Never `none`, never
        #    inferred from the header.
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(f"malformed token header: {exc}") from exc
        if header.get("alg") != ALGORITHM:
            raise TokenVerificationError(
                f"unexpected alg {header.get('alg')!r}; only {ALGORITHM} is accepted"
            )
        # A transaction token (`typ: txn+jwt`) is signed by the same key and carries most of
        # the same claims; it must never pass as a hop token (security audit, Phase 4).
        if header.get("typ") not in (None, "JWT"):
            raise TokenVerificationError(
                f"unexpected typ {header.get('typ')!r}; a hop token has typ JWT"
            )
        if header.get("kid") != self._key.kid:
            raise TokenVerificationError(f"unknown kid {header.get('kid')!r}")

        try:
            # 2. exp/iat and 3. iss are enforced here; 4. aud when a target is given.
            claims = jwt.decode(
                token,
                self._key.public_pem(),
                algorithms=[ALGORITHM],
                issuer=self._issuer,
                audience=audience,
                leeway=LEEWAY_SECONDS,
                options={
                    "require": ["exp", "iat", "jti", "sub", "aud", "iss"],
                    "verify_aud": audience is not None,
                },
            )
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(str(exc)) from exc

        for claim in ("scope", "session_id", "policy_version", "hop"):
            if claim not in claims:
                raise TokenVerificationError(f"missing required claim {claim!r}")

        act = claims.get("act")
        if act is not None and not isinstance(act, dict):
            raise TokenVerificationError("act claim must be an object")

        # 5. hop and act depth must agree. A mismatch means a hand-assembled token.
        try:
            expected_hop = hop_of(act)
        except MalformedActChain as exc:
            raise TokenVerificationError(f"malformed act chain: {exc}") from exc
        if claims["hop"] != expected_hop:
            raise TokenVerificationError(
                f"hop claim {claims['hop']} disagrees with act depth (expected {expected_hop})"
            )

        aud = claims["aud"]
        if isinstance(aud, list):  # a hop token names exactly one target
            if len(aud) != 1:
                raise TokenVerificationError("hop token must name exactly one audience")
            aud = aud[0]

        # The audit link. Optional (root grants have none), but when present it must be an
        # action id — a malformed one would otherwise surface later as a broken chain.
        action_id = claims.get("action_id")
        if action_id is not None:
            if not isinstance(action_id, str):
                raise TokenVerificationError("action_id claim must be a UUID string")
            try:
                uuid.UUID(action_id)
            except ValueError as exc:
                raise TokenVerificationError("action_id claim must be a UUID string") from exc

        # Phase 4: a present taint must be one of the two classes; anything else is a
        # hand-assembled token.
        raw_taint = claims.get("taint")
        taint: Taint | None = None
        if raw_taint is not None:
            try:
                taint = Taint(raw_taint)
            except ValueError as exc:
                raise TokenVerificationError(f"unknown taint claim {raw_taint!r}") from exc

        # Step 6 (session live, policy version matching) belongs to the PDP and the
        # exchange service — they hold the session, this module does not.
        return VerifiedToken(
            raw=token,
            sub=claims["sub"],
            aud=aud,
            scope=claims["scope"],
            session_id=claims["session_id"],
            policy_version=claims["policy_version"],
            hop=claims["hop"],
            jti=claims["jti"],
            expires_at=datetime.fromtimestamp(claims["exp"], tz=UTC),
            act=act,
            action_id=action_id,
            taint=taint,
        )

    # -- transaction tokens (Phase 4) ------------------------------------------------

    def mint_transaction_token(
        self, *, hop: VerifiedToken, params_hash: str, binding: list[str] | None
    ) -> str:
        jti = str(uuid.uuid4())
        claims: dict[str, Any] = {
            "jti": jti,
            "txn": jti,
            "sub": hop.sub,
            "aud": hop.aud,
            "session_id": hop.session_id,
            "action_id": hop.action_id,
            "hop": hop.hop,
            "azd": {
                "target": hop.aud,
                "params_hash": params_hash,
                "hash_alg": "sha-256",
                "canon": "rfc8785",
                "binding": list(binding) if binding is not None else None,
            },
        }
        if hop.act is not None:
            claims["act"] = hop.act
        if hop.taint is not None:
            claims["taint"] = hop.taint.value
        return self._mint(
            claims,
            ttl_seconds=get_settings().transaction_token_ttl_seconds,
            typ=TRANSACTION_TYP,
        )

    def verify_transaction_token(self, token: str, *, audience: str) -> VerifiedTransaction:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(f"malformed token header: {exc}") from exc
        # `typ` first: a hop token presented as a transaction token (or the reverse) is
        # refused before any claim is read.
        if header.get("typ") != TRANSACTION_TYP:
            raise TokenVerificationError(
                f"expected typ {TRANSACTION_TYP!r}, got {header.get('typ')!r}"
            )
        if header.get("alg") != ALGORITHM:
            raise TokenVerificationError(f"unexpected alg {header.get('alg')!r}")
        if header.get("kid") != self._key.kid:
            raise TokenVerificationError(f"unknown kid {header.get('kid')!r}")
        try:
            claims = jwt.decode(
                token,
                self._key.public_pem(),
                algorithms=[ALGORITHM],
                issuer=self._issuer,
                audience=audience,
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "jti", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(str(exc)) from exc
        for claim in ("txn", "session_id", "action_id", "hop", "azd"):
            if claim not in claims:
                raise TokenVerificationError(f"missing required claim {claim!r}")
        if claims["txn"] != claims["jti"]:
            raise TokenVerificationError("txn must equal jti")
        azd = claims["azd"]
        if not isinstance(azd, dict) or not isinstance(azd.get("params_hash"), str):
            raise TokenVerificationError("azd claim is malformed")
        if azd.get("hash_alg") != "sha-256" or azd.get("canon") != "rfc8785":
            raise TokenVerificationError("unsupported binding algorithm")
        if azd.get("target") != claims["aud"]:
            raise TokenVerificationError("azd.target disagrees with aud")
        binding = azd.get("binding")
        if binding is not None and not (
            isinstance(binding, list) and all(isinstance(b, str) for b in binding)
        ):
            raise TokenVerificationError("azd.binding must be a list of pointers or null")
        act = claims.get("act")
        if act is not None and not isinstance(act, dict):
            raise TokenVerificationError("act claim must be an object")
        raw_taint = claims.get("taint")
        taint: Taint | None = None
        if raw_taint is not None:
            try:
                taint = Taint(raw_taint)
            except ValueError as exc:
                raise TokenVerificationError(f"unknown taint claim {raw_taint!r}") from exc
        return VerifiedTransaction(
            raw=token,
            jti=claims["jti"],
            sub=claims["sub"],
            aud=claims["aud"],
            session_id=claims["session_id"],
            action_id=str(claims["action_id"]),
            hop=int(claims["hop"]),
            act=act,
            taint=taint,
            params_hash=azd["params_hash"],
            binding=list(binding) if binding is not None else None,
            expires_at=datetime.fromtimestamp(claims["exp"], tz=UTC),
        )

    # -- proof of possession at the exchange (Phase 4) -------------------------------

    def verify_actor_token(
        self, token: str, *, anchor_jwks: dict[str, Any], subject_token: str, expected_agent: str
    ) -> str:
        import base64
        import hashlib

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(f"malformed actor_token header: {exc}") from exc
        if header.get("alg") != ALGORITHM:
            raise TokenVerificationError(f"actor_token alg {header.get('alg')!r} is not accepted")
        entry = next(
            (k for k in anchor_jwks.get("keys", []) if k.get("kid") == header.get("kid")), None
        )
        if entry is None:
            raise TokenVerificationError(
                f"actor_token kid {header.get('kid')!r} is not in the pinned trust anchor"
            )
        try:
            key = jwt.PyJWK(dict(entry), algorithm=ALGORITHM).key
            claims = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                audience=self._issuer,
                leeway=5,
                options={"require": ["exp", "iat", "jti", "sub", "aud", "st_hash"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(f"actor_token rejected: {exc}") from exc
        expected_sub = f"agent://{expected_agent}"
        if claims.get("sub") != expected_sub or claims.get("iss") != expected_sub:
            raise TokenVerificationError("actor_token was issued for a different agent")
        if int(claims["exp"]) - int(claims["iat"]) > 60:
            raise TokenVerificationError("actor_token lifetime exceeds 60s")
        digest = hashlib.sha256(subject_token.encode()).digest()
        if claims["st_hash"] != base64.urlsafe_b64encode(digest).rstrip(b"=").decode():
            raise TokenVerificationError("actor_token does not hash this subject token")
        return expected_agent

    def jwks(self) -> dict[str, Any]:
        # This profile's OWN key. A profile built around an injected key (tests, rotation
        # rehearsals) must publish the key it signs with, not the process-global one.
        return {"keys": [self._key.public_jwk()]}
