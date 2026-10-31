"""Minting call-bound authority — ``POST /v1/token/transaction``.

One transaction token per recorded allow decision. The row that records it is committed
**before** the token is minted, so a token that exists always has a row and a second mint
for the same decision is an ``IntegrityError`` on ``UNIQUE (action_id)``, never a second
token.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from redis.asyncio import Redis
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.config import get_settings
from agentic_auth.errors import (
    PolicyDenied,
    TransactionAlreadyMinted,
    TransactionValidationError,
    UnauthorizedError,
)
from agentic_auth.repositories import audit_decisions as audit_repo
from agentic_auth.repositories import transaction_tokens as txn_repo
from agentic_auth.schemas.authorize import DenyReason, Taint
from agentic_auth.schemas.transaction import TransactionMinted
from agentic_auth.services import policy_loader
from agentic_auth.services.metrics import get_metrics
from agentic_auth.services.sessions import SessionService
from agentic_auth.services.tokens.profile import TokenProfile, VerifiedToken
from agentic_auth.verify.canonical import CanonicalizationError, binding_hash, canonical_json

logger = logging.getLogger(__name__)


def _normalized(session_id: str) -> str:
    try:
        return str(uuid.UUID(session_id))
    except (ValueError, TypeError, AttributeError):
        return session_id


class TransactionService:
    def __init__(self, tokens: TokenProfile, sessions: SessionService) -> None:
        self._tokens = tokens
        self._sessions = sessions

    async def mint(
        self,
        db: AsyncSession,
        redis: Redis | None,
        token: VerifiedToken,
        params: dict[str, object],
    ) -> TransactionMinted:
        settings = get_settings()
        metrics = get_metrics()

        # The bearer must be a token minted FOR this tool call: a tool-call token names a
        # resource, never an agent, and cannot be exchanged further.
        if token.holder is not None:
            metrics.transaction_mints.labels(result="invalid_token").inc()
            raise UnauthorizedError(
                "transaction tokens are minted against the hop token issued for the tool call, "
                "not a delegation token or root grant"
            )
        if token.action_id is None:
            metrics.transaction_mints.labels(result="invalid_token").inc()
            raise UnauthorizedError("hop token names no recorded decision")

        action_id = uuid.UUID(token.action_id)
        row = await audit_repo.get_committed_allow(db, action_id)
        if (
            row is None
            or row.outcome != "allow"
            or str(row.session_id) != _normalized(token.session_id)
            or row.target != token.aud
        ):
            metrics.transaction_mints.labels(result="invalid_token").inc()
            raise UnauthorizedError(
                f"recorded decision {action_id} does not authorize a transaction for this token"
            )

        session = await self._sessions.get(db, redis, token.session_id)
        policy = await policy_loader.load(db, redis, session.scope, session.policy_version)
        caller = row.acting_agent
        if caller is None or not policy.is_privileged(caller, token.aud):
            metrics.transaction_mints.labels(result="not_privileged").inc()
            raise TransactionValidationError(
                "target is not privileged",
                [
                    {
                        "loc": ["target"],
                        "msg": f"{token.aud} is not privileged in policy version "
                        f"{session.policy_version}",
                    }
                ],
            )

        # Defence in depth behind decide(): a tainted context never mints call-bound
        # authority for a protected target, whatever the row says. Off with the taint
        # enforcement flag, like decide() itself (recorded, never refused).
        if (
            settings.taint_enforcement_enabled
            and token.taint is Taint.UNTRUSTED_EXTERNAL
            and policy.is_protected(caller, token.aud, row.data_class)
        ):
            metrics.transaction_mints.labels(result="tainted").inc()
            raise PolicyDenied(
                "tainted context cannot mint call-bound authority",
                {
                    "reason": DenyReason.TAINTED_INTO_PRIVILEGED.value,
                    "recoverable": False,
                    "target": token.aud,
                },
            )

        try:
            if len(canonical_json(params)) > settings.max_privileged_body_bytes:
                metrics.transaction_mints.labels(result="too_large").inc()
                raise TransactionValidationError(
                    "params exceed the binding size cap",
                    [{"loc": ["params"], "msg": f"> {settings.max_privileged_body_bytes} bytes"}],
                )
            binding = policy.binding_params(caller, token.aud)
            params_hash = binding_hash(token.aud, params, binding)
        except CanonicalizationError as exc:
            metrics.transaction_mints.labels(result="too_large").inc()
            raise TransactionValidationError(
                "params cannot be canonicalized", [{"loc": ["params"], "msg": str(exc)}]
            ) from exc

        issued_at = datetime.now(UTC)
        expires_at = issued_at + timedelta(seconds=settings.transaction_token_ttl_seconds)
        jti = str(uuid.uuid4())
        try:
            await txn_repo.append(
                db,
                jti=jti,
                action_id=action_id,
                session_id=row.session_id,
                target=token.aud,
                params_hash=params_hash,
                binding=binding,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            # Committed BEFORE minting: a token that exists always has a row.
            await db.commit()
        except IntegrityError as exc:
            await db.rollback()
            metrics.transaction_mints.labels(result="already_minted").inc()
            raise TransactionAlreadyMinted(
                f"decision {action_id} already has a transaction token",
                {"action_id": str(action_id)},
            ) from exc

        raw = self._tokens.mint_transaction_token(
            hop=token, params_hash=params_hash, binding=binding
        )
        # The row's jti must be the token's: re-read is not possible without decoding, so the
        # profile is asked to mint with the jti we recorded.
        metrics.transaction_mints.labels(result="minted").inc()
        return TransactionMinted(
            transaction_token=raw,
            expires_in=settings.transaction_token_ttl_seconds,
            params_hash=params_hash,
            binding=binding,
            action_id=action_id,
        )
