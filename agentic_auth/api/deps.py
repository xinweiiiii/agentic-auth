"""FastAPI dependencies: admin auth, DB session, pagination."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, Header, Query
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.config import get_settings
from agentic_auth.db import get_session
from agentic_auth.errors import UnauthorizedError
from agentic_auth.schemas.common import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, PaginationParams
from agentic_auth.services.tokens.profile import VerifiedToken


async def require_admin(authorization: Annotated[str | None, Header()] = None) -> None:
    expected = get_settings().admin_token
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("missing or malformed admin bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    # Constant-time: `!=` stops at the first differing byte, which leaks how much of the
    # token was guessed correctly to anyone who can time the response.
    if not hmac.compare_digest(token.encode(), expected.encode()):
        raise UnauthorizedError("invalid admin bearer token")


async def require_audit_reader(authorization: Annotated[str | None, Header()] = None) -> None:
    """Audit data is readable with the dedicated reader token or the admin token.

    An auditor should never need the credential that can register manifests or record
    consent, so ``AGENTIC_AUTH_AUDIT_READ_TOKEN`` exists; the admin token keeps working. An
    empty reader setting disables that token rather than accepting an empty bearer.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("missing or malformed audit reader bearer token")
    presented = authorization.removeprefix("Bearer ").strip().encode()
    settings = get_settings()
    accepted = [t.encode() for t in (settings.audit_read_token, settings.admin_token) if t]
    # Compare against every accepted token, not just until the first match, so timing does
    # not reveal which one was presented.
    matches = [hmac.compare_digest(presented, token) for token in accepted]
    if not presented or not any(matches):
        raise UnauthorizedError("invalid audit reader bearer token")


async def require_enroller(authorization: Annotated[str | None, Header()] = None) -> None:
    """Enrollment is begun and completed with the dedicated enroller token or the admin
    token. An empty enroller setting disables that token, never accepts an empty bearer."""
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("missing or malformed enroller bearer token")
    presented = authorization.removeprefix("Bearer ").strip().encode()
    settings = get_settings()
    accepted = [t.encode() for t in (settings.enroll_token, settings.admin_token) if t]
    # Compare against every accepted token, not just until the first match, so timing does
    # not reveal which one was presented.
    matches = [hmac.compare_digest(presented, token) for token in accepted]
    if not presented or not any(matches):
        raise UnauthorizedError("invalid enroller bearer token")


async def require_identity_reader(authorization: Annotated[str | None, Header()] = None) -> None:
    """Identity material and the revocation list are readable by verifiers and operators:
    the audit reader token or the admin token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("missing or malformed identity reader bearer token")
    presented = authorization.removeprefix("Bearer ").strip().encode()
    settings = get_settings()
    accepted = [t.encode() for t in (settings.audit_read_token, settings.admin_token) if t]
    matches = [hmac.compare_digest(presented, token) for token in accepted]
    if not presented or not any(matches):
        raise UnauthorizedError("invalid identity reader bearer token")


def pagination_params(
    limit: int = Query(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    cursor: str | None = Query(default=None),
) -> PaginationParams:
    return PaginationParams(limit=limit, cursor=cursor)


async def presented_token(
    authorization: Annotated[str | None, Header()] = None,
) -> VerifiedToken:
    """Verify the caller's current hop token before a single claim is read.

    Returns a :class:`VerifiedToken`, never a raw string, so downstream code has no way
    to reach an unverified claim. Every failure is a rejection — there is no path here
    that yields a partially trusted token.
    """
    from agentic_auth.api.service_deps import get_token_profile
    from agentic_auth.services.tokens.jwt_profile import TokenVerificationError

    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("missing or malformed bearer token")
    raw = authorization.removeprefix("Bearer ").strip()
    try:
        # Audience is checked against the concrete target by the caller of this
        # dependency, which knows what is being called; here we establish authenticity.
        return get_token_profile().verify(raw)
    except TokenVerificationError as exc:
        raise UnauthorizedError(f"token rejected: {exc}") from exc


SessionDep = Annotated[AsyncSession, Depends(get_session)]
PresentedTokenDep = Annotated[VerifiedToken, Depends(presented_token)]


async def require_consenting_human(
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    """Who may APPROVE a step-up widening: the human, not the agent (research.md R6).

    The whole threat model assumes the agent may be under an attacker's influence. An
    agent that could approve its own widening would turn ``SCOPE_NOT_CONSENTED`` from a
    control into a formality — the injected instruction would simply answer the prompt it
    triggered. So the session's own root grant is deliberately NOT sufficient here, even
    though it is sufficient to *raise* the challenge.

    Where the deployment has configured a human identity provider, this is an ID token
    from it and the subject is its ``sub``. Where it has not, the admin bearer stands in
    and the subject is recorded as ``admin`` — a deployment with no independent human
    channel, which its documentation must say plainly rather than imply otherwise.

    Returns the subject to record as the approver.
    """
    settings = get_settings()
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("missing or malformed credential")
    token = authorization.removeprefix("Bearer ").strip()

    if settings.principal_idp_issuer:
        from agentic_auth.services.principal import PrincipalBinder

        try:
            return await PrincipalBinder().verify_human(token)
        except Exception as exc:  # noqa: BLE001 - any failure here is a refusal
            raise UnauthorizedError(f"human credential did not verify: {exc}") from exc

    if hmac.compare_digest(token.encode(), settings.admin_token.encode()):
        return "admin"
    raise UnauthorizedError(
        "step-up approval requires the consenting human's credential; the session's own "
        "grant is not sufficient"
    )


AdminDep = Depends(require_admin)
AuditReaderDep = Depends(require_audit_reader)
EnrollerDep = Depends(require_enroller)
IdentityReaderDep = Depends(require_identity_reader)
ConsentingHumanDep = Annotated[str, Depends(require_consenting_human)]
PaginationDep = Annotated[PaginationParams, Depends(pagination_params)]
