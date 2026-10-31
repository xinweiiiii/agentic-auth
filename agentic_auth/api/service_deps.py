"""Dependency wiring for the manifest service (overridden in tests)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from redis.asyncio import Redis

from agentic_auth import runtime
from agentic_auth.config import get_settings
from agentic_auth.redis import get_redis
from agentic_auth.services.anchors import AnchorCache
from agentic_auth.services.audit import AuditService
from agentic_auth.services.chain_query import ChainQueryService
from agentic_auth.services.discovery import DiscoveryClient
from agentic_auth.services.enrollment import EnrollmentService
from agentic_auth.services.manifest_service import ManifestService
from agentic_auth.services.principal import PrincipalBinder
from agentic_auth.services.revocation import RevocationService
from agentic_auth.services.sessions import SessionService
from agentic_auth.services.tokens.exchange import TokenExchangeService
from agentic_auth.services.tokens.jwt_profile import JwtTokenProfile
from agentic_auth.services.tokens.profile import TokenProfile
from agentic_auth.services.transactions import TransactionService


async def get_manifest_service() -> AsyncIterator[ManifestService]:
    settings = get_settings()
    current = runtime.override()
    # An embedded instance discovers capabilities through its own in-process transport.
    discovery = (
        DiscoveryClient(client=current.http)
        if current is not None
        else DiscoveryClient(timeout=settings.discovery_timeout_seconds)
    )
    try:
        yield ManifestService(discovery=discovery)
    finally:
        await discovery.aclose()


def get_redis_dep() -> Redis:
    return get_redis()


def get_token_profile() -> TokenProfile:
    """One profile per control plane: the process's, or an embedded instance's own."""
    current = runtime.override()
    if current is None:
        return _process_token_profile()
    if current._token_profile is None:
        current._token_profile = JwtTokenProfile()
    profile: TokenProfile = current._token_profile
    return profile


@lru_cache
def _process_token_profile() -> TokenProfile:
    """One issuer key per process — regenerating per request would invalidate every
    token already in flight."""
    return JwtTokenProfile()


def get_session_service() -> SessionService:
    return SessionService(tokens=get_token_profile())


def get_token_exchange_service() -> TokenExchangeService:
    return TokenExchangeService(tokens=get_token_profile(), sessions=get_session_service())


def get_transaction_service() -> TransactionService:
    return TransactionService(tokens=get_token_profile(), sessions=get_session_service())


def get_anchor_cache(redis: Redis = Depends(get_redis_dep)) -> AnchorCache:  # noqa: B008
    return AnchorCache(redis)


def get_enrollment_service(
    anchors: AnchorCache = Depends(get_anchor_cache),  # noqa: B008
) -> EnrollmentService:
    return EnrollmentService(binder=PrincipalBinder(), anchors=anchors)


def get_revocation_service(
    anchors: AnchorCache = Depends(get_anchor_cache),  # noqa: B008
) -> RevocationService:
    return RevocationService(anchors)


def get_audit_service() -> AuditService:
    return AuditService()


def get_chain_query_service() -> ChainQueryService:
    return ChainQueryService()


ManifestServiceDep = Annotated[ManifestService, Depends(get_manifest_service)]
RedisDep = Annotated[Redis, Depends(get_redis_dep)]
TokenProfileDep = Annotated[TokenProfile, Depends(get_token_profile)]
SessionServiceDep = Annotated[SessionService, Depends(get_session_service)]
TokenExchangeServiceDep = Annotated[TokenExchangeService, Depends(get_token_exchange_service)]
AuditServiceDep = Annotated[AuditService, Depends(get_audit_service)]
TransactionServiceDep = Annotated[TransactionService, Depends(get_transaction_service)]
AnchorCacheDep = Annotated[AnchorCache, Depends(get_anchor_cache)]
EnrollmentServiceDep = Annotated[EnrollmentService, Depends(get_enrollment_service)]
RevocationServiceDep = Annotated[RevocationService, Depends(get_revocation_service)]
ChainQueryServiceDep = Annotated[ChainQueryService, Depends(get_chain_query_service)]
