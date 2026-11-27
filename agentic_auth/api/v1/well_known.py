"""``/.well-known/oauth-authorization-server`` — the control plane's RFC 8414 metadata
(feature 011, M3).

Unauthenticated and cacheable, like the JWKS. 404 unless ``as_metadata_enabled``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from agentic_auth.api.deps import SessionDep
from agentic_auth.config import get_settings
from agentic_auth.errors import NotFoundError
from agentic_auth.oauth.metadata import authorization_server_metadata
from agentic_auth.services.catalog_service import pinned_data_classes

router = APIRouter(tags=["ops"])


@router.get("/.well-known/oauth-authorization-server")
async def get_authorization_server_metadata(db: SessionDep) -> Any:
    settings = get_settings()
    if not settings.as_metadata_enabled:
        raise NotFoundError("authorization server metadata is not enabled on this deployment")
    document = authorization_server_metadata(
        settings.issuer,
        scopes=await pinned_data_classes(db),
        transaction_tokens=settings.transaction_tokens_enabled,
    )
    return JSONResponse(document, headers={"cache-control": "public, max-age=300"})
