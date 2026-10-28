"""``/.well-known/jwks.json`` — issuer public keys.

Unauthenticated by design: any resource server must be able to verify a hop token
**offline**, with no call back to the control plane on the hot path. Only public key
material is served here.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.services.tokens import keys

router = APIRouter(tags=["ops"])


@router.get("/.well-known/jwks.json")
async def get_jwks() -> dict[str, Any]:
    return keys.jwks()
