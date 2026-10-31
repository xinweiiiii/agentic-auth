"""Export the live OpenAPI schema for the docs site's interactive API explorer.

Run from the repository root: ``python scripts/export_openapi.py``

Generated from the actual FastAPI app (``agentic_auth.main.create_app().openapi()``), never
hand-written — so the docs site's "try it" panel can only ever describe endpoints that
really exist, and so the docs site's Reference section can never describe an endpoint
that has not shipped.

The documentation site pulls this file and regenerates its interactive API pages from it.
Re-run this script after adding, removing, or changing a route.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentic_auth.main import create_app

OUT = Path(__file__).resolve().parents[1] / "openapi" / "agentic-auth.json"

# The FastAPI app declares its own auth checks per-route (AdminDep / AuditReaderDep)
# rather than through FastAPI's Security() system, so app.openapi() has no
# securitySchemes of its own. Adding one here lets the docs site's interactive
# explorer show a single "Authorize" control instead of requiring a header to be
# retyped on every request — see the how-to guides for which routes actually need it.
BEARER_SECURITY_SCHEME = {
    "type": "http",
    "scheme": "bearer",
    "description": (
        "The admin bearer token (AGENTIC_AUTH_ADMIN_TOKEN in a local dev setup) for "
        "most routes, or the audit-reader token for /v1/audit/*. "
        "GET /.well-known/jwks.json needs no token at all."
    ),
}


def build() -> dict:
    app = create_app()
    schema = app.openapi()
    schema.setdefault("servers", []).append(
        {
            "url": "http://localhost:8000",
            "description": "Local control plane — see the Get Started tutorial",
        }
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = (
        BEARER_SECURITY_SCHEME
    )
    schema["security"] = [{"bearerAuth": []}]
    schema["info"]["x-generated-from"] = "agentic_auth.main.create_app().openapi()"
    return schema


def main() -> None:
    schema = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(schema['paths'])} paths)")


if __name__ == "__main__":
    main()
