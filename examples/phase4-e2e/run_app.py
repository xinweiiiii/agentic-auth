"""The control plane, as the least-privileged database role, with Phase 4 enabled."""

import os
import pathlib
import sys

BACKEND = pathlib.Path(__file__).resolve().parents[2]
WORK = pathlib.Path(os.environ.get("AA4_DIR", "/tmp/aa4"))  # keys, issuer key, generated files
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ["AGENTIC_AUTH_DATABASE_URL"] = (
    "postgresql+asyncpg://agentic_auth_app:app@localhost:5432/agentic_auth_e2e4"
)
os.environ["AGENTIC_AUTH_REDIS_URL"] = "redis://localhost:6379/4"
os.environ["AGENTIC_AUTH_ADMIN_TOKEN"] = "dev-admin-token"
os.environ["AGENTIC_AUTH_AUDIT_READ_TOKEN"] = "dev-audit-reader"
os.environ["AGENTIC_AUTH_ENROLL_TOKEN"] = "dev-enroller"
os.environ["AGENTIC_AUTH_ISSUER_PRIVATE_KEY"] = (WORK / "issuer-key.pem").read_text()
os.environ["AGENTIC_AUTH_PRINCIPAL_IDP_ISSUER"] = "http://127.0.0.1:9100"
os.environ["AGENTIC_AUTH_PRINCIPAL_IDP_JWKS_URL"] = "http://127.0.0.1:9100/.well-known/jwks.json"
os.environ["AGENTIC_AUTH_PRINCIPAL_IDP_AUDIENCE"] = "agentic-auth"
os.environ["AGENTIC_AUTH_REVOCATION_FRESHNESS_SECONDS"] = "6"
os.environ["AGENTIC_AUTH_IDENTITY_REQUIRED"] = "true"
import uvicorn

uvicorn.run("app.main:app", host="127.0.0.1", port=8199, log_level="warning")
