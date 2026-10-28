# A protected tool server: it admits a call only with a grant AND the calling agent's identity
# (and a transaction token for the privileged tool), verified OFFLINE against pinned keys.
import asyncio
import os
import pathlib
import sys

BACKEND = pathlib.Path(__file__).resolve().parents[2]
WORK = pathlib.Path(os.environ.get("AA4_DIR", "/tmp/aa4"))  # keys, issuer key, generated files
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import uvicorn
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.verify import HttpAnchors, HttpJwks, InMemoryReplay, Verifier
from tests.fixtures.resource.server import build_resource

CP = "http://127.0.0.1:8199"
verifier = Verifier(
    issuer_jwks=HttpJwks(f"{CP}/.well-known/jwks.json"),
    anchors=HttpAnchors(
        base_url=CP,
        token="dev-audit-reader",
        agents=["bank-assistant", "balance-agent", "support-agent"],
        freshness_seconds=6,
    ),
    replay=InMemoryReplay(),
    identity_required=True,
    freshness_seconds=6,
)
app, recorder = build_resource(verifier)


async def state(_):
    return JSONResponse({"executed": recorder.executed, "reasons": recorder.reasons()})


app.router.routes.append(Route("/_state", state))


async def main():
    await verifier.bootstrap()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=9200, log_level="warning"))
    await server.serve()
    await verifier.close()


asyncio.run(main())
