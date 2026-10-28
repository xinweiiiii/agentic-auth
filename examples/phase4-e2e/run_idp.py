# A stand-in for the organization's human IdP: serves a JWKS and mints ID tokens that name an agent.
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

from tests.fixtures.idp.server import FakeIdp, build_idp

idp = FakeIdp(issuer="http://127.0.0.1:9100")
app, _ = build_idp(idp)


async def mint(request):
    agent = request.query_params["agent"]
    return JSONResponse({"id_token": idp.mint_id_token(sub="alice", agent=f"agent://{agent}")})


app.router.routes.append(Route("/mint", mint))
uvicorn.run(app, host="127.0.0.1", port=9100, log_level="warning")
