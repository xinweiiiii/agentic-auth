import asyncio
import os
import pathlib
import subprocess
import sys
import time

BACKEND = pathlib.Path(__file__).resolve().parents[2]
WORK = pathlib.Path(os.environ.get("AA4_DIR", "/tmp/aa4"))  # keys, issuer key, generated files
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import httpx
from walk import client

from app.sdk import PolicyDenied

TARGET = "mcp://accounts.internal/read_balance"
CP = "http://127.0.0.1:8199"


async def call(headers):
    async with httpx.AsyncClient() as http:
        r = await http.get("http://127.0.0.1:9200/tools/read_balance", headers=headers)
    return r.status_code, r.json().get("error", {}).get("details", {}).get("reason") or "admitted"


async def main():
    # read_balance is balance-agent's tool: walk to balance-agent, revoke it
    root = client("bank-assistant")
    session = await root.consent(scope="bank-assistant", user_sub="user:alice")
    _, ctx = await root.hop(
        session.context(), target="agent://balance-agent", data_class="account.read"
    )
    bal = client("balance-agent")
    grant = await bal.authorize(ctx, target=TARGET, data_class="account.read")
    print("before revocation, at the resource:      ", await call(grant.headers()))

    grant2 = await bal.authorize(ctx, target=TARGET, data_class="account.read")
    ids = {
        a["name"]: a["id"]
        for a in httpx.get(
            f"{CP}/v1/agents", headers={"Authorization": "Bearer dev-admin-token"}
        ).json()["data"]
    }
    out = subprocess.run(
        [
            "agentic-auth",
            "identity",
            "revoke",
            ids["balance-agent"],
            "--base-url",
            CP,
            "--reason",
            "compromised",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "AGENTIC_AUTH_ADMIN_TOKEN": "dev-admin-token"},
    )
    print("revoke ->", out.stdout.replace("\n", " "))
    t0 = time.time()

    try:
        await bal.authorize(ctx, target=TARGET, data_class="account.read")
    except PolicyDenied as denied:
        print(
            "control plane, next hop:                 ",
            denied.reason.value,
            f"(recoverable={denied.recoverable})",
        )
    try:
        await root.hop(session.context(), target="agent://balance-agent", data_class="account.read")
    except PolicyDenied as denied:
        print("delegating to the revoked agent again:   ", denied.reason.value)

    print(
        f"resource, {time.time() - t0:4.1f}s after revoke:        ",
        await call(grant2.headers()),
        "  (its view may not have refreshed yet)",
    )
    while True:
        status = await call(grant2.headers())
        if status[1] != "admitted":
            break
        await asyncio.sleep(0.5)
    print(
        f"resource, {time.time() - t0:4.1f}s after revoke:        ",
        status,
        "  (freshness window is 6 s)",
    )


asyncio.run(main())
