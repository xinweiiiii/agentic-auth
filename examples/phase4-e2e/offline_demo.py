import asyncio
import os
import pathlib
import signal
import subprocess
import sys
import time

BACKEND = pathlib.Path(__file__).resolve().parents[2]
WORK = pathlib.Path(os.environ.get("AA4_DIR", "/tmp/aa4"))  # keys, issuer key, generated files
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import httpx
from walk import client, to_support

TARGET = "mcp://accounts.internal/terminate_account"
PARAMS = {"account_id": "acc-7", "reason": "fraud"}


async def present(headers):
    async with httpx.AsyncClient() as http:
        r = await http.post(
            "http://127.0.0.1:9200/tools/terminate_account", headers=headers, json=PARAMS
        )
    return r.status_code, r.json().get("error", {}).get("details", {}).get("reason") or "admitted"


def control_plane_pid():
    return int(
        subprocess.run(
            ["lsof", "-tiTCP:8199", "-sTCP:LISTEN"], capture_output=True, text=True
        ).stdout.split()[0]
    )


async def main():
    support = client("support-agent")
    _, ctx_a = await to_support()
    _, ctx_b = await to_support()  # a second session: one privileged call taints its own context
    a = (
        await support.authorize(ctx_a, target=TARGET, data_class="account.write", params=PARAMS)
    ).headers()
    b = (
        await support.authorize(ctx_b, target=TARGET, data_class="account.write", params=PARAMS)
    ).headers()
    os.kill(control_plane_pid(), signal.SIGTERM)
    t0 = time.time()
    time.sleep(1)
    print(
        f"control plane KILLED. resource, {time.time() - t0:3.0f}s later:   ",
        await present(a),
        "  <- verified with no control plane",
    )
    await asyncio.sleep(8)
    print(
        f"resource, {time.time() - t0:3.0f}s later (window 6 s):   ",
        await present(b),
        "  <- cannot refresh, so it refuses everything",
    )


asyncio.run(main())
