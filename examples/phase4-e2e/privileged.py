"""A privileged call, presented to the resource four ways with the SAME call-bound authority."""

import asyncio
import os
import pathlib
import sys

BACKEND = pathlib.Path(__file__).resolve().parents[2]
WORK = pathlib.Path(os.environ.get("AA4_DIR", "/tmp/aa4"))  # keys, issuer key, generated files
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import httpx
from walk import client, to_support

TARGET = "mcp://accounts.internal/terminate_account"
PARAMS = {"account_id": "acc-42", "reason": "fraud"}
RESOURCE = "http://127.0.0.1:9200/tools/terminate_account"


async def post(headers, body):
    async with httpx.AsyncClient() as http:
        r = await http.post(RESOURCE, headers=headers, json=body)
    detail = r.json().get("error", {}).get("details", {}).get("reason") or "admitted"
    return r.status_code, detail


async def main():
    _, ctx = await to_support()
    grant = await client("support-agent").authorize(
        ctx, target=TARGET, data_class="account.write", params=PARAMS
    )
    h = grant.headers()
    print("headers presented:", sorted(h))
    print(
        "hop token alone (no Txn-Token, no identity):",
        await post({"Authorization": h["Authorization"]}, PARAMS),
    )
    print(
        "no Txn-Token:                                ",
        await post({k: v for k, v in h.items() if k != "Txn-Token"}, PARAMS),
    )
    print(
        "account_id changed to acc-43:                ",
        await post(h, {**PARAMS, "account_id": "acc-43"}),
    )
    print("the call it was minted for:                  ", await post(h, PARAMS))
    print("the SAME token again (replay):               ", await post(h, PARAMS))


asyncio.run(main())
