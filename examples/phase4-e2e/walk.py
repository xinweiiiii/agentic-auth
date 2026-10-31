"""Consent, then walk bank-assistant -> balance-agent -> support-agent, each hop signed with
that agent's own enrolled key. Prints support-agent's hop token (and the session id)."""

import asyncio
import json
import os
import pathlib
import sys

BACKEND = pathlib.Path(__file__).resolve().parents[2]
WORK = pathlib.Path(os.environ.get("AA4_DIR", "/tmp/aa4"))  # keys, issuer key, generated files
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from agentic_auth.sdk import AgenticAuthClient, AgentKey

CP = "http://127.0.0.1:8199"


def client(agent):
    return AgenticAuthClient(
        CP,
        admin_token="dev-admin-token",
        identity_key=AgentKey.load(WORK / "keys" / f"{agent}.pem"),
        agent_name=agent,
    )


async def to_support():
    root = client("bank-assistant")
    session = await root.consent(scope="bank-assistant", user_sub="user:alice")
    _, ctx = await root.hop(
        session.context(), target="agent://balance-agent", data_class="account.read"
    )
    _, ctx = await client("balance-agent").hop(
        ctx, target="agent://support-agent", data_class="kb.internal"
    )
    return session, ctx


if __name__ == "__main__":
    session, ctx = asyncio.run(to_support())
    print(json.dumps({"session_id": session.session_id, "support_token": ctx.token}))
