"""The whole control plane in-process: consent, three narrowing hops, a refusal, the chain."""

import asyncio

from agentic_auth.embedded import EmbeddedControlPlane, PolicyDenied


async def main() -> None:
    async with EmbeddedControlPlane.open(
        "examples/drift-fixture/manifests", override_reason="quickstart"
    ) as cp:
        client = cp.client()
        session = await client.consent(scope="bank-assistant", user_sub="user:alice")
        grant, ctx = await client.hop(
            session.context(), target="agent://balance-agent", data_class="account.read"
        )
        grant, ctx = await client.hop(ctx, target="agent://support-agent", data_class="kb.internal")
        grant, ctx = await client.hop(
            ctx, target="mcp://kb.internal/search", data_class="kb.internal"
        )
        print("allow", grant.hop, " → ".join(ctx.act_chain))
        try:
            await client.authorize(
                ctx, target="mcp://accounts.internal/terminate_account", data_class="account.write"
            )
        except PolicyDenied as denied:
            print("deny", denied.reason.value)
        chain = await client.audit.chain(grant.action_id)
        print(
            "chain",
            " → ".join(
                [chain["root_consent"]["user_sub"], *(h["acting_agent"] for h in chain["chain"])]
            ),
        )


asyncio.run(main())
