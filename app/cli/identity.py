"""``agentic-auth identity`` — key generation, challenge signing, revocation."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich import print as rprint

from app.sdk.identity import AgentKey

app = typer.Typer(help="Agent identity: keys, challenges, revocation (Phase 4).")


@app.command()
def keygen(out: Path = typer.Option(..., "--out", help="Where to write the PKCS8 PEM")) -> None:
    """Generate an Ed25519 agent key (mode 0600) and print its public JWK."""
    key = AgentKey.generate()
    key.save(out)
    rprint(json.dumps(key.jwk(), indent=2))


@app.command("sign-challenge")
def sign_challenge(
    key: Path = typer.Option(..., "--key"),
    agent: str = typer.Option(..., "--agent"),
    challenge: Path = typer.Option(..., "--challenge", help="The JSON body from POST .../enroll"),
    aud: str = typer.Option("agentic-auth", "--aud"),
) -> None:
    """Sign an enrollment challenge; prints the compact JWS for POST .../enroll/complete."""
    nonce = json.loads(challenge.read_text())["nonce"]
    typer.echo(AgentKey.load(key).sign_challenge(agent, nonce, aud=aud))


@app.command("identity-document")
def identity_document(
    key: Path = typer.Option(..., "--key"),
    agent: str = typer.Option(..., "--agent"),
    principal_assertion: str | None = typer.Option(None, "--principal-assertion"),
) -> None:
    """Print the identity document to POST to .../enroll."""
    doc = AgentKey.load(key).identity_document(agent, principal_assertion=principal_assertion)
    typer.echo(json.dumps({"identity_doc": doc}, indent=2))


@app.command()
def revoke(
    agent_id: str = typer.Argument(...),
    base_url: str = typer.Option("http://localhost:8000", "--base-url"),
    admin_token: str = typer.Option(..., "--admin-token", envvar="AGENTIC_AUTH_ADMIN_TOKEN"),
    reason: str | None = typer.Option(None, "--reason"),
) -> None:
    """Revoke an agent's trust anchor (admin)."""
    import asyncio

    from app.sdk.client import AgenticAuthClient

    async def _run() -> dict:
        async with AgenticAuthClient(base_url, admin_token=admin_token) as client:
            return await client.revoke(agent_id, reason=reason)

    rprint(json.dumps(asyncio.run(_run()), indent=2, default=str))
