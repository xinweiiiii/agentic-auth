"""``agentic-auth`` command-line entry point."""

from __future__ import annotations

from agentic_auth._extras import require_extra

require_extra("agentic_auth.cli", "drift", "typer", "rich", "yaml", "httpx", "prometheus_client")

import typer

from agentic_auth.cli.audit import audit_app
from agentic_auth.cli.drift import drift_app
from agentic_auth.cli.identity import app as identity_app
from agentic_auth.cli.manifest import manifest_app
from agentic_auth.cli.sandbox import sandbox_app

app = typer.Typer(help="Agentic Authorization SDK developer CLI", no_args_is_help=True)
app.add_typer(manifest_app, name="manifest")
app.add_typer(audit_app, name="audit")
app.add_typer(drift_app, name="drift")
app.add_typer(identity_app, name="identity")
app.add_typer(sandbox_app, name="sandbox")


def main() -> None:
    app()


__all__ = ["app", "main"]
