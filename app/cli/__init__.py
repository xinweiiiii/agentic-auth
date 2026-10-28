"""``agentic-auth`` command-line entry point."""

from __future__ import annotations

import typer

from app.cli.audit import audit_app
from app.cli.drift import drift_app
from app.cli.identity import app as identity_app
from app.cli.manifest import manifest_app

app = typer.Typer(help="Agentic Authorization SDK developer CLI", no_args_is_help=True)
app.add_typer(manifest_app, name="manifest")
app.add_typer(audit_app, name="audit")
app.add_typer(drift_app, name="drift")
app.add_typer(identity_app, name="identity")


def main() -> None:
    app()


__all__ = ["app", "main"]
