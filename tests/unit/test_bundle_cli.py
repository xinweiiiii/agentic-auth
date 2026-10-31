"""The import commands refuse a bad bundle or a missing credential before touching anything."""

from __future__ import annotations

from typer.testing import CliRunner

from agentic_auth.cli import app

runner = CliRunner()


def test_register_bundle_needs_the_admin_token(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AGENTIC_AUTH_ADMIN_TOKEN", raising=False)
    bundle = tmp_path / "b.ndjson"
    bundle.write_text("{}\n")
    result = runner.invoke(
        app,
        [
            "manifest",
            "register-bundle",
            str(bundle),
            "--control-plane",
            "http://x",
            "--override-reason",
            "r",
        ],
    )
    assert result.exit_code == 2
    assert "AGENTIC_AUTH_ADMIN_TOKEN is not set" in result.output


def test_register_bundle_names_the_bad_line(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AGENTIC_AUTH_ADMIN_TOKEN", "t")
    bundle = tmp_path / "b.ndjson"
    bundle.write_text('{"kind":"agent","id":"a","name":"x"}\n')
    result = runner.invoke(
        app,
        [
            "manifest",
            "register-bundle",
            str(bundle),
            "--control-plane",
            "http://x",
            "--override-reason",
            "r",
        ],
    )
    assert result.exit_code == 2
    assert "bundle line 1" in result.output


def test_audit_import_names_the_bad_line_without_a_database(tmp_path) -> None:
    bundle = tmp_path / "b.ndjson"
    bundle.write_text("not json\n")
    result = runner.invoke(
        app, ["audit", "import", str(bundle), "--database-url", "postgresql+asyncpg://nowhere/x"]
    )
    assert result.exit_code == 2
    assert "bundle line 1" in result.output
