"""``agentic-auth audit export`` — read-only archival."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import text
from typer.testing import CliRunner

from agentic_auth.cli import app as cli
from agentic_auth.cli.audit import export_before
from agentic_auth.config import get_settings
from tests.fixtures.bank import BANK_ASSISTANT, CLEAN_CALLS, bank_docs
from tests.fixtures.hops import authorize, consent_session, register_agents, run_calls


async def test_export_splits_at_the_cutoff_and_changes_nothing(
    client, admin_headers, db_session, tmp_path
) -> None:
    await register_agents(client, admin_headers, bank_docs())
    session = await consent_session(client, admin_headers, BANK_ASSISTANT)

    # Two decisions before the cutoff...
    early, presented = await run_calls(client, session["root_grant"], CLEAN_CALLS[:2])
    cutoff = datetime.now(UTC)
    # ...and one after it. A decision is recorded whether or not a token is ever issued.
    _, target, data_class = CLEAN_CALLS[1]
    late = await authorize(client, presented[-1], target=target, data_class=data_class)
    assert late.json()["recorded"] is True

    out = tmp_path / "archive.jsonl"
    exported = await export_before(get_settings().database_url, cutoff, out)

    lines = [json.loads(line) for line in out.read_text().splitlines()]
    assert exported == len(lines) == 2
    assert [line["hop"] for line in lines] == [1, 2]
    assert [line["id"] for line in lines] == [d["action_id"] for d in early]

    archive = out.read_text()
    for token in presented:
        assert token not in archive

    remaining = await db_session.scalar(
        text("SELECT count(*) FROM audit_decisions WHERE session_id = :s"),
        {"s": session["session_id"]},
    )
    assert remaining == 3  # exporting removed nothing


def test_a_cutoff_without_a_timezone_is_refused(tmp_path) -> None:
    result = CliRunner().invoke(
        cli,
        ["audit", "export", "--before", "2027-01-01T00:00:00", "--out", str(tmp_path / "a.jsonl")],
    )
    assert result.exit_code == 2
    assert "timezone" in result.output


def test_a_cutoff_that_is_not_a_timestamp_is_refused(tmp_path) -> None:
    result = CliRunner().invoke(
        cli, ["audit", "export", "--before", "yesterday", "--out", str(tmp_path / "a.jsonl")]
    )
    assert result.exit_code == 2


def test_an_unwritable_destination_is_refused_before_connecting(tmp_path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "audit",
            "export",
            "--before",
            "2027-01-01T00:00:00Z",
            "--out",
            str(tmp_path / "missing-dir" / "a.jsonl"),
            "--database-url",
            "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none",
        ],
    )
    assert result.exit_code == 2
    assert "does not exist" in result.output
