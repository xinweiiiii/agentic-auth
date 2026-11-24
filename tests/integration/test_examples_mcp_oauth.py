"""examples/mcp-oauth runs as published, offline (feature 011, quickstart V3, SC-001).

And its client side really is a standard MCP client: ``client_flow.py`` imports nothing from
Agentic Auth, which is the claim the example exists to demonstrate.
"""

from __future__ import annotations

import ast
import importlib.util
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "mcp-oauth"


def test_the_client_side_contains_no_agentic_auth_code() -> None:
    tree = ast.parse((EXAMPLE / "client_flow.py").read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "agentic_auth" not in imported


async def test_the_example_runs_end_to_end_offline(monkeypatch) -> None:
    def refuse(*_a, **_k):
        raise AssertionError("the example opened a network connection")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.syspath_prepend(str(EXAMPLE))
    spec = importlib.util.spec_from_file_location("mcp_oauth_run_local", EXAMPLE / "run_local.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    lines: list[str] = []
    outcome = await module.main(log=lines.append)

    assert [line.split("->")[1].strip() for line in lines[:1]] == ["401"]
    assert lines[4].endswith("-> 200")
    assert outcome["result"]["result"]["content"][0]["text"] == "3 articles found"
    root = outcome["chain"]["root_consent"]
    assert root["principal_source"] == "embedded-test"
    assert root["client_id"] == "desktop-client"
