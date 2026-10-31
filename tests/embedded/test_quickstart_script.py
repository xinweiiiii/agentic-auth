"""examples/embedded/quickstart.py — the docs' embedded quickstart — runs as published.

SC-001: an allowed chain and a refusal in 20 lines or fewer, with no infrastructure. "Lines"
are statements, counted with ``ast``, so the limit measures code and not how a formatter
chose to wrap it. SC-006: the whole run, start-up included, under a second.
"""

from __future__ import annotations

import ast
import runpy
import socket
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "examples" / "embedded" / "quickstart.py"


def test_quickstart_is_at_most_twenty_statements() -> None:
    tree = ast.parse(SCRIPT.read_text())
    statements = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.stmt)
        and not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))
    ]
    assert len(statements) <= 20, len(statements)


def test_quickstart_runs_offline_and_fast(monkeypatch, capsys) -> None:
    def refuse(*_a, **_k):
        raise AssertionError("the quickstart opened a network connection")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.chdir(ROOT)

    started = time.perf_counter()
    runpy.run_path(str(SCRIPT), run_name="__main__")
    elapsed = time.perf_counter() - started

    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("allow 4 user:alice → agent://bank-assistant")
    assert out[1] == "deny OUT_OF_SCOPE"
    assert out[2] == "chain user:alice → bank-assistant → balance-agent → support-agent"
    assert elapsed < 1.0, f"{elapsed:.2f}s"


@pytest.mark.parametrize("name", ["README.md"])
def test_the_example_says_what_it_is_for(name: str) -> None:
    text = (SCRIPT.parent / name).read_text()
    assert "development and testing only" in text
