"""REQUIREMENTS.md and the suite agree: every requirement is tested or says why not, and
every requirement test is listed (FR-016)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

HERE = Path(__file__).parent
ROW = re.compile(r"^\| (MCPA-[A-Z0-9-]+) \|.*\| (.+?) \|$")


def _index() -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in (HERE / "REQUIREMENTS.md").read_text().splitlines():
        match = ROW.match(line)
        if match:
            rows[match.group(1)] = match.group(2)
    return rows


def _tests() -> set[str]:
    names: set[str] = set()
    for path in HERE.glob("test_*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name.startswith(
                "test_MCPA_"
            ):
                names.add(node.name)
    return names


def _id_of(test_name: str) -> str:
    return test_name.removeprefix("test_").replace("_", "-")


def test_every_requirement_has_a_test_or_a_reason() -> None:
    index = _index()
    assert index, "REQUIREMENTS.md lists no requirements"
    tested = {_id_of(t) for t in _tests()}
    for requirement, cell in index.items():
        if cell.startswith("NOT COVERED:"):
            assert len(cell) > len("NOT COVERED: ") + 10, f"{requirement} needs a reason"
            assert requirement not in tested, f"{requirement} is tested but marked not covered"
        else:
            assert requirement in tested, f"{requirement} is listed but has no test"


def test_every_requirement_test_is_listed() -> None:
    listed = set(_index())
    for test in _tests():
        assert _id_of(test) in listed, f"{test} is not in REQUIREMENTS.md"
