"""Locating the checked-in contracts from a test.

The contracts under ``docs/contracts/`` are the normative wire formats: a resource server
or an auditor implements against them, and the tests here hold the running code to the same
documents. Keeping one copy that both consume is what stops the implementation and its
published description drifting apart.

Resolved by walking **up** to the repository root rather than by counting directories, so
the tests keep working when the tree is copied somewhere deeper — which is exactly what
``mutmut`` does when it builds ``mutants/``. A fixed ``parents[N]`` silently becomes the
wrong directory there, and the test fails at import with a missing file.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

import yaml


@cache
def repo_root() -> Path:
    """The first ancestor holding this project's ``docs/contracts/`` directory."""
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "docs" / "contracts").is_dir():
            return candidate
    raise RuntimeError(f"no docs/contracts/ directory above {Path(__file__).resolve()}")


def contract_path(name: str) -> Path:
    return repo_root() / "docs" / "contracts" / name


@cache
def load_json_contract(name: str) -> Any:
    return json.loads(contract_path(name).read_text())


@cache
def load_yaml_contract(name: str) -> Any:
    return yaml.safe_load(contract_path(name).read_text())


def component_schema(name: str, component: str) -> dict[str, Any]:
    """One ``components.schemas`` entry from an OpenAPI document, ready for jsonschema."""
    spec = load_yaml_contract(name)
    return {"$ref": f"#/components/schemas/{component}", "components": spec["components"]}


def defs_schema(name: str, definition: str) -> dict[str, Any]:
    """One ``$defs`` entry from a JSON Schema document."""
    schema = load_json_contract(name)
    return {"$ref": f"#/$defs/{definition}", "$defs": schema["$defs"]}
