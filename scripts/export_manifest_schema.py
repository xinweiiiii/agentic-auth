"""Export the JSON Schema for the agent manifest from the Pydantic model.

Run from the repository root:  ``python scripts/export_manifest_schema.py``
The output is the single source of truth consumed by external integrators; a unit test
(``tests/unit/test_manifest_schema.py::test_json_schema_no_drift``) fails if it drifts.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.schemas.manifest import AgentManifest

OUT = (
    Path(__file__).resolve().parents[2]
    / "specs"
    / "001-manifest-and-dag"
    / "contracts"
    / "manifest.schema.json"
)


def build() -> dict:
    schema = AgentManifest.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://agentic-auth.dev/schemas/agent-manifest/v1.json"
    schema["x-generated-from"] = "app.schemas.manifest.AgentManifest"
    return schema


def main() -> None:
    OUT.write_text(json.dumps(build(), indent=2) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
