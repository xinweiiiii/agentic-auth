"""The example drift fixture on disk is exactly the bank fixture the suite uses (T053)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.schemas.manifest import AgentManifest
from app.services.drift import load_manifest_dirs
from app.sidecar.config import load as load_sidecar_config
from tests.fixtures.bank import bank_docs

FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "drift-fixture"


@pytest.mark.parametrize(
    ("directory", "widened"), [("manifests", False), ("manifests-widened", True)]
)
def test_the_example_manifests_are_the_bank_fixture(directory: str, widened: bool) -> None:
    loaded = load_manifest_dirs([FIXTURE / directory])

    assert loaded.errors == []
    assert loaded.manifests == {
        name: AgentManifest.model_validate(doc) for name, doc in bank_docs(widened=widened).items()
    }


def test_the_example_sidecar_config_records_in_observe_mode() -> None:
    config = load_sidecar_config(FIXTURE / "sidecar.yaml")

    assert config.observe_mode is True
    assert config.trace_path == "./edge-events.jsonl"
    assert "/tools/terminate_account" in config.upstream_map
