"""Schema validation for the agent manifest."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.schemas.manifest import AgentManifest
from tests.fixtures.contracts import contract_path
from tests.fixtures.manifests import base_manifest

SCHEMA_PATH = contract_path("manifest.schema.json")


def test_valid_manifest_parses() -> None:
    m = AgentManifest.model_validate(base_manifest())
    assert m.metadata.agent == "kb-search-agent"
    assert m.spec.hop_budget == 4


def test_missing_hop_budget_rejected() -> None:
    doc = base_manifest()
    del doc["spec"]["hop_budget"]
    with pytest.raises(ValidationError) as exc:
        AgentManifest.model_validate(doc)
    assert any("hop_budget" in ".".join(str(p) for p in e["loc"]) for e in exc.value.errors())


def test_unknown_top_level_key_rejected() -> None:
    doc = base_manifest()
    doc["surprise"] = 1
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(doc)


def test_client_set_version_rejected_on_create() -> None:
    doc = base_manifest()
    doc["metadata"]["version"] = 3
    m = AgentManifest.model_validate(doc)  # parses fine as a read model
    with pytest.raises(ValueError, match="server-assigned"):
        m.ensure_create_form()


def test_tool_data_class_must_be_declared() -> None:
    doc = base_manifest()
    doc["spec"]["tools"][0]["data_classes"].append("kb.secret")
    with pytest.raises(ValidationError, match="not present in"):
        AgentManifest.model_validate(doc)


def test_downstream_hop_depth_cannot_exceed_budget() -> None:
    doc = base_manifest()
    doc["spec"]["hop_budget"] = 2
    doc["spec"]["downstream_agents"] = [{"ref": "agent://ledger", "max_hop_depth": 5}]
    with pytest.raises(ValidationError, match="exceeds spec.hop_budget"):
        AgentManifest.model_validate(doc)


def test_bad_tool_ref_scheme_rejected() -> None:
    doc = base_manifest()
    doc["spec"]["tools"][0]["ref"] = "http://kb.internal/search"
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(doc)


def test_json_schema_no_drift() -> None:
    generated = AgentManifest.model_json_schema()
    on_disk = json.loads(SCHEMA_PATH.read_text())
    assert on_disk.get("x-generated-from") == "app.schemas.manifest.AgentManifest"
    assert on_disk["properties"].keys() == generated["properties"].keys()


# -- Phase 4: taint_policy and binding_params ---------------------------------------


def test_taint_policy_defaults_are_privileged_only_and_no_trusted_sources() -> None:
    m = AgentManifest.model_validate(base_manifest())
    assert m.spec.taint_policy.trusted_sources is None  # compiler materializes downstream agents
    assert m.spec.taint_policy.block_tainted_into == ["privileged"]


def test_taint_policy_globs_parse() -> None:
    doc = base_manifest()
    doc["spec"]["taint_policy"] = {
        "trusted_sources": ["mcp://kb.internal/*", "agent://ledger"],
        "block_tainted_into": ["privileged", "*.write", "mcp://accounts.internal/*"],
    }
    m = AgentManifest.model_validate(doc)
    assert m.spec.taint_policy.trusted_sources == ["mcp://kb.internal/*", "agent://ledger"]


def test_empty_glob_rejected() -> None:
    doc = base_manifest()
    doc["spec"]["taint_policy"] = {"trusted_sources": [""]}
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(doc)


def test_binding_params_require_a_privileged_tool() -> None:
    doc = base_manifest()
    doc["spec"]["tools"][0]["binding_params"] = ["/account_id"]
    with pytest.raises(ValidationError, match="not privileged"):
        AgentManifest.model_validate(doc)


def test_binding_params_must_be_json_pointers() -> None:
    doc = base_manifest()
    doc["spec"]["tools"][0]["privileged"] = True
    doc["spec"]["tools"][0]["binding_params"] = ["account_id"]  # no leading slash
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(doc)
    doc["spec"]["tools"][0]["binding_params"] = ["/a/~2"]  # bad escape
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(doc)
    doc["spec"]["tools"][0]["binding_params"] = ["/account_id", "/nested/0/~0tilde", "/a~1b"]
    assert AgentManifest.model_validate(doc).spec.tools[0].binding_params is not None


def test_binding_params_default_is_whole_body() -> None:
    doc = base_manifest()
    doc["spec"]["tools"][0]["privileged"] = True
    assert AgentManifest.model_validate(doc).spec.tools[0].binding_params is None
