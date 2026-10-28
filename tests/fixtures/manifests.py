"""Manifest document builders for tests."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def base_manifest(agent: str = "kb-search-agent") -> dict[str, Any]:
    return {
        "apiVersion": "agentic-auth/v1",
        "kind": "AgentManifest",
        "metadata": {"agent": agent},
        "spec": {
            "tools": [
                {
                    "ref": "mcp://kb.internal/search",
                    "data_classes": ["kb.public", "kb.internal"],
                    "privileged": False,
                }
            ],
            "data_classes": {"reads": ["kb.public", "kb.internal"], "writes": []},
            "downstream_agents": [],
            "hop_budget": 4,
        },
    }


def with_tool(doc: dict, **tool: Any) -> dict:
    doc = deepcopy(doc)
    doc["spec"]["tools"].append(tool)
    return doc


def overbroad_manifest(agent: str = "kb-search-agent") -> dict:
    """Declares account.write on a tool the source advertises only for account.read."""
    doc = base_manifest(agent)
    doc["spec"]["tools"].append(
        {
            "ref": "mcp://accounts.internal/read_account",
            "data_classes": ["account.read", "account.write"],
            "privileged": False,
        }
    )
    doc["spec"]["data_classes"]["reads"].append("account.read")
    doc["spec"]["data_classes"]["writes"].append("account.write")
    return doc


def unknown_tool_manifest(agent: str = "kb-search-agent") -> dict:
    doc = base_manifest(agent)
    doc["spec"]["tools"].append(
        {
            "ref": "mcp://kb.internal/nonexistent",
            "data_classes": ["kb.public"],
            "privileged": False,
        }
    )
    return doc


def data_class_conflict_manifest(agent: str = "closer-agent") -> dict:
    """Declares privileged=False for a tool the source classifies as privileged."""
    return {
        "apiVersion": "agentic-auth/v1",
        "kind": "AgentManifest",
        "metadata": {"agent": agent},
        "spec": {
            "tools": [
                {
                    "ref": "mcp://accounts.internal/close_account",
                    "data_classes": ["account.write"],
                    "privileged": False,
                }
            ],
            "data_classes": {"reads": [], "writes": ["account.write"]},
            "downstream_agents": [],
            "hop_budget": 2,
        },
    }


def discovery_down_manifest(agent: str = "down-agent") -> dict:
    doc = base_manifest(agent)
    doc["spec"]["tools"] = [
        {
            "ref": "mcp://down.internal/search",
            "data_classes": ["kb.public"],
            "privileged": False,
        }
    ]
    doc["spec"]["data_classes"] = {"reads": ["kb.public"], "writes": []}
    return doc


def with_taint_policy(
    doc: dict,
    *,
    trusted_sources: list[str] | None = None,
    block_tainted_into: list[str] | None = None,
) -> dict:
    """Phase 4: attach a ``taint_policy`` to a manifest document."""
    doc = deepcopy(doc)
    policy: dict[str, Any] = {}
    if trusted_sources is not None:
        policy["trusted_sources"] = trusted_sources
    if block_tainted_into is not None:
        policy["block_tainted_into"] = block_tainted_into
    doc["spec"]["taint_policy"] = policy
    return doc


def privileged_tool(
    ref: str, data_classes: list[str], *, binding_params: list[str] | None = None
) -> dict[str, Any]:
    """Phase 4: a privileged tool declaration, optionally bound on a parameter subset."""
    tool: dict[str, Any] = {"ref": ref, "data_classes": data_classes, "privileged": True}
    if binding_params is not None:
        tool["binding_params"] = binding_params
    return tool
