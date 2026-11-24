"""Reconcile a declared manifest against discovered capabilities.

Output: a terminal status (``reconciled`` | ``needs_review`` | ``rejected``) plus a
100%-actionable diff — every entry names the exact offending tool ref, the field, the
declared vs discovered value, a machine code, and a concrete remedy.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentic_auth.schemas.manifest import AgentManifest, ToolDecl
from agentic_auth.schemas.reconciliation import HARD_CODES, DiffCode, DiffEntry
from agentic_auth.services.discovery import (
    DiscoveredAuthorizationServer,
    DiscoveryResult,
    authority_for,
    tool_name,
)


@dataclass
class ReconcileOutcome:
    status: str  # reconciled | needs_review | rejected
    diff: list[DiffEntry]
    discovery_ok: bool


def _entry(
    tool: ToolDecl, field: str, declared: object, discovered: object, code: DiffCode, remedy: str
) -> DiffEntry:
    return DiffEntry(
        tool_ref=tool.ref,
        field=field,
        declared=declared,
        discovered=discovered,
        code=code,
        remedy=remedy,
    )


class ReconcilerService:
    def authorities(self, manifest: AgentManifest) -> set[str]:
        return {authority_for(t.ref) for t in manifest.spec.tools}

    def reconcile(
        self, manifest: AgentManifest, discovered: dict[str, DiscoveryResult]
    ) -> ReconcileOutcome:
        diff: list[DiffEntry] = []
        discovery_ok = True

        for tool in manifest.spec.tools:
            authority = authority_for(tool.ref)
            result = discovered.get(authority)

            if result is None or not result.ok or result.resource is None:
                discovery_ok = False
                reason = result.error if result else "not attempted"
                diff.append(
                    _entry(
                        tool,
                        "ref",
                        tool.ref,
                        None,
                        DiffCode.DISCOVERY_UNAVAILABLE,
                        f"capability source {authority} is unreachable ({reason}); "
                        f"retry once it is up or submit an admin override with a recorded reason",
                    )
                )
                continue

            resource = result.resource
            name = tool_name(tool.ref)
            advertised = resource.tools.get(name)

            if advertised is None:
                diff.append(
                    _entry(
                        tool,
                        "ref",
                        tool.ref,
                        sorted(resource.tools),
                        DiffCode.UNKNOWN_TOOL,
                        f"tool {name!r} is not advertised by {authority}; "
                        f"remove it or point `ref` at an advertised tool",
                    )
                )
                continue

            allowed = set(advertised.data_classes)
            for dc in tool.data_classes:
                if dc in allowed:
                    continue
                diff.append(
                    _entry(
                        tool,
                        "data_classes",
                        sorted(tool.data_classes),
                        sorted(allowed),
                        DiffCode.DECLARED_EXCEEDS_DISCOVERED,
                        f"remove data class {dc!r} from tool {tool.ref} or widen the "
                        f"manifest scope request — {authority} does not advertise it for "
                        f"tool {name!r}",
                    )
                )

            if result.authorization_server is not None:
                as_entries = _authorization_server_check(tool, result.authorization_server)
                if any(e.code is DiffCode.AUTHORIZATION_SERVER_UNAVAILABLE for e in as_entries):
                    discovery_ok = False
                diff.extend(as_entries)

            if tool.privileged != advertised.privileged and advertised.privileged:
                diff.append(
                    _entry(
                        tool,
                        "privileged",
                        tool.privileged,
                        advertised.privileged,
                        DiffCode.DATA_CLASS_CONFLICT,
                        f"{authority} classifies tool {name!r} as privileged; "
                        f"set `privileged: true` on this tool",
                    )
                )

        # AUTHORIZATION_SERVER_CHECK_SKIPPED never reaches here as a reason: it is neither a
        # hard code nor a discovery failure, so it changes no status.
        if any(d.code in HARD_CODES for d in diff):
            return ReconcileOutcome("rejected", diff, discovery_ok)
        if not discovery_ok:
            return ReconcileOutcome("needs_review", diff, discovery_ok)
        return ReconcileOutcome("reconciled", diff, discovery_ok)


def _authorization_server_check(
    tool: ToolDecl, server: DiscoveredAuthorizationServer
) -> list[DiffEntry]:
    """Feature 011 (M3, research R9): is every declared data class a scope the resource's
    authorization server issues? A scope nobody issues is a capability nobody can hold."""
    if server.issuer is None:
        return [
            _entry(
                tool,
                "authorization_servers",
                sorted(tool.data_classes),
                None,
                DiffCode.AUTHORIZATION_SERVER_CHECK_SKIPPED,
                f"no authorization server is named in the metadata for {tool.ref}; only the "
                "resource's own advertisement was checked",
            )
        ]
    if not server.ok:
        return [
            _entry(
                tool,
                "authorization_servers",
                server.issuer,
                None,
                DiffCode.AUTHORIZATION_SERVER_UNAVAILABLE,
                f"authorization server {server.issuer} metadata could not be fetched "
                f"({server.error}); retry once it is up or submit an admin override with a "
                "recorded reason",
            )
        ]
    if server.scopes_supported is None:
        return [
            _entry(
                tool,
                "data_classes",
                sorted(tool.data_classes),
                None,
                DiffCode.AUTHORIZATION_SERVER_CHECK_SKIPPED,
                f"authorization server {server.issuer} does not publish scopes_supported; only "
                "the resource's own advertisement was checked",
            )
        ]
    issued = set(server.scopes_supported)
    return [
        _entry(
            tool,
            "data_classes",
            sorted(tool.data_classes),
            sorted(issued),
            DiffCode.DECLARED_EXCEEDS_AUTHORIZATION_SERVER,
            f"remove data class {dc!r} from tool {tool.ref} — authorization server "
            f"{server.issuer} does not list it in scopes_supported",
        )
        for dc in sorted(tool.data_classes)
        if dc not in issued
    ]
