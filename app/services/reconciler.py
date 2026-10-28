"""Reconcile a declared manifest against discovered capabilities.

Output: a terminal status (``reconciled`` | ``needs_review`` | ``rejected``) plus a
100%-actionable diff — every entry names the exact offending tool ref, the field, the
declared vs discovered value, a machine code, and a concrete remedy.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.manifest import AgentManifest, ToolDecl
from app.schemas.reconciliation import HARD_CODES, DiffCode, DiffEntry
from app.services.discovery import DiscoveryResult, authority_for, tool_name


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

        if any(d.code in HARD_CODES for d in diff):
            return ReconcileOutcome("rejected", diff, discovery_ok)
        if not discovery_ok:
            return ReconcileOutcome("needs_review", diff, discovery_ok)
        return ReconcileOutcome("reconciled", diff, discovery_ok)
