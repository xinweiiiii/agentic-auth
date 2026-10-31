"""Read an embedded export bundle and carry it into a deployed control plane.

The bundle is ``EmbeddedControlPlane.export``'s NDJSON (agentic_auth/embedded/export.py). Two
things come across, each through the door that already exists for it:

- **Manifests** are re-registered through the admin API (``agentic-auth manifest
  register-bundle``), so they reconcile against this deployment's real capability discovery
  exactly as a fresh registration does. Every version is replayed in order.
- **Audit history** lands in ``imported_audit`` (``agentic-auth audit import``), apart from
  this deployment's own log. See agentic_auth/models/imported_audit.py for why.

Two things deliberately do not: **trust anchors**, because enrollment is proof of possession
of a private key the bundle does not (and must not) contain — an agent re-enrolls with its own
key; and **sessions and keys**, which the export never writes.

The reader names the bundle line of every problem, so a hand-edited or truncated bundle points
at the exact record.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

KINDS = ("agent", "manifest", "trust_anchor", "audit")


class BundleError(ValueError):
    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"bundle line {line}: {message}")
        self.line = line


@dataclass
class Bundle:
    header: dict[str, Any]
    agents: list[dict[str, Any]] = field(default_factory=list)
    manifests: list[dict[str, Any]] = field(default_factory=list)
    trust_anchors: list[dict[str, Any]] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)

    @property
    def exported_at(self) -> datetime:
        return datetime.fromisoformat(self.header["exported_at"])

    def manifest_history(self) -> dict[str, list[dict[str, Any]]]:
        """Agent name -> every manifest document it had, oldest version first."""
        names = {agent["id"]: agent["name"] for agent in self.agents}
        history: dict[str, list[tuple[int, dict[str, Any]]]] = {}
        for manifest in self.manifests:
            name = names.get(manifest["agent_id"])
            if name is not None:
                history.setdefault(name, []).append((manifest["version"], manifest["doc"]))
        return {name: [doc for _, doc in sorted(rows)] for name, rows in history.items()}


def read_bundle(path: Path) -> Bundle:
    bundle: Bundle | None = None
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BundleError(number, f"not JSON ({exc.msg})") from exc
        if not isinstance(record, dict) or not isinstance(record.get("kind"), str):
            raise BundleError(number, "a record must be an object with a `kind`")
        kind = record.pop("kind")
        if bundle is None:
            if kind != "header":
                raise BundleError(number, "the first record must be the header")
            for key in ("source_deployment", "package_version", "exported_at", "counts"):
                if key not in record:
                    raise BundleError(number, f"header is missing `{key}`")
            bundle = Bundle(header=record)
            continue
        if kind not in KINDS:
            raise BundleError(number, f"unknown record kind {kind!r}")
        required = {
            "agent": ("id", "name"),
            "manifest": ("agent_id", "version", "doc"),
            "trust_anchor": ("agent_id",),
            "audit": ("id",),
        }[kind]
        missing = [key for key in required if key not in record]
        if missing:
            raise BundleError(number, f"{kind} record is missing {', '.join(missing)}")
        target = {
            "agent": bundle.agents,
            "manifest": bundle.manifests,
            "trust_anchor": bundle.trust_anchors,
            "audit": bundle.audit,
        }[kind]
        target.append(record)
    if bundle is None:
        raise BundleError(1, "empty bundle")
    counts = bundle.header["counts"]
    for kind, rows in (
        ("agent", bundle.agents),
        ("manifest", bundle.manifests),
        ("trust_anchor", bundle.trust_anchors),
        ("audit", bundle.audit),
    ):
        if counts.get(kind) != len(rows):
            raise BundleError(
                1, f"header counts {counts.get(kind)} {kind} record(s), the bundle has {len(rows)}"
            )
    return bundle


@dataclass(frozen=True)
class AuditImport:
    imported: int
    already_present: int


async def import_audit(db: AsyncSession, bundle: Bundle) -> AuditImport:
    """Append the bundle's decisions to ``imported_audit``. Idempotent: a decision whose
    action id is already there is skipped, so re-running an import adds nothing."""
    from sqlalchemy import select

    from agentic_auth.models import ImportedAudit

    ids = [uuid.UUID(row["id"]) for row in bundle.audit]
    present = (
        set(
            (
                await db.execute(
                    select(ImportedAudit.action_id).where(ImportedAudit.action_id.in_(ids))
                )
            )
            .scalars()
            .all()
        )
        if ids
        else set()
    )
    new = [row for row in bundle.audit if uuid.UUID(row["id"]) not in present]
    db.add_all(
        ImportedAudit(
            action_id=uuid.UUID(row["id"]),
            source_deployment=str(bundle.header["source_deployment"]),
            source_package_version=str(bundle.header["package_version"]),
            exported_at=bundle.exported_at,
            row=row,
        )
        for row in new
    )
    await db.flush()
    return AuditImport(imported=len(new), already_present=len(present))


def registration_plan(bundle: Bundle) -> list[tuple[str, list[dict[str, Any]]]]:
    """Agents in registration order (downstream first), each with its manifest history."""
    from agentic_auth.schemas.manifest import AgentManifest
    from agentic_auth.services.drift import registration_order

    history = bundle.manifest_history()
    latest: Mapping[str, AgentManifest] = {
        name: AgentManifest.model_validate(docs[-1]) for name, docs in history.items()
    }
    return [(name, history[name]) for name in registration_order(latest)]


def summarize(names: Iterable[str]) -> str:
    return ", ".join(sorted(names)) or "none"
