"""Export an embedded store as an NDJSON bundle (data-model.md, "Export bundle").

One JSON object per line, in an order a reader can replay:

1. a ``header`` naming where the bundle came from
2. ``agent`` and ``manifest`` records, every manifest version in version order
3. ``trust_anchor`` records: enrollments, with their revocations
4. ``audit`` records in write order, parent links intact

Sessions, keys, taint marks and replay records are deliberately absent: they are runtime
state of *this* instance, and carrying a development signing key into a deployment would be
the one export worse than none.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select

import agentic_auth
from agentic_auth.models import Agent, AuditDecision, Manifest, TrustAnchor
from agentic_auth.runtime import Runtime


def _jsonable(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _row(kind: str, obj: Any) -> dict[str, Any]:
    columns = obj.__table__.columns
    return {"kind": kind, **{c.key: _jsonable(getattr(obj, c.key)) for c in columns}}


async def export_bundle(runtime: Runtime, path: Path) -> Path:
    async with runtime.sessionmaker() as db:
        agents = (await db.execute(select(Agent).order_by(Agent.name))).scalars().all()
        manifests = (
            (await db.execute(select(Manifest).order_by(Manifest.agent_id, Manifest.version)))
            .scalars()
            .all()
        )
        anchors = (
            (
                await db.execute(
                    select(TrustAnchor).order_by(TrustAnchor.agent_id, TrustAnchor.version)
                )
            )
            .scalars()
            .all()
        )
        audit = (
            (await db.execute(select(AuditDecision).order_by(AuditDecision.seq))).scalars().all()
        )

    header = {
        "kind": "header",
        "source_deployment": runtime.deployment,
        "package_version": agentic_auth.__version__,
        "exported_at": datetime.now(UTC).isoformat(),
        "counts": {
            "agent": len(agents),
            "manifest": len(manifests),
            "trust_anchor": len(anchors),
            "audit": len(audit),
        },
    }
    lines = [header]
    lines += [_row("agent", a) for a in agents]
    lines += [_row("manifest", m) for m in manifests]
    lines += [_row("trust_anchor", t) for t in anchors]
    lines += [_row("audit", r) for r in audit]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as out:
        for line in lines:
            out.write(json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n")
    return path
