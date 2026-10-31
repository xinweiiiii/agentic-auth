"""Sandbox runs, proposals, and the human act that makes one real.

The shape of this workstream in one paragraph: an agent with no manifest is watched
against mock tools; what it did becomes a candidate manifest; **nothing happens until a
person ratifies it** (FR-037). The generator is pure and lives in
:mod:`agentic_auth.coldstart.propose`; this module is the orchestration and the two invariants
that need a database.

**One run at a time per agent.** A partial unique index, surfaced as a ``409``. Two
concurrent traces racing to become one proposal is a correctness problem — you would not
know which observation the manifest came from — not a capacity one.

**Ratification pins through the ordinary path.** A proposal is a ``manifests`` row whose
status flips; it is not copied into a pinned manifest. One row means "what the
administrator approved" and "what got pinned" cannot differ, and the Phase 1
reconciliation that runs afterwards is the same code a hand-written manifest gets
(FR-042, research.md R12).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.coldstart.propose import propose, was_edited
from agentic_auth.config import get_settings
from agentic_auth.errors import DomainError, NotFoundError, QueryValidationError
from agentic_auth.models.manifest import STATUS_PROPOSED
from agentic_auth.models.sandbox_run import (
    STATUS_COMPLETED,
    STATUS_DEADLINE_EXCEEDED,
    STATUS_FAILED,
    SandboxRun,
)
from agentic_auth.repositories import manifests as manifests_repo
from agentic_auth.repositories import sandbox_runs as runs_repo
from agentic_auth.schemas.edge_trace import EdgeTrace
from agentic_auth.services.metrics import get_metrics

logger = logging.getLogger(__name__)


class RunAlreadyInProgress(DomainError):
    """One observation at a time per agent."""

    status_code = 409
    code = "run_in_progress"


class AlreadyRatified(DomainError):
    """A proposal becomes a pinned manifest once."""

    status_code = 409
    code = "already_ratified"


class NotDerivedFromRun(DomainError):
    """The submitted document is not this proposal's. Editing is allowed; substituting
    a document for a different agent or run is not."""

    status_code = 403
    code = "forbidden"


class SandboxService:
    def __init__(self, *, deadline_seconds: int | None = None) -> None:
        self._deadline = deadline_seconds or get_settings().sandbox_run_deadline_seconds

    async def start(
        self,
        db: AsyncSession,
        *,
        agent_id: uuid.UUID,
        scope: str,
        deadline_seconds: int | None = None,
    ) -> SandboxRun:
        existing = await runs_repo.running_for(db, agent_id)
        if existing is not None:
            raise RunAlreadyInProgress(
                f"agent {agent_id} already has run {existing.id} in progress"
            )

        now = datetime.now(UTC)
        try:
            run = await runs_repo.start(
                db,
                agent_id=agent_id,
                scope=scope,
                started_at=now,
                deadline_at=now + timedelta(seconds=deadline_seconds or self._deadline),
            )
        except IntegrityError as exc:
            # The partial unique index caught a race the read above could not.
            await db.rollback()
            raise RunAlreadyInProgress(f"agent {agent_id} already has a run in progress") from exc
        await db.commit()
        return run

    async def finish(
        self,
        db: AsyncSession,
        run: SandboxRun,
        *,
        trace: EdgeTrace | None,
        failed: bool = False,
    ) -> SandboxRun:
        """Close a run and record what it saw.

        The status distinguishes three endings that mean different things to whoever
        reads the proposal: the agent stopped on its own, the deadline stopped it (so
        the observation is a prefix of its behaviour), or the run broke.
        """
        now = datetime.now(UTC)
        if failed:
            status = STATUS_FAILED
        elif now >= run.deadline_at:
            status = STATUS_DEADLINE_EXCEEDED
        else:
            status = STATUS_COMPLETED

        finished = await runs_repo.finish(
            db,
            run,
            status=status,
            ended_at=now,
            # None preserves whatever the run already collected; the repository treats
            # it as "no new trace" rather than "discard".
            trace=trace.model_dump(mode="json", by_alias=True) if trace else None,
            recorder_errors=trace.recorder_errors if trace else run.recorder_errors,
        )
        await db.commit()
        get_metrics().sandbox_runs.labels(status=status).inc()
        return finished

    async def expire_if_due(self, db: AsyncSession, run: SandboxRun) -> SandboxRun:
        """End a run whose agent never stopped (FR-033).

        Checked lazily on read rather than by a background sweep: a run only matters
        when someone asks about it, and a sweeper would be a second place the deadline
        could be got wrong.
        """
        if run.status != "running" or datetime.now(UTC) < run.deadline_at:
            return run
        return await self.finish(db, run, trace=None)

    # -- proposing -------------------------------------------------------------

    async def propose(
        self,
        db: AsyncSession,
        run: SandboxRun,
        *,
        agent_name: str,
        data_classes: dict[str, str] | None = None,
        privileged: frozenset[str] = frozenset(),
    ) -> Any:
        """Fold the run's trace into a ``proposed`` manifest row.

        Idempotent per run: a second call returns the row the first one created, because
        ``UNIQUE (proposed_from_run_id)`` makes one proposal per run a database fact and
        re-deriving would silently produce a second candidate for the same evidence.
        """
        existing = await manifests_repo.proposed_from_run(db, run.id)
        if existing is not None:
            return existing

        trace = EdgeTrace.model_validate(run.trace) if run.trace else _empty_trace(run)
        document = propose(
            trace,
            agent_name,
            run_id=str(run.id),
            data_classes=data_classes,
            privileged=privileged,
        )

        row = await manifests_repo.append_version(
            db,
            agent_id=run.agent_id,
            doc=document,
            status=STATUS_PROPOSED,
            attested_by="sandbox",
            override_reason=None,
        )
        row.proposed_from_run_id = run.id
        await db.commit()
        return row

    # -- ratifying -------------------------------------------------------------

    async def ratify(
        self,
        db: AsyncSession,
        *,
        run_id: uuid.UUID,
        agent_id: uuid.UUID,
        approved_by: str,
        document: dict[str, Any] | None = None,
    ) -> Any:
        """Turn a proposal into a pinned manifest. One transaction.

        What gets pinned is what the administrator approved — ``document`` when they
        edited it, the generated proposal when they did not (FR-039). The ``x-proposal``
        block is retained either way, so "observed" and "administrator-added" stay
        distinguishable after the fact.
        """
        row = await manifests_repo.proposed_from_run(db, run_id)
        if row is None:
            raise NotFoundError(f"no proposal for run {run_id}")
        if row.agent_id != agent_id:
            raise NotDerivedFromRun(f"run {run_id} does not belong to agent {agent_id}")
        if row.status != STATUS_PROPOSED or row.ratified_at is not None:
            raise AlreadyRatified(f"the proposal from run {run_id} was already ratified")

        final = row.doc
        if document is not None:
            final = _merge_edit(row.doc, document)

        row.doc = final
        row.status = "reconciled"
        row.ratified_by = approved_by
        row.ratified_at = datetime.now(UTC)
        await db.commit()

        get_metrics().proposals_ratified.labels(edited=str(was_edited(final)).lower()).inc()
        logger.info(
            "proposal from run %s ratified by %s as version %s", run_id, approved_by, row.version
        )
        return row


def _merge_edit(proposed: dict[str, Any], edited: dict[str, Any]) -> dict[str, Any]:
    """Keep the administrator's ``spec`` and the generator's provenance.

    An edit that dropped ``x-proposal`` would erase the record of which entries were
    observed, which is the one thing that must survive ratification (FR-039). An edit
    that *rewrote* it would let someone relabel their own additions as evidence, so the
    original block wins.
    """
    if edited.get("metadata", {}).get("agent") != proposed.get("metadata", {}).get("agent"):
        raise NotDerivedFromRun("the edited document names a different agent")
    if "spec" not in edited:
        raise QueryValidationError(
            "an edited proposal must carry a spec",
            [{"loc": ["body", "doc", "spec"], "msg": "missing"}],
        )
    return {**edited, "x-proposal": proposed.get("x-proposal", {})}


def _empty_trace(run: SandboxRun) -> EdgeTrace:
    """A run that recorded nothing still yields a proposal — one that says it covers no
    behaviour, rather than no proposal at all. An administrator seeing 'we watched and
    saw nothing' learns something; a 404 does not."""
    return EdgeTrace.model_validate(
        {
            "schema_version": 1,
            "run": {
                "started_at": run.started_at.isoformat(),
                "finished_at": (run.ended_at or run.deadline_at).isoformat(),
                "command": None,
                "event_files": [],
                "exit_code": None,
            },
            "edges": [],
            "unattributed": {"count": 0, "by_reason": {}},
            "recorder_errors": run.recorder_errors,
            "events_total": 0,
        }
    )


__all__ = [
    "AlreadyRatified",
    "NotDerivedFromRun",
    "RunAlreadyInProgress",
    "SandboxService",
]
