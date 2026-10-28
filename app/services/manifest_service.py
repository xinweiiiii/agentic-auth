"""Orchestrates validate → reconcile → persist → compile in one transaction."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.errors import ManifestValidationError, NotFoundError
from app.repositories import agents as agents_repo
from app.repositories import compiled_policies as policies_repo
from app.repositories import manifests as manifests_repo
from app.repositories import reconciliation_reports as reports_repo
from app.schemas.agent import OverrideDecl
from app.schemas.manifest import AgentManifest
from app.services import catalog_service
from app.services.dag_compiler import DagCompiler
from app.services.discovery import DiscoveryClient
from app.services.reconciler import ReconcilerService


@dataclass
class ProcessOutcome:
    agent_id: uuid.UUID
    agent_name: str
    version: int
    status: str  # reconciled | needs_review | rejected
    discovery_ok: bool
    diff: list[dict]
    http_status: int  # 201 | 409 | 422


class ManifestService:
    def __init__(
        self,
        *,
        discovery: DiscoveryClient,
        reconciler: ReconcilerService | None = None,
        compiler: DagCompiler | None = None,
    ) -> None:
        self._discovery = discovery
        self._reconciler = reconciler or ReconcilerService()
        self._compiler = compiler or DagCompiler()

    async def register_agent(
        self,
        session: AsyncSession,
        redis: Redis,
        *,
        name: str,
        manifest: AgentManifest,
        attested_by: str,
        override: OverrideDecl | None,
    ) -> ProcessOutcome:
        if manifest.metadata.agent != name:
            raise ManifestValidationError(
                "metadata.agent must match the registered agent name",
                {"fields": [{"loc": ["manifest", "metadata", "agent"], "msg": "name mismatch"}]},
            )
        agent = await agents_repo.create(session, name)
        return await self._process(session, redis, agent.id, name, manifest, attested_by, override)

    async def submit_manifest(
        self,
        session: AsyncSession,
        redis: Redis,
        *,
        agent_name: str,
        manifest: AgentManifest,
        attested_by: str,
        override: OverrideDecl | None,
    ) -> ProcessOutcome:
        agent = await agents_repo.get_by_name(session, agent_name)
        if agent is None:
            raise NotFoundError(f"agent {agent_name!r} is not registered")
        if manifest.metadata.agent != agent_name:
            raise ManifestValidationError(
                "manifest.metadata.agent must match the target agent",
                {"fields": [{"loc": ["manifest", "metadata", "agent"], "msg": "name mismatch"}]},
            )
        return await self._process(
            session, redis, agent.id, agent_name, manifest, attested_by, override
        )

    async def _process(
        self,
        session: AsyncSession,
        redis: Redis,
        agent_id: uuid.UUID,
        agent_name: str,
        manifest: AgentManifest,
        attested_by: str,
        override: OverrideDecl | None,
    ) -> ProcessOutcome:
        try:
            manifest.ensure_create_form()
        except ValueError as exc:
            raise ManifestValidationError(
                str(exc),
                {"fields": [{"loc": ["manifest", "metadata", "version"], "msg": str(exc)}]},
            ) from exc

        discovered = await self._discovery.discover(self._reconciler.authorities(manifest))
        outcome = self._reconciler.reconcile(manifest, discovered)

        status = outcome.status
        override_reason: str | None = None
        http_status = 201

        if status == "rejected":
            http_status = 422
        elif status == "needs_review":
            if override is not None:
                override_reason = override.validated_reason()
                status = "reconciled"
            else:
                http_status = 409

        manifest_row = await manifests_repo.append_version(
            session,
            agent_id=agent_id,
            doc=manifest.canonical_doc(),
            status=status,
            attested_by=attested_by,
            override_reason=override_reason,
        )
        await reports_repo.create(
            session,
            manifest_id=manifest_row.id,
            diff=[d.model_dump(mode="json") for d in outcome.diff],
            discovery_ok=outcome.discovery_ok,
        )

        if status == "reconciled":
            await self._recompile(session, redis, agent_name)

        return ProcessOutcome(
            agent_id=agent_id,
            agent_name=agent_name,
            version=manifest_row.version,
            status=status,
            discovery_ok=outcome.discovery_ok,
            diff=[d.model_dump(mode="json") for d in outcome.diff],
            http_status=http_status,
        )

    async def _recompile(self, session: AsyncSession, redis: Redis, changed_agent: str) -> None:
        reconciled = await manifests_repo.all_reconciled(session)
        manifests = {
            m.doc["metadata"]["agent"]: AgentManifest.model_validate(m.doc) for m in reconciled
        }
        manifest_id_by_agent = {m.doc["metadata"]["agent"]: m.id for m in reconciled}
        compiled = self._compiler.compile(manifests)  # raises DagCycleError -> route rollback

        for scope, cs in compiled.items():
            if changed_agent not in cs.source_agents:
                continue
            source_ids = [
                manifest_id_by_agent[a] for a in cs.source_agents if a in manifest_id_by_agent
            ]
            row = await policies_repo.append_version(
                session, scope=scope, dag=cs.to_dag(), source_manifest_ids=source_ids
            )
            await catalog_service.warm(redis, scope, row.version, row.dag)
