"""One scenario, two deployments: the remote control plane and the embedded one (FR-010).

Every scenario in this package takes ``deployment`` and drives only what an integrator can
reach: the SDK client, the resource-side verifier, and the audit plane. The ``remote``
parametrization is the integration harness every other test uses (the real app on PostgreSQL
and Redis behind an in-process transport); ``embedded`` is ``EmbeddedControlPlane`` on SQLite
with nothing else running. ``test_zz_identical.py`` then holds the two transcripts equal.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import text

from agentic_auth.sdk import AgenticAuthClient, AgentKey, HttpAnchors, HttpJwks, InMemoryReplay
from agentic_auth.verify import Verifier
from tests.fixtures.bank import leaf_first
from tests.fixtures.discovery.server import RESOURCES

pytestmark = pytest.mark.conformance


@dataclass
class Deployment:
    name: str
    sdk: AgenticAuthClient
    _register: Callable[[dict[str, dict[str, Any]]], Awaitable[None]]
    _enroll: Callable[[str, AgentKey], Awaitable[dict[str, Any]]]
    _verifier: Callable[..., Awaitable[Verifier]]
    _agent_client: Callable[[str, AgentKey], AgenticAuthClient]
    _flags: Callable[..., None]
    _raw_sql: Callable[[str], Awaitable[str]]
    verifiers: list[Verifier] = field(default_factory=list)

    async def register(self, docs: dict[str, dict[str, Any]]) -> None:
        await self._register(docs)

    async def enroll(self, agent: str, key: AgentKey) -> dict[str, Any]:
        return await self._enroll(agent, key)

    async def verifier(self, **kwargs: Any) -> Verifier:
        verifier = await self._verifier(**kwargs)
        self.verifiers.append(verifier)
        return verifier

    def agent_client(self, agent: str, key: AgentKey) -> AgenticAuthClient:
        return self._agent_client(agent, key)

    def flags(self, **values: Any) -> None:
        self._flags(**values)

    async def raw_sql(self, statement: str) -> str:
        """Run ``statement`` as the deployment's own database role; "ok" or the refusal."""
        return await self._raw_sql(statement)


async def _remote(
    client: Any, flags: Any, principal_assertion_for: Any, writer_engine: Any
) -> AsyncIterator[Deployment]:
    from tests.conftest import ADMIN_TOKEN

    admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    sdk = AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)

    async def register(docs: dict[str, dict[str, Any]]) -> None:
        for name in leaf_first(docs):
            r = await client.post(
                "/v1/agents", headers=admin, json={"name": name, "manifest": docs[name]}
            )
            assert r.status_code == 201, (name, r.status_code, r.text)

    async def enroll(agent: str, key: AgentKey) -> dict[str, Any]:
        agent_id = await sdk.admin.agent_id(agent)
        return await sdk.enroll(
            agent_id, key=key, agent_name=agent, principal_assertion=principal_assertion_for(agent)
        )

    async def verifier(*, agents: list[str] = (), **kwargs: Any) -> Verifier:
        v = Verifier(
            issuer_jwks=HttpJwks("http://test/.well-known/jwks.json", client=client),
            anchors=HttpAnchors(
                base_url="http://test", token=ADMIN_TOKEN, agents=list(agents), client=client
            ),
            replay=InMemoryReplay(),
            **kwargs,
        )
        await v.bootstrap()
        return v

    def agent_client(agent: str, key: AgentKey) -> AgenticAuthClient:
        return AgenticAuthClient(
            base_url="http://test",
            admin_token=ADMIN_TOKEN,
            client=client,
            identity_key=key,
            agent_name=agent,
        )

    async def raw_sql(statement: str) -> str:
        try:
            async with writer_engine.begin() as conn:
                await conn.execute(text(statement))
        except Exception:
            return "refused"
        return "ok"

    yield Deployment("remote", sdk, register, enroll, verifier, agent_client, flags, raw_sql)


async def _embedded() -> AsyncIterator[Deployment]:
    from agentic_auth.embedded import EmbeddedControlPlane

    cp = await EmbeddedControlPlane.start(capabilities=RESOURCES)

    async def register(docs: dict[str, dict[str, Any]]) -> None:
        await cp.register(docs)

    async def enroll(agent: str, key: AgentKey) -> dict[str, Any]:
        return await cp.enroll_test_principal(agent, key)

    async def verifier(*, agents: list[str] = (), **kwargs: Any) -> Verifier:
        return await cp.verifier(agents=agents, **kwargs)

    def flags(**values: Any) -> None:
        cp.configure(**values)

    async def raw_sql(statement: str) -> str:
        try:
            async with cp._store.engine.begin() as conn:
                await conn.execute(text(statement))
        except Exception:
            return "refused"
        return "ok"

    try:
        yield Deployment(
            "embedded",
            cp.client(),
            register,
            enroll,
            verifier,
            lambda agent, key: cp.client(agent, key=key),
            flags,
            raw_sql,
        )
    finally:
        await cp.aclose()


@pytest_asyncio.fixture(params=["remote", "embedded"])
async def deployment(
    request, client, flags, principal_assertion_for, writer_engine
) -> AsyncIterator[Deployment]:
    """Both parametrizations take the remote harness's fixtures, so the suite always needs
    PostgreSQL and Redis — it is a comparison, and the remote side is half of it. The
    embedded control plane on its own is covered by tests/embedded, which needs neither."""
    deployments = (
        _remote(client, flags, principal_assertion_for, writer_engine)
        if request.param == "remote"
        else _embedded()
    )
    async for d in deployments:
        try:
            yield d
        finally:
            for v in d.verifiers:
                await v.close()
