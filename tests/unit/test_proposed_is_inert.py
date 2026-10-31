"""A proposed manifest governs nothing.

The failure mode here is silent over-permission — an observation-derived manifest that
quietly starts authorizing calls before a human ever looked at it. That is exactly what
this product exists to prevent, so inertness is asserted directly rather than left to
emerge from three separate filters happening to line up.

Three layers, each tested:

1. **No compiled policy.** ``all_reconciled`` excludes proposals, so the compiler never
   sees one.
2. **No session.** ``SessionService.consent()`` loads the latest compiled policy version
   and raises before its insert when there is none. So nothing can pin a proposal.
3. **No decision path reads it.** ``latest_resolvable`` skips proposals even though
   ``get_latest`` (used by the proposal endpoints) does not.
"""

from __future__ import annotations

import uuid

import pytest

from agentic_auth.errors import NotFoundError
from agentic_auth.models.manifest import (
    MANIFEST_STATUSES,
    RESOLVABLE_STATUSES,
    STATUS_PROPOSED,
)
from agentic_auth.repositories import manifests as manifests_repo
from agentic_auth.services import policy_loader
from tests.fixtures.manifests import base_manifest

pytestmark = pytest.mark.asyncio


@pytest.mark.asyncio(loop_scope=None)
async def test_proposed_is_a_status_but_not_a_resolvable_one() -> None:
    assert STATUS_PROPOSED in MANIFEST_STATUSES
    assert STATUS_PROPOSED not in RESOLVABLE_STATUSES


async def _agent(db_session, name: str):
    from agentic_auth.repositories import agents as agents_repo

    return await agents_repo.create(db_session, name=name)


async def _manifest(db_session, agent, *, status: str, run_id: uuid.UUID | None = None):
    row = await manifests_repo.append_version(
        db_session,
        agent_id=agent.id,
        doc=base_manifest(agent.name),
        status=status,
        attested_by="admin",
        override_reason=None,
    )
    if run_id is not None:
        row.proposed_from_run_id = run_id
    await db_session.commit()
    return row


async def test_a_proposal_never_reaches_the_compiler(db_session) -> None:
    """Layer 1. ``all_reconciled`` is the compiler's only input."""
    agent = await _agent(db_session, "cold-start-agent")
    await _manifest(db_session, agent, status=STATUS_PROPOSED)

    reconciled = await manifests_repo.all_reconciled(db_session)

    assert [m.agent_id for m in reconciled] == []


async def test_a_proposal_alongside_a_reconciled_one_does_not_shadow_it(db_session) -> None:
    """A later proposal must not displace the manifest actually in force — that would
    make ratification implicit, which is the whole thing ratification exists to prevent."""
    agent = await _agent(db_session, "mixed-agent")
    live = await _manifest(db_session, agent, status="reconciled")
    await _manifest(db_session, agent, status=STATUS_PROPOSED)

    reconciled = await manifests_repo.all_reconciled(db_session)

    assert [m.id for m in reconciled] == [live.id]


async def test_latest_resolvable_skips_a_proposal(db_session) -> None:
    """Layer 3. ``get_latest`` returns it (the proposal endpoints need that);
    ``latest_resolvable`` does not."""
    agent = await _agent(db_session, "resolvable-agent")
    live = await _manifest(db_session, agent, status="reconciled")
    proposal = await _manifest(db_session, agent, status=STATUS_PROPOSED)

    latest = await manifests_repo.get_latest(db_session, agent.id)
    resolvable = await manifests_repo.latest_resolvable(db_session, agent.id)
    assert latest is not None and latest.id == proposal.id
    assert resolvable is not None and resolvable.id == live.id


async def test_proposed_for_finds_only_the_proposal(db_session) -> None:
    agent = await _agent(db_session, "proposal-lookup-agent")
    await _manifest(db_session, agent, status="reconciled")
    proposal = await _manifest(db_session, agent, status=STATUS_PROPOSED)

    found = await manifests_repo.proposed_for(db_session, agent.id)

    assert found is not None and found.id == proposal.id


async def test_an_agent_with_only_a_proposal_has_no_compiled_policy(db_session) -> None:
    """Layer 2, first half: there is no policy version to pin."""
    agent = await _agent(db_session, "uncompiled-agent")
    await _manifest(db_session, agent, status=STATUS_PROPOSED)

    version = await policy_loader.latest_version(db_session, agent.name)

    assert version is None


async def test_consent_against_a_proposal_only_agent_is_refused(db_session, redis_client) -> None:
    """Layer 2, second half, and the property that actually matters: **no session can
    pin a proposal**, so no decision can ever resolve against one.

    ``SessionService.consent()`` looks up the latest compiled policy version and raises
    ``NotFoundError`` before its insert. Because layer 1 kept the proposal out of the
    compiler, there is nothing to find.
    """
    from agentic_auth.schemas.consent import ConsentCreate
    from agentic_auth.services.sessions import SessionService
    from agentic_auth.services.tokens.jwt_profile import JwtTokenProfile

    agent = await _agent(db_session, "never-consented-agent")
    await _manifest(db_session, agent, status=STATUS_PROPOSED)

    service = SessionService(JwtTokenProfile())

    with pytest.raises(NotFoundError, match="no compiled policy"):
        await service.consent(
            db_session,
            redis_client,
            ConsentCreate(scope=agent.name, user_sub="alice"),
        )
