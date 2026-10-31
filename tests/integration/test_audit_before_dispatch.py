"""No allowed call leaves without a durable record.

Every "blocked" test asserts the same fact the Phase 2 fail-closed tests do: the upstream
received **zero** requests. The audit store is broken at exactly one step —
``AuditService._commit`` — so each test isolates the one guarantee it names.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from agentic_auth.api.v1.token import ACTION_ID_REQUIRED
from agentic_auth.services.audit import AuditService
from tests.fixtures.chains import SUMMARIZER
from tests.fixtures.hops import authorize, exchange

KB_TOOL = "mcp://kb.internal/search"

# A hop the policy refuses: orchestrator -> summarizer skips the declared kb-search edge.
DENIED = {"X-Agentic-Target": f"agent://{SUMMARIZER}", "X-Agentic-Data-Class": "account.read"}


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _reason(response) -> str:
    return response.json()["error"]["details"]["reason"]


async def _audit_rows(db_session) -> int:
    return await db_session.scalar(text("SELECT count(*) FROM audit_decisions"))


@pytest.fixture
async def rooted(register_chain, consent):
    await register_chain()
    return await consent()


@pytest.fixture
def audit_store_down(monkeypatch):
    async def _fail(self, db):
        raise OperationalError("COMMIT", {}, ConnectionError("audit store unreachable"))

    monkeypatch.setattr(AuditService, "_commit", _fail)


# -- an allow that cannot be recorded ------------------------------------------


async def test_an_allow_that_cannot_be_recorded_is_not_dispatched(
    sidecar_stack, rooted, audit_store_down, db_session
) -> None:
    sidecar = await sidecar_stack.client()

    r = await sidecar.get("/kb/search", headers=_bearer(rooted["root_grant"]))

    assert r.status_code == 503
    assert _reason(r) == "AUDIT_UNAVAILABLE"
    assert sidecar_stack.recorder.count == 0
    assert await _audit_rows(db_session) == 0


async def test_the_decision_service_refuses_an_allow_it_could_not_record(
    client, rooted, audit_store_down
) -> None:
    body = (
        await authorize(client, rooted["root_grant"], target=KB_TOOL, data_class="kb.public")
    ).json()

    assert body["outcome"] == "deny"
    assert body["reason"] == "AUDIT_UNAVAILABLE"
    assert body["recoverable"] is False
    assert body["recorded"] is False
    assert body["action_id"] is None


# -- a deny that cannot be recorded ---------------------------------------------


async def test_an_enforced_deny_that_cannot_be_recorded_stays_a_deny(
    sidecar_stack, client, rooted, audit_store_down
) -> None:
    body = (
        await authorize(
            client, rooted["root_grant"], target=f"agent://{SUMMARIZER}", data_class="account.read"
        )
    ).json()
    assert body["reason"] == "EDGE_NOT_IN_DAG"  # not rewritten — a deny is already safe
    assert (body["recorded"], body["action_id"]) == (False, None)

    sidecar = await sidecar_stack.client()
    r = await sidecar.get("/bare", headers={**_bearer(rooted["root_grant"]), **DENIED})

    assert r.status_code == 403
    assert _reason(r) == "EDGE_NOT_IN_DAG"
    assert sidecar_stack.recorder.count == 0


async def test_observe_mode_does_not_forward_a_would_be_deny_it_could_not_record(
    sidecar_stack, rooted, audit_store_down
) -> None:
    """Observe mode forwards a would-be deny — so its record matters exactly as an allow's."""
    sidecar = await sidecar_stack.client(observe_mode=True)

    r = await sidecar.get("/bare", headers={**_bearer(rooted["root_grant"]), **DENIED})

    assert r.status_code == 503
    assert _reason(r) == "AUDIT_UNAVAILABLE"
    assert sidecar_stack.recorder.count == 0


# -- observe mode and infrastructure failures -----------------------------------


async def test_observe_mode_does_not_forward_an_infrastructure_failure(
    sidecar_stack, rooted, monkeypatch
) -> None:
    """Phase 2 forwarded this: a PDP_UNAVAILABLE deny body looked like any other deny."""
    from agentic_auth.services import policy_loader

    sidecar = await sidecar_stack.client(observe_mode=True)

    async def _broken(*_args, **_kwargs):
        raise RuntimeError("policy store unreachable")

    monkeypatch.setattr(policy_loader, "load", _broken)

    r = await sidecar.get("/kb/search", headers=_bearer(rooted["root_grant"]))

    assert r.status_code == 503
    assert _reason(r) == "PDP_UNAVAILABLE"
    assert sidecar_stack.recorder.count == 0


# -- the exchange is bound to a committed allow ---------------------------------


async def test_an_exchange_without_a_recorded_decision_is_refused_and_spends_nothing(
    client, rooted
) -> None:
    root = rooted["root_grant"]

    refused = await exchange(client, root, resource=KB_TOOL, scope="kb.public")
    assert refused.status_code == 400
    assert refused.json() == {"error": "invalid_request", "error_description": ACTION_ID_REQUIRED}

    decision = (await authorize(client, root, target=KB_TOOL, data_class="kb.public")).json()
    retried = await exchange(
        client, root, resource=KB_TOOL, scope="kb.public", action_id=decision["action_id"]
    )
    assert retried.status_code == 200, retried.text


async def test_a_decision_that_never_committed_cannot_buy_a_token(
    sidecar_stack, client, rooted, monkeypatch, db_session
) -> None:
    """Even a decision service that claims a record it did not keep gets nothing dispatched:
    the exchange looks for the committed row, and it is not there."""

    async def _rolled_back(self, db):
        await db.rollback()

    monkeypatch.setattr(AuditService, "_commit", _rolled_back)
    root = rooted["root_grant"]

    claimed = (await authorize(client, root, target=KB_TOOL, data_class="kb.public")).json()
    assert (claimed["outcome"], claimed["recorded"]) == ("allow", True)  # the lie

    r = await exchange(
        client, root, resource=KB_TOOL, scope="kb.public", action_id=claimed["action_id"]
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"
    assert "no recorded allow decision" in r.json()["error_description"]

    sidecar = await sidecar_stack.client()
    blocked = await sidecar.get("/kb/search", headers=_bearer(root))
    assert blocked.status_code == 401
    assert sidecar_stack.recorder.count == 0
    assert await _audit_rows(db_session) == 0
