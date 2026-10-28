"""An operator can search the decision history (T055, US4, FR-016–FR-019, SC-011).

Seeds 60 decisions across 3 sessions, 4 agents, both outcomes, both target kinds and two
hours, then checks every filter alone and every pairwise combination against a Python-side
expectation — paging through small pages so the cursor is exercised on every query.
"""

from __future__ import annotations

import itertools
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jsonschema
import pytest

from app.repositories import audit_decisions as audit_repo
from app.services.audit_cursor import encode_cursor
from tests.fixtures.contracts import component_schema

AGENTS = ["orchestrator", "kb-search", "summarizer", "notifier"]
BASE = datetime(2026, 9, 13, 8, 0, tzinfo=UTC)
CONTRACT = "audit-plane.openapi.yaml"


@dataclass(frozen=True)
class Seeded:
    id: str
    session_id: str
    acting_agent: str
    outcome: str
    deny_reason: str | None
    enforced: bool
    target_kind: str
    ts: datetime


async def _append(db_session, *, session_id: str, index: int, ts: datetime) -> Seeded:
    outcome = "deny" if index % 3 == 0 else "allow"
    deny_reason = ("EDGE_NOT_IN_DAG", "OUT_OF_SCOPE")[index % 2] if outcome == "deny" else None
    enforced = not (outcome == "deny" and index % 2 == 0)
    target = "agent://summarizer" if index % 2 else "mcp://kb.internal/search"
    row = await audit_repo.append(
        db_session,
        action_id=uuid.uuid4(),
        ts=ts,
        session_id=uuid.UUID(session_id),
        caller="user:alice",
        target=target,
        data_class="kb.internal",
        hop=1,
        outcome=outcome,
        deny_reason=deny_reason,
        recoverable=False,
        enforced=enforced,
        taint=None,
        taint_source=None,
        privileged=False,
        policy_version=1,
        act_chain=["user:alice"],
        acting_agent=AGENTS[index % 4],
        subject_jti=None,
        parent_action_id=None,
        chain=None,
        chain_complete=False,
        chain_break="LEGACY_TOKEN",
    )
    return Seeded(
        id=str(row.id),
        session_id=session_id,
        acting_agent=AGENTS[index % 4],
        outcome=outcome,
        deny_reason=deny_reason,
        enforced=enforced,
        target_kind="agent" if target.startswith("agent://") else "tool",
        ts=ts,
    )


@pytest.fixture
async def seeded(register_chain, consent, db_session) -> dict:
    await register_chain()
    sessions = [(await consent())["session_id"] for _ in range(3)]
    rows = [
        await _append(
            db_session, session_id=sessions[i % 3], index=i, ts=BASE + timedelta(minutes=2 * i)
        )
        for i in range(60)
    ]
    await db_session.commit()
    return {"sessions": sessions, "newest_first": list(reversed(rows))}


async def fetch_all(client, headers, params: dict, *, limit: int = 7) -> tuple[list[str], set]:
    ids: list[str] = []
    marks: set = set()
    cursor = None
    while True:
        query = {**params, "limit": limit, **({"cursor": cursor} if cursor else {})}
        r = await client.get("/v1/audit/decisions", headers=headers, params=query)
        assert r.status_code == 200, r.text
        body = r.json()
        ids += [row["id"] for row in body["data"]]
        marks.add(body["page"]["as_of_seq"])
        cursor = body["page"]["next_cursor"]
        if not cursor:
            return ids, marks


def _matches(row: Seeded, params: dict) -> bool:
    checks = {
        "session_id": lambda v: row.session_id == v,
        "agent": lambda v: row.acting_agent == v,
        "outcome": lambda v: row.outcome == v,
        "deny_reason": lambda v: row.deny_reason == v,
        "enforced": lambda v: str(row.enforced).lower() == v,
        "target_kind": lambda v: row.target_kind == v,
        "since": lambda v: row.ts >= datetime.fromisoformat(v),
        "until": lambda v: row.ts <= datetime.fromisoformat(v),
    }
    return all(checks[key](value) for key, value in params.items())


# -- filters ----------------------------------------------------------------------


async def test_every_filter_alone_and_in_pairs_returns_exactly_the_expected_rows(
    client, admin_headers, seeded
) -> None:
    values = {
        "session_id": seeded["sessions"][1],
        "agent": "kb-search",
        "outcome": "deny",
        "deny_reason": "EDGE_NOT_IN_DAG",
        "enforced": "false",
        "target_kind": "tool",
        "since": (BASE + timedelta(minutes=30)).isoformat(),
        "until": (BASE + timedelta(minutes=90)).isoformat(),
    }
    combinations = [(key,) for key in values] + list(itertools.combinations(values, 2))

    for keys in [(), *combinations]:
        params = {key: values[key] for key in keys}
        expected = [row.id for row in seeded["newest_first"] if _matches(row, params)]

        ids, marks = await fetch_all(client, admin_headers, params)

        assert ids == expected, f"filters {params}"
        assert len(marks) == 1, f"high-water mark moved during iteration for {params}"


async def test_a_filter_that_matches_nothing_is_an_empty_page(
    client, admin_headers, seeded
) -> None:
    r = await client.get("/v1/audit/decisions", headers=admin_headers, params={"agent": "nobody"})
    assert r.status_code == 200
    body = r.json()
    assert body["data"] == []
    assert body["page"]["next_cursor"] is None


async def test_an_empty_history_has_no_high_water_mark(client, admin_headers) -> None:
    r = await client.get("/v1/audit/decisions", headers=admin_headers)
    assert r.status_code == 200
    assert r.json() == {"data": [], "page": {"next_cursor": None, "limit": 20, "as_of_seq": None}}


async def test_a_page_matches_the_published_contract(client, admin_headers, seeded) -> None:
    schema = component_schema(CONTRACT, "AuditDecisionPage")

    r = await client.get("/v1/audit/decisions", headers=admin_headers, params={"limit": 5})

    jsonschema.Draft202012Validator(schema).validate(r.json())


# -- paging stability ---------------------------------------------------------------


async def test_paging_is_stable_while_decisions_keep_arriving(
    client, admin_headers, seeded, db_session
) -> None:
    expected = [row.id for row in seeded["newest_first"]]

    first = await client.get("/v1/audit/decisions", headers=admin_headers, params={"limit": 2})
    body = first.json()
    ids = [row["id"] for row in body["data"]]
    mark = body["page"]["as_of_seq"]
    cursor = body["page"]["next_cursor"]

    # Twenty newer decisions land mid-iteration.
    for i in range(20):
        await _append(
            db_session,
            session_id=seeded["sessions"][0],
            index=i,
            ts=BASE + timedelta(hours=5, minutes=i),
        )
    await db_session.commit()

    while cursor:
        r = await client.get(
            "/v1/audit/decisions", headers=admin_headers, params={"limit": 2, "cursor": cursor}
        )
        page = r.json()
        assert page["page"]["as_of_seq"] == mark
        ids += [row["id"] for row in page["data"]]
        cursor = page["page"]["next_cursor"]

    assert ids == expected  # every pre-existing row exactly once, none of the new ones

    fresh, _ = await fetch_all(client, admin_headers, {}, limit=100)
    assert len(fresh) == 80  # a new iteration sees them


# -- validation and access ---------------------------------------------------------


@pytest.mark.parametrize(
    ("params", "field"),
    [
        ({"since": "2026-09-13T10:00:00Z", "until": "2026-09-13T09:00:00Z"}, "since"),
        ({"since": "2026-09-13T10:00:00"}, "since"),  # no timezone
        ({"since": "yesterday"}, "since"),
        ({"outcome": "maybe"}, "outcome"),
        ({"target_kind": "robot"}, "target_kind"),
        ({"deny_reason": "NOT_A_REASON"}, "deny_reason"),
        ({"enforced": "sometimes"}, "enforced"),
        ({"session_id": "not-a-uuid"}, "session_id"),
        ({"cursor": "garbage"}, "cursor"),
        (
            {"cursor": encode_cursor(before=5, hwm=2)},  # well-formed, but past its own mark
            "cursor",
        ),
        ({"limit": "0"}, "limit"),
    ],
)
async def test_an_invalid_query_names_the_parameter(client, admin_headers, params, field) -> None:
    r = await client.get("/v1/audit/decisions", headers=admin_headers, params=params)

    assert r.status_code == 422, r.text
    error = r.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"]["fields"][0]["loc"] == ["query", field]


async def test_the_history_requires_an_audit_reader(client) -> None:
    r = await client.get("/v1/audit/decisions")
    assert r.status_code == 401
    assert "data" not in r.json()


async def test_the_phase_2_report_is_a_deprecated_alias_over_the_same_history(
    client, admin_headers, seeded
) -> None:
    denies = [row.id for row in seeded["newest_first"] if row.outcome == "deny"]

    r = await client.get(
        "/v1/decisions", headers=admin_headers, params={"outcome": "deny", "limit": 100}
    )

    assert r.status_code == 200
    assert [row["id"] for row in r.json()["data"]] == denies
    spec = (await client.get("/openapi.json")).json()
    assert spec["paths"]["/v1/decisions"]["get"]["deprecated"] is True
