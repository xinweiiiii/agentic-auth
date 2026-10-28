"""``TaintStore`` against real Redis (US2, T043): one field per (context, action), first
writer's timestamp wins, TTL bounded, unavailable store raises."""

from __future__ import annotations

import pytest

from app.services.taint import SENTINEL, Marked, TaintStore, TaintStoreUnavailable, taint_key


async def test_marks_round_trip_with_their_source_and_deciding_action(redis_client) -> None:
    store = TaintStore(redis_client)
    await store.mark("s1", {"j1", "j2"}, "mcp://kb.internal/search", action_id="a1", ttl_seconds=60)
    marks = await store.marked("s1")
    assert {(m.context, m.source, m.action_id) for m in marks} == {
        ("j1", "mcp://kb.internal/search", "a1"),
        ("j2", "mcp://kb.internal/search", "a1"),
    }
    assert all(m.ts > 0 for m in marks)
    assert Marked.of(marks, "j1").tainted and not Marked.of(marks, "j9").tainted


async def test_a_second_mark_from_the_same_decision_keeps_the_first_timestamp(redis_client) -> None:
    store = TaintStore(redis_client)
    await store.mark("s1", {"j1"}, "src", action_id="a1", ttl_seconds=60)
    first = (await store.marked("s1"))[0].ts
    await store.mark("s1", {"j1"}, "src", action_id="a1", ttl_seconds=60)
    marks = await store.marked("s1")
    assert len(marks) == 1 and marks[0].ts == first


async def test_different_decisions_leave_separate_marks(redis_client) -> None:
    store = TaintStore(redis_client)
    await store.mark("s1", {"j1"}, "first", action_id="a1", ttl_seconds=60)
    await store.mark("s1", {"j1"}, "second", action_id="a2", ttl_seconds=60)
    marks = await store.marked("s1")
    assert {m.action_id for m in marks} == {"a1", "a2"}
    assert Marked.of(marks, "j1", exclude_action_id="a1").source == "second"


async def test_the_sentinel_and_sessions_are_isolated(redis_client) -> None:
    store = TaintStore(redis_client)
    await store.mark("s1", {SENTINEL}, "src", action_id=None, ttl_seconds=60)
    assert Marked.of(await store.marked("s1"), "anyone").tainted
    assert await store.marked("s2") == []


async def test_the_key_expires_with_the_session(redis_client) -> None:
    store = TaintStore(redis_client)
    await store.mark("s1", {"j1"}, "src", action_id="a1", ttl_seconds=45)
    ttl = await redis_client.ttl(taint_key("s1"))
    assert 0 < ttl <= 45
    await store.mark(
        "s1", {"j2"}, "src", action_id="a1", ttl_seconds=0
    )  # clamped to 1s, never forever
    assert 0 < await redis_client.pttl(taint_key("s1")) <= 1000


async def test_clear_removes_the_session(redis_client) -> None:
    store = TaintStore(redis_client)
    await store.mark("s1", {"j1"}, "src", action_id="a1", ttl_seconds=60)
    await store.clear("s1")
    assert await store.marked("s1") == []


async def test_a_missing_or_broken_store_raises(redis_client) -> None:
    with pytest.raises(TaintStoreUnavailable):
        await TaintStore(None).marked("s1")
    with pytest.raises(TaintStoreUnavailable):
        await TaintStore(None).mark("s1", {"j"}, "src", action_id="a", ttl_seconds=1)

    class _Broken:
        async def hgetall(self, *_):
            raise ConnectionError("down")

        def pipeline(self, **_):
            raise ConnectionError("down")

    with pytest.raises(TaintStoreUnavailable):
        await TaintStore(_Broken()).marked("s1")
    with pytest.raises(TaintStoreUnavailable):
        await TaintStore(_Broken()).mark("s1", {"j"}, "src", action_id="a", ttl_seconds=1)


async def test_marks_are_written_in_one_atomic_transaction_and_clear_never_raises() -> None:
    calls: dict[str, object] = {}

    class _Pipe:
        def hsetnx(self, *a):
            calls.setdefault("hsetnx", []).append(a)

        def expire(self, *a):
            calls["expire"] = a

        async def execute(self):
            calls["executed"] = True

    class _Redis:
        def pipeline(self, **kwargs):
            calls["pipeline"] = kwargs
            return _Pipe()

        async def delete(self, *_):
            raise ConnectionError("down")

    store = TaintStore(_Redis())
    await store.mark("s1", {"j1"}, "src", action_id="a1", ttl_seconds=30)
    assert calls["pipeline"] == {"transaction": True}
    assert calls["expire"] == ("taint:s1", 30) and calls["executed"] is True
    await store.clear("s1")  # the delete raises; clear swallows it
