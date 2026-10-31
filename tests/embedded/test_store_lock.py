"""One process at a time may hold a durable store (the "two processes, one store" edge case).

The lock is an OS advisory lock, released by the OS when its holder exits, so a crashed
process can never leave a store locked for good.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import sys

import pytest

from agentic_auth.embedded import EmbeddedControlPlane, StoreLocked

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="fork-based holder process")


def _hold(path: str, ready, release) -> None:
    async def run() -> None:
        async with EmbeddedControlPlane.open(store=path):
            ready.set()
            await asyncio.get_running_loop().run_in_executor(None, release.wait)

    asyncio.run(run())


async def test_a_second_process_is_refused_and_named(tmp_path) -> None:
    store = tmp_path / "auth.db"
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    holder = ctx.Process(target=_hold, args=(str(store), ready, release))
    holder.start()
    try:
        assert await asyncio.get_running_loop().run_in_executor(None, ready.wait, 30)
        with pytest.raises(StoreLocked) as exc:
            async with EmbeddedControlPlane.open(store=store):
                pass
        assert exc.value.pid == holder.pid
        assert str(holder.pid) in str(exc.value)
    finally:
        release.set()
        holder.join(30)

    # Released on exit: the store opens again.
    async with EmbeddedControlPlane.open(store=store):
        pass


async def test_a_crashed_holder_leaves_no_lock_behind(tmp_path) -> None:
    store = tmp_path / "auth.db"
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    holder = ctx.Process(target=_hold, args=(str(store), ready, release))
    holder.start()
    assert await asyncio.get_running_loop().run_in_executor(None, ready.wait, 30)
    os.kill(holder.pid, 9)
    holder.join(30)

    async with EmbeddedControlPlane.open(store=store):
        pass
