"""Run a system job's synchronous work in a thread, one run at a time per
worker process.

A system job whose work is synchronous database access (a walk over every
tenant, batched deletes) must not run it on the worker's event loop: for
the length of the run no other job of the worker would start. This module
runs the work with `asyncio.to_thread`, as the email consumer does.

One run per key at a time in this process: a run that starts while the
previous one under the same key is still in its thread is skipped (the
caller logs it), so slow runs do not pile up threads in the shared
executor. The run in progress is a task awaited through `asyncio.shield`,
so a job the handler timeout cancels leaves its thread to finish (a thread
cannot be stopped) and no second run starts beside it until it has.

This guards one worker process only. Work that two worker processes may
run at once must stay safe for that on its own, as it already had to be.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

_running: dict[str, asyncio.Task[None]] = {}


async def run_in_thread_once(key: str, work: Callable[[], None]) -> bool:
    """Run `work` in a thread and wait for it. Returns `False`, without
    running it, when a previous run under `key` is still in progress in
    this process; `True` once it has run. An exception `work` raises is
    raised here."""
    loop = asyncio.get_running_loop()
    previous = _running.get(key)
    if previous is not None and not previous.done() and previous.get_loop() is loop:
        return False
    task = loop.create_task(asyncio.to_thread(work))
    _running[key] = task
    await asyncio.shield(task)
    return True
