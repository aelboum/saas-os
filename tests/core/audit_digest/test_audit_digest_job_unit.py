"""ADR-0053 -- the `_audit_digest_cycle` job runs the synchronous digest in a
thread, one run at a time per worker process, without a database (the
digest itself is replaced).

Why: `digest_settled_windows()` reads every tenant in its own transaction.
On the worker's event loop, an installation with thousands of tenants
stalled every other job of the worker for the whole run (about 93 s for
6124 tenants, measured on a local test database on 2026-11-16)."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable, Iterator

import pytest

from saas_os.core.audit_digest import jobs as digest_jobs
from saas_os.core.audit_digest.service import DigestRun
from saas_os.infra.jobs import SystemJobContext, single_flight

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _no_run_in_progress(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(single_flight, "_running", {})
    yield


def _replace_digest(monkeypatch: pytest.MonkeyPatch, digest: Callable[[], DigestRun]) -> None:
    monkeypatch.setattr(digest_jobs, "digest_settled_windows", digest)


async def test_the_digest_runs_in_a_thread_not_on_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    threads: list[int] = []

    def digest() -> DigestRun:
        threads.append(threading.get_ident())
        return DigestRun()

    _replace_digest(monkeypatch, digest)
    await digest_jobs._audit_digest_cycle(SystemJobContext())
    assert len(threads) == 1
    assert threads[0] != threading.get_ident()


async def test_the_event_loop_keeps_running_other_work_during_a_slow_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow_digest() -> DigestRun:
        time.sleep(0.5)
        return DigestRun()

    _replace_digest(monkeypatch, slow_digest)
    ticks = 0

    async def other_job() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    ticker = asyncio.create_task(other_job())
    try:
        await digest_jobs._audit_digest_cycle(SystemJobContext())
    finally:
        ticker.cancel()
    # On the event loop the ticker could not run at all while the digest
    # slept; in a thread it runs about fifty times in 0.5 s.
    assert ticks >= 10


async def test_a_run_that_starts_while_one_is_in_progress_is_skipped_and_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    release = threading.Event()
    calls = 0

    def blocked_digest() -> DigestRun:
        nonlocal calls
        calls += 1
        release.wait(5)
        return DigestRun()

    _replace_digest(monkeypatch, blocked_digest)
    first = asyncio.create_task(digest_jobs._audit_digest_cycle(SystemJobContext()))
    while calls == 0:
        await asyncio.sleep(0.01)

    with caplog.at_level(logging.INFO, logger=digest_jobs.__name__):
        await digest_jobs._audit_digest_cycle(SystemJobContext())
    assert calls == 1
    assert [r.getMessage() for r in caplog.records] == ["audit_digest_cycle_skipped"]

    release.set()
    await first
    await digest_jobs._audit_digest_cycle(SystemJobContext())
    assert calls == 2


async def test_a_cancelled_run_keeps_its_thread_and_no_second_run_starts_beside_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The handler timeout cancels the job's coroutine; the thread cannot be
    stopped, so the run it started stays the one in progress until it ends."""
    release = threading.Event()
    calls = 0
    finished = threading.Event()

    def blocked_digest() -> DigestRun:
        nonlocal calls
        calls += 1
        release.wait(5)
        finished.set()
        return DigestRun()

    _replace_digest(monkeypatch, blocked_digest)
    job = asyncio.create_task(digest_jobs._audit_digest_cycle(SystemJobContext()))
    while calls == 0:
        await asyncio.sleep(0.01)
    job.cancel()
    with pytest.raises(asyncio.CancelledError):
        await job

    await digest_jobs._audit_digest_cycle(SystemJobContext())
    assert calls == 1 and not finished.is_set()

    release.set()
    running = single_flight._running["audit_digest_cycle"]
    await running
    assert finished.is_set()
    await digest_jobs._audit_digest_cycle(SystemJobContext())
    assert calls == 2


async def test_a_failing_digest_fails_the_job_and_does_not_block_the_next_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failing_digest() -> DigestRun:
        raise RuntimeError("database unavailable")

    _replace_digest(monkeypatch, failing_digest)
    with pytest.raises(RuntimeError, match="database unavailable"):
        await digest_jobs._audit_digest_cycle(SystemJobContext())

    calls = 0

    def digest() -> DigestRun:
        nonlocal calls
        calls += 1
        return DigestRun()

    _replace_digest(monkeypatch, digest)
    await digest_jobs._audit_digest_cycle(SystemJobContext())
    assert calls == 1


async def test_a_run_that_digests_windows_logs_its_count(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def digest() -> DigestRun:
        run = DigestRun()
        run.records.append({"window": "w"})
        return run

    _replace_digest(monkeypatch, digest)
    with caplog.at_level(logging.INFO, logger=digest_jobs.__name__):
        await digest_jobs._audit_digest_cycle(SystemJobContext())
    completed = [r for r in caplog.records if r.getMessage() == "audit_digest_cycle_completed"]
    assert len(completed) == 1
    assert completed[0].__dict__["windows"] == 1
