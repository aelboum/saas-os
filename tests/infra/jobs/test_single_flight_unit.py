"""`saas_os.infra.jobs.single_flight` and the system jobs that use it: their
synchronous database work runs in a thread, one run at a time per worker
process, so the worker's event loop keeps starting other jobs meanwhile.

Why: on the event loop, a walk over every tenant stalled every other job of
the worker for the whole run (the audit digest: about 93 s for 6124 tenants
on a local test database, 2026-11-16; ledger, `docs/P-ROADMAP.md`)."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable, Coroutine, Iterator
from types import ModuleType

import pytest

from saas_os.control_plane.inference import attempt_retention_jobs
from saas_os.core.audit_identity import jobs as audit_identity_jobs
from saas_os.core.identity import session_retention
from saas_os.infra.jobs import SystemJobContext, single_flight
from saas_os.infra.jobs.context import JobActor
from saas_os.infra.jobs.single_flight import run_in_thread_once

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _no_run_in_progress(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(single_flight, "_running", {})
    yield


# --- The helper ----------------------------------------------------------------


async def test_the_work_runs_in_a_thread_and_the_loop_keeps_running() -> None:
    threads: list[int] = []

    def work() -> None:
        threads.append(threading.get_ident())
        time.sleep(0.5)

    ticks = 0

    async def other_job() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    ticker = asyncio.create_task(other_job())
    try:
        assert await run_in_thread_once("k", work) is True
    finally:
        ticker.cancel()
    assert threads and threads[0] != threading.get_ident()
    assert ticks >= 10


async def test_a_second_run_under_the_same_key_is_skipped_until_the_first_ends() -> None:
    release = threading.Event()
    calls = 0

    def work() -> None:
        nonlocal calls
        calls += 1
        release.wait(5)

    first = asyncio.create_task(run_in_thread_once("k", work))
    while calls == 0:
        await asyncio.sleep(0.01)
    assert await run_in_thread_once("k", work) is False
    assert calls == 1
    release.set()
    assert await first is True
    assert await run_in_thread_once("k", work) is True
    assert calls == 2


async def test_different_keys_do_not_block_each_other() -> None:
    release = threading.Event()
    started: list[str] = []

    def blocked() -> None:
        started.append("a")
        release.wait(5)

    def quick() -> None:
        started.append("b")

    first = asyncio.create_task(run_in_thread_once("a", blocked))
    while not started:
        await asyncio.sleep(0.01)
    assert await run_in_thread_once("b", quick) is True
    release.set()
    await first
    assert started == ["a", "b"]


async def test_a_cancelled_caller_leaves_its_thread_running_and_blocks_a_second_run() -> None:
    release = threading.Event()
    finished = threading.Event()
    calls = 0

    def work() -> None:
        nonlocal calls
        calls += 1
        release.wait(5)
        finished.set()

    caller = asyncio.create_task(run_in_thread_once("k", work))
    while calls == 0:
        await asyncio.sleep(0.01)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert await run_in_thread_once("k", work) is False
    assert not finished.is_set()
    release.set()
    await single_flight._running["k"]
    assert finished.is_set()
    assert await run_in_thread_once("k", work) is True
    assert calls == 2


async def test_an_exception_is_raised_to_the_caller_and_the_key_is_free_again() -> None:
    def failing() -> None:
        raise RuntimeError("database unavailable")

    with pytest.raises(RuntimeError, match="database unavailable"):
        await run_in_thread_once("k", failing)
    assert await run_in_thread_once("k", lambda: None) is True


# --- The system jobs -----------------------------------------------------------

_Job = Callable[[SystemJobContext], Coroutine[None, None, None]]

_JOBS: list[tuple[str, ModuleType, str, _Job, str]] = [
    (
        "session_cleanup",
        session_retention,
        "_cleanup_once",
        session_retention._cleanup_expired_sessions_job,
        "session_cleanup_skipped",
    ),
    (
        "ai_attempt_retention",
        attempt_retention_jobs,
        "_purge_once",
        attempt_retention_jobs._purge_expired_ai_attempts_job,
        "ai_attempt_retention_skipped",
    ),
    (
        "audit_identity_expiry_report",
        audit_identity_jobs,
        "_report_once",
        audit_identity_jobs._report_audit_identity_expiry_job,
        "audit_identity_expiry_report_skipped",
    ),
]


@pytest.mark.parametrize(("key", "module", "body", "job", "skipped_event"), _JOBS)
async def test_the_job_runs_its_work_in_a_thread_and_skips_an_overlapping_run(
    key: str,
    module: ModuleType,
    body: str,
    job: _Job,
    skipped_event: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    release = threading.Event()
    threads: list[int] = []

    def blocked(*args: object) -> None:
        threads.append(threading.get_ident())
        release.wait(5)

    monkeypatch.setattr(module, body, blocked)
    # The context the worker gives a system job (the AI job converts its
    # actor before the thread starts and refuses a missing one).
    context = SystemJobContext(system_actor=JobActor(kind="worker_job", name=key))
    first = asyncio.create_task(job(context))
    deadline = time.monotonic() + 5
    while not threads:
        if first.done():
            first.result()  # raises the job's own error instead of waiting
        assert time.monotonic() < deadline, "the job never reached its thread"
        await asyncio.sleep(0.01)
    assert threads[0] != threading.get_ident()
    assert key in single_flight._running

    with caplog.at_level(logging.INFO, logger=module.__name__):
        await job(context)
    assert len(threads) == 1
    assert [r.getMessage() for r in caplog.records if r.name == module.__name__] == [skipped_event]

    release.set()
    await first
