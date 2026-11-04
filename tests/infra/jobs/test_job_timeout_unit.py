"""Ledger row F5 (2026-11-01): a job whose handler runs out of time is
dead-lettered, not dropped.

arq ends a job that outlives its timeout by cancelling the coroutine and
finishing the job itself, with no retry and no entry in SaaS OS's
dead-letter list. The wrapper now gives the handler its own deadline
(`HANDLER_TIMEOUT_SECONDS`) below arq's (`ARQ_JOB_TIMEOUT_SECONDS`, passed
explicitly on every function and schedule built here), so a timeout is
caught, logged (`job_timed_out`) and dead-lettered. It is not retried in the
same run: a cancelled handler's thread work may still be running.

Unit level: the wrapper is called directly against a fake Redis pool. The
same behaviour through a real arq worker and Redis is
`tests/infra/jobs/test_job_timeout_integration.py`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import pytest
from arq import Retry

from saas_os.infra.jobs import queue as jobs_queue
from saas_os.infra.jobs.config import JobsConfig
from saas_os.infra.jobs.context import JobKind
from saas_os.infra.jobs.errors import JobDeadLetteredError
from saas_os.infra.jobs.queue import (
    _with_retry_and_dead_letter,  # pyright: ignore[reportPrivateUsage]
    register_system_job,
    register_tenant_job,
    system_cron,
)

if TYPE_CHECKING:
    from tests.infra.jobs.conftest import FakeRedisPool

pytestmark = pytest.mark.anyio

_CONFIG = JobsConfig(
    redis_url="redis://localhost:6379/0", max_tries=3, retry_backoff_base_seconds=1.0
)


@pytest.fixture
def short_deadline(monkeypatch: pytest.MonkeyPatch) -> float:
    monkeypatch.setattr(jobs_queue, "HANDLER_TIMEOUT_SECONDS", 0.05)
    return 0.05


@pytest.fixture
def dead_letters(monkeypatch: pytest.MonkeyPatch, fake_redis_pool: FakeRedisPool) -> FakeRedisPool:
    async def _fake_get_redis_pool(config: object = None) -> FakeRedisPool:
        return fake_redis_pool

    monkeypatch.setattr("saas_os.infra.jobs.queue.get_redis_pool", _fake_get_redis_pool)
    return fake_redis_pool


async def _sleeps_past_the_deadline(context: object) -> str:
    await asyncio.sleep(5)
    return "never"


async def test_a_timed_out_job_is_dead_lettered_on_its_first_attempt(
    short_deadline: float, dead_letters: FakeRedisPool, caplog: pytest.LogCaptureFixture
) -> None:
    wrapped = _with_retry_and_dead_letter(
        _sleeps_past_the_deadline, config=_CONFIG, kind=JobKind.SYSTEM
    )
    with caplog.at_level(logging.ERROR, logger=jobs_queue.logger.name):
        with pytest.raises(JobDeadLetteredError) as excinfo:
            await wrapped({"job_try": 1}, None)  # attempts remain, yet not retried

    assert isinstance(excinfo.value.__cause__, TimeoutError)
    entries = dead_letters.lists.get(_CONFIG.dead_letter_key, [])
    assert len(entries) == 1
    assert "TimeoutError" in str(entries[0])
    assert any(record.getMessage() == "job_timed_out" for record in caplog.records)


async def test_a_timed_out_scheduled_run_is_dead_lettered(
    short_deadline: float, dead_letters: FakeRedisPool
) -> None:
    wrapped = _with_retry_and_dead_letter(
        _sleeps_past_the_deadline, config=_CONFIG, kind=JobKind.SYSTEM, scheduled=True
    )
    with pytest.raises(JobDeadLetteredError):
        await wrapped({"job_try": 1}, None)
    assert len(dead_letters.lists.get(_CONFIG.dead_letter_key, [])) == 1


async def test_a_timeout_the_handler_raises_itself_is_an_ordinary_retryable_failure(
    short_deadline: float, dead_letters: FakeRedisPool
) -> None:
    """Only the wrapper's own deadline counts as a timeout: a `TimeoutError`
    from inside the handler (a client's own timeout) keeps the bounded
    retry it always had."""

    async def _raises_its_own_timeout(context: object) -> None:
        raise TimeoutError("the handler's own client timed out")

    wrapped = _with_retry_and_dead_letter(
        _raises_its_own_timeout, config=_CONFIG, kind=JobKind.SYSTEM
    )
    with pytest.raises(Retry):
        await wrapped({"job_try": 1}, None)
    with pytest.raises(JobDeadLetteredError):
        await wrapped({"job_try": 3}, None)  # final attempt: retry exhausted
    assert len(dead_letters.lists.get(_CONFIG.dead_letter_key, [])) == 1


async def test_a_failure_then_success_still_retries_and_succeeds(
    short_deadline: float, dead_letters: FakeRedisPool
) -> None:
    calls: list[int] = []

    async def _fails_once(context: object) -> str:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("transient")
        return "ok"

    wrapped = _with_retry_and_dead_letter(_fails_once, config=_CONFIG, kind=JobKind.SYSTEM)
    with pytest.raises(Retry):
        await wrapped({"job_try": 1}, None)
    assert await wrapped({"job_try": 2}, None) == "ok"
    assert dead_letters.lists.get(_CONFIG.dead_letter_key, []) == []


async def test_a_handler_within_its_deadline_is_unaffected(dead_letters: FakeRedisPool) -> None:
    async def _quick(context: object) -> str:
        await asyncio.sleep(0)
        return "ok"

    wrapped = _with_retry_and_dead_letter(_quick, config=_CONFIG, kind=JobKind.SYSTEM)
    assert await wrapped({"job_try": 1}, None) == "ok"
    assert dead_letters.lists.get(_CONFIG.dead_letter_key, []) == []


async def _tenant_noop(context: object, payload: object) -> None:
    return None


async def _system_noop_for_timeout_test(context: object) -> None:
    return None


def test_arq_is_given_a_longer_timeout_than_the_handler_on_every_function() -> None:
    """arq's own timeout must never fire first, whatever the worker's
    `job_timeout`: it is set on each function and schedule."""
    assert jobs_queue.ARQ_JOB_TIMEOUT_SECONDS > jobs_queue.HANDLER_TIMEOUT_SECONDS
    tenant = register_tenant_job(_tenant_noop, config=_CONFIG)
    system = register_system_job(_system_noop_for_timeout_test, config=_CONFIG)
    schedule = system_cron(system, every_seconds=60)
    assert tenant.timeout_s == jobs_queue.ARQ_JOB_TIMEOUT_SECONDS
    assert system.timeout_s == jobs_queue.ARQ_JOB_TIMEOUT_SECONDS
    assert schedule.timeout_s == jobs_queue.ARQ_JOB_TIMEOUT_SECONDS


def test_the_handler_deadline_keeps_the_limit_workers_already_had() -> None:
    """300 s is arq's default `job_timeout`, the effective limit before
    this change: no job that used to finish now times out."""
    assert jobs_queue.HANDLER_TIMEOUT_SECONDS == 300.0
