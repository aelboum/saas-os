"""Review of #197: a handler error that says a retry could repeat an
external effect (`NonRetriableJobError`) is dead-lettered by the job wrapper
at once, never retried with `arq.Retry`. The outbox's
`AmbiguousOutcomeError` subclasses it, so an ambiguous e-mail sent by a
directly queued job (no outbox event) is not sent again by the job's own
retry. Unit level: the wrapper is called directly against a fake Redis pool.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from arq import Retry

from saas_os.infra.jobs import queue as jobs_queue
from saas_os.infra.jobs.config import JobsConfig
from saas_os.infra.jobs.context import JobKind
from saas_os.infra.jobs.errors import JobDeadLetteredError, NonRetriableJobError
from saas_os.infra.jobs.queue import (
    _with_retry_and_dead_letter,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from tests.infra.jobs.conftest import FakeRedisPool

pytestmark = pytest.mark.anyio

_CONFIG = JobsConfig(
    redis_url="redis://localhost:6379/0", max_tries=3, retry_backoff_base_seconds=1.0
)


@pytest.fixture
def dead_letters(monkeypatch: pytest.MonkeyPatch, fake_redis_pool: FakeRedisPool) -> FakeRedisPool:
    async def _fake_get_redis_pool(config: object = None) -> FakeRedisPool:
        return fake_redis_pool

    monkeypatch.setattr("saas_os.infra.jobs.queue.get_redis_pool", _fake_get_redis_pool)
    return fake_redis_pool


class _MaySent(NonRetriableJobError):
    """A product-layer error: the request may have been sent."""


class _MaySentButDeduplicated(NonRetriableJobError):
    job_retry_safe = True


def _raising(error: BaseException):  # noqa: ANN202 -- a test handler factory
    calls: list[int] = []

    async def handler(context: object) -> None:
        calls.append(1)
        raise error

    return handler, calls


async def test_a_non_retriable_error_is_dead_lettered_on_its_first_attempt(
    dead_letters: FakeRedisPool, caplog: pytest.LogCaptureFixture
) -> None:
    handler, calls = _raising(_MaySent("may have been sent"))
    wrapped = _with_retry_and_dead_letter(handler, config=_CONFIG, kind=JobKind.SYSTEM)
    with caplog.at_level(logging.ERROR, logger=jobs_queue.logger.name):
        with pytest.raises(JobDeadLetteredError) as excinfo:
            await wrapped({"job_try": 1}, None)  # attempts remain, yet not retried
    assert isinstance(excinfo.value.__cause__, _MaySent)
    assert calls == [1]
    assert len(dead_letters.lists.get(_CONFIG.dead_letter_key, [])) == 1
    assert any(record.getMessage() == "job_not_retried" for record in caplog.records)


async def test_an_instance_that_says_retry_is_safe_keeps_the_retry(
    dead_letters: FakeRedisPool,
) -> None:
    handler, _ = _raising(_MaySentButDeduplicated("receiver de-duplicates"))
    wrapped = _with_retry_and_dead_letter(handler, config=_CONFIG, kind=JobKind.SYSTEM)
    with pytest.raises(Retry):
        await wrapped({"job_try": 1}, None)
    assert dead_letters.lists.get(_CONFIG.dead_letter_key, []) == []


async def test_an_ordinary_error_keeps_the_retry(dead_letters: FakeRedisPool) -> None:
    handler, _ = _raising(RuntimeError("transient"))
    wrapped = _with_retry_and_dead_letter(handler, config=_CONFIG, kind=JobKind.SYSTEM)
    with pytest.raises(Retry):
        await wrapped({"job_try": 1}, None)


async def test_the_outbox_ambiguous_outcome_is_not_retried_by_a_direct_job(
    dead_letters: FakeRedisPool,
) -> None:
    """`AmbiguousOutcomeError` without a policy, or with an idempotency
    window (which a direct job cannot honour: nothing records its first
    attempt), is dead-lettered; `at_least_once` keeps the job's retry."""
    from saas_os.core.outbox import AmbiguousOutcomeError

    no_policy = AmbiguousOutcomeError("data_lost", phase="data")
    window = AmbiguousOutcomeError("read_timeout", phase="read", retry_within=timedelta(hours=1))
    at_least_once = AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True)
    assert isinstance(no_policy, NonRetriableJobError)

    for error in (no_policy, window):
        handler, calls = _raising(error)
        wrapped = _with_retry_and_dead_letter(handler, config=_CONFIG, kind=JobKind.SYSTEM)
        with pytest.raises(JobDeadLetteredError):
            await wrapped({"job_try": 1}, None)
        assert calls == [1]

    handler, _ = _raising(at_least_once)
    wrapped = _with_retry_and_dead_letter(handler, config=_CONFIG, kind=JobKind.SYSTEM)
    with pytest.raises(Retry):
        await wrapped({"job_try": 1}, None)
    assert len(dead_letters.lists.get(_CONFIG.dead_letter_key, [])) == 2
