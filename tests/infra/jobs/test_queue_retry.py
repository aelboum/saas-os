"""`infra/jobs`'s retry/dead-letter decision logic (docs/IMPLEMENTATION-
ROADMAP.md Phase 2.4, docs/ADR/0007-background-job-and-workflow-engine.md).

Exercises `_with_retry_and_dead_letter` directly (the wrapper `register_job`
attaches to every job function) rather than through a real arq `Worker`,
so these stay independent of a real Redis instance -- the literal
end-to-end behavior (enqueue -> real worker -> retries -> dead-letters) is
covered separately by `test_jobs_integration.py` (marked `integration`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from arq import Retry
from infra.jobs.config import JobsConfig
from infra.jobs.errors import JobDeadLetteredError
from infra.jobs.queue import _with_retry_and_dead_letter, register_job

if TYPE_CHECKING:
    from tests.infra.jobs.conftest import FakeRedisPool

pytestmark = pytest.mark.anyio

_CONFIG = JobsConfig(
    redis_url="redis://localhost:6379/0", max_tries=3, retry_backoff_base_seconds=1.0
)


async def _always_fails(payload: object) -> None:
    raise RuntimeError("simulated job failure")


async def _always_succeeds(payload: object) -> str:
    return "ok"


async def test_wrapped_returns_handler_result_on_success() -> None:
    wrapped = _with_retry_and_dead_letter(_always_succeeds, config=_CONFIG)
    result = await wrapped({"job_try": 1}, None)
    assert result == "ok"


async def test_wrapped_raises_retry_when_attempts_remain() -> None:
    wrapped = _with_retry_and_dead_letter(_always_fails, config=_CONFIG)
    with pytest.raises(Retry) as excinfo:
        await wrapped({"job_try": 1}, None)
    assert excinfo.value.defer_score is not None


async def test_retry_defer_grows_with_each_attempt() -> None:
    wrapped = _with_retry_and_dead_letter(_always_fails, config=_CONFIG)
    with pytest.raises(Retry) as first:
        await wrapped({"job_try": 1}, None)
    with pytest.raises(Retry) as second:
        await wrapped({"job_try": 2}, None)
    assert first.value.defer_score is not None
    assert second.value.defer_score is not None
    assert second.value.defer_score > first.value.defer_score


async def test_wrapped_dead_letters_on_final_attempt(
    monkeypatch: pytest.MonkeyPatch, fake_redis_pool: FakeRedisPool
) -> None:
    async def _fake_get_redis_pool(config: object = None) -> FakeRedisPool:
        return fake_redis_pool

    monkeypatch.setattr("infra.jobs.queue.get_redis_pool", _fake_get_redis_pool)

    wrapped = _with_retry_and_dead_letter(_always_fails, config=_CONFIG)
    with pytest.raises(JobDeadLetteredError) as excinfo:
        await wrapped({"job_try": 3}, None)  # max_tries=3 -- this is the final attempt

    assert excinfo.value.function_name == "_always_fails"
    assert excinfo.value.attempts == 3
    assert fake_redis_pool.closed
    assert len(fake_redis_pool.lists.get(_CONFIG.dead_letter_key, [])) == 1


async def test_wrapped_does_not_dead_letter_before_attempts_are_exhausted(
    monkeypatch: pytest.MonkeyPatch, fake_redis_pool: FakeRedisPool
) -> None:
    async def _fake_get_redis_pool(config: object = None) -> FakeRedisPool:
        return fake_redis_pool

    monkeypatch.setattr("infra.jobs.queue.get_redis_pool", _fake_get_redis_pool)

    wrapped = _with_retry_and_dead_letter(_always_fails, config=_CONFIG)
    with pytest.raises(Retry):
        await wrapped({"job_try": 1}, None)
    with pytest.raises(Retry):
        await wrapped({"job_try": 2}, None)

    assert fake_redis_pool.lists.get(_CONFIG.dead_letter_key, []) == []


async def test_wrapped_preserves_original_exception_as_cause(
    monkeypatch: pytest.MonkeyPatch, fake_redis_pool: FakeRedisPool
) -> None:
    async def _fake_get_redis_pool(config: object = None) -> FakeRedisPool:
        return fake_redis_pool

    monkeypatch.setattr("infra.jobs.queue.get_redis_pool", _fake_get_redis_pool)

    wrapped = _with_retry_and_dead_letter(_always_fails, config=_CONFIG)
    with pytest.raises(JobDeadLetteredError) as excinfo:
        await wrapped({"job_try": 3}, None)

    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert str(excinfo.value.__cause__) == "simulated job failure"


def test_register_job_pins_arq_max_tries_to_the_configured_policy() -> None:
    registered = register_job(_always_succeeds, config=_CONFIG)
    assert registered.name == "_always_succeeds"
    assert registered.max_tries == _CONFIG.max_tries
