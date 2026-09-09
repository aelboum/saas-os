"""P2.1: `infra/jobs`'s worker-side observability -- payload repr safety,
producer-to-worker correlation capture, and the structured job lifecycle
log lines `_with_retry_and_dead_letter` now emits. No Redis needed (the
same fake-pool style as `test_queue_retry.py`).
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest
from arq import Retry
from infra.jobs.config import JobsConfig
from infra.jobs.payload import TenantJobPayload
from infra.jobs.queue import _with_retry_and_dead_letter, build_worker, enqueue_job, register_job

from infra.observability import (
    CorrelationContext,
    bind_correlation_context,
    get_correlation_context,
)

if TYPE_CHECKING:
    from arq import ArqRedis
    from tests.infra.jobs.conftest import FakeRedisPool

pytestmark = pytest.mark.anyio

_CONFIG = JobsConfig(
    redis_url="redis://localhost:6379/0", max_tries=3, retry_backoff_base_seconds=1.0
)


# --- Payload -----------------------------------------------------------------


def test_payload_repr_never_includes_its_data() -> None:
    payload = TenantJobPayload(
        tenant_id="t1",
        data={"recipient_email": "person@example.com", "body": "confidential-body"},
    )
    text = repr(payload)
    assert "t1" in text
    assert "person@example.com" not in text
    assert "confidential-body" not in text
    assert "recipient_email" not in text


def test_payload_correlation_id_is_optional_and_defaults_to_none() -> None:
    assert TenantJobPayload(tenant_id="t1").correlation_id is None
    assert TenantJobPayload(tenant_id="t1", correlation_id="req-1").correlation_id == "req-1"


# --- enqueue_job() correlation capture ---------------------------------------


async def test_enqueue_captures_the_ambient_request_id(fake_redis_pool: FakeRedisPool) -> None:
    with bind_correlation_context(request_id="req-from-http"):
        await enqueue_job(
            "sample_job", TenantJobPayload(tenant_id="t1"), pool=cast("ArqRedis", fake_redis_pool)
        )
    _name, enqueued = fake_redis_pool.enqueued[0]
    assert isinstance(enqueued, TenantJobPayload)
    assert enqueued.correlation_id == "req-from-http"
    assert enqueued.tenant_id == "t1"


async def test_enqueue_never_overwrites_an_explicit_correlation_id(
    fake_redis_pool: FakeRedisPool,
) -> None:
    with bind_correlation_context(request_id="ambient"):
        await enqueue_job(
            "sample_job",
            TenantJobPayload(tenant_id="t1", correlation_id="explicit"),
            pool=cast("ArqRedis", fake_redis_pool),
        )
    _name, enqueued = fake_redis_pool.enqueued[0]
    assert isinstance(enqueued, TenantJobPayload)
    assert enqueued.correlation_id == "explicit"


async def test_enqueue_without_ambient_context_passes_the_payload_unchanged(
    fake_redis_pool: FakeRedisPool,
) -> None:
    payload = TenantJobPayload(tenant_id="t1")
    await enqueue_job("sample_job", payload, pool=cast("ArqRedis", fake_redis_pool))
    _name, enqueued = fake_redis_pool.enqueued[0]
    assert enqueued is payload
    assert cast(TenantJobPayload, enqueued).correlation_id is None


# --- Worker-side correlation binding -----------------------------------------


async def test_wrapper_binds_tenant_and_request_id_for_the_handler_only() -> None:
    seen: list[CorrelationContext] = []

    async def _handler(payload: object) -> str:
        seen.append(get_correlation_context())
        return "ok"

    wrapped = _with_retry_and_dead_letter(_handler, config=_CONFIG)
    payload = TenantJobPayload(tenant_id="t9", correlation_id="req-9")
    assert await wrapped({"job_try": 1, "job_id": "job-9"}, payload) == "ok"

    context = seen[0]
    assert context.tenant_id == "t9"
    assert context.request_id == "req-9"
    # Restored once the job is done -- nothing leaks into the next job.
    assert get_correlation_context().tenant_id is None
    assert get_correlation_context().request_id is None


async def test_wrapper_tolerates_a_pre_p21_payload_without_correlation_id() -> None:
    seen: list[CorrelationContext] = []

    async def _handler(payload: object) -> None:
        seen.append(get_correlation_context())

    wrapped = _with_retry_and_dead_letter(_handler, config=_CONFIG)
    legacy_payload = SimpleNamespace(tenant_id="t-legacy", data={})
    await wrapped({"job_try": 1, "job_id": "job-legacy"}, legacy_payload)  # type: ignore[arg-type]
    assert seen[0].tenant_id == "t-legacy"
    assert seen[0].request_id is None


async def test_wrapper_tolerates_a_none_payload_and_a_ctx_without_job_id() -> None:
    async def _handler(payload: object) -> str:
        return "ok"

    wrapped = _with_retry_and_dead_letter(_handler, config=_CONFIG)
    assert await wrapped({"job_try": 1}, None) == "ok"


# --- Structured lifecycle logs: identifiers only ----------------------------


async def test_success_logs_started_and_succeeded_with_identifiers_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _handler(payload: object) -> str:
        return "result-with-secret-body"

    wrapped = _with_retry_and_dead_letter(_handler, config=_CONFIG)
    payload = TenantJobPayload(tenant_id="t1", data={"body": "secret-body"})
    with caplog.at_level(logging.INFO, logger="infra.jobs.queue"):
        await wrapped({"job_try": 1, "job_id": "job-1"}, payload)

    messages = [r.getMessage() for r in caplog.records]
    assert messages == ["job_started", "job_succeeded"]
    for record in caplog.records:
        assert record.job_function == "_handler"  # type: ignore[attr-defined]
        assert record.job_id == "job-1"  # type: ignore[attr-defined]
        assert record.job_try == 1  # type: ignore[attr-defined]
    assert "secret-body" not in caplog.text
    assert "result-with-secret-body" not in caplog.text


async def test_retry_log_carries_error_type_never_the_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _handler(payload: object) -> None:
        raise RuntimeError("smtp password=hunter2 rejected")

    wrapped = _with_retry_and_dead_letter(_handler, config=_CONFIG)
    with caplog.at_level(logging.INFO, logger="infra.jobs.queue"):
        with pytest.raises(Retry):
            await wrapped({"job_try": 1, "job_id": "job-2"}, TenantJobPayload(tenant_id="t1"))

    retry_records = [r for r in caplog.records if r.getMessage() == "job_retry_scheduled"]
    assert len(retry_records) == 1
    assert retry_records[0].job_error_type == "RuntimeError"  # type: ignore[attr-defined]
    assert retry_records[0].job_retry_defer_seconds == 1.0  # type: ignore[attr-defined]
    assert "hunter2" not in caplog.text


async def test_dead_letter_log_carries_error_type_never_the_message(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis_pool: FakeRedisPool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _fake_get_redis_pool(config: object = None) -> FakeRedisPool:
        return fake_redis_pool

    monkeypatch.setattr("infra.jobs.queue.get_redis_pool", _fake_get_redis_pool)

    async def _handler(payload: object) -> None:
        raise RuntimeError("token=abc123 expired")

    wrapped = _with_retry_and_dead_letter(_handler, config=_CONFIG)
    with caplog.at_level(logging.INFO, logger="infra.jobs.queue"):
        with pytest.raises(Exception, match="dead-lettered"):
            await wrapped({"job_try": 3, "job_id": "job-3"}, TenantJobPayload(tenant_id="t1"))

    dead = [r for r in caplog.records if r.getMessage() == "job_dead_lettered"]
    assert len(dead) == 1
    assert dead[0].job_error_type == "RuntimeError"  # type: ignore[attr-defined]
    assert "abc123" not in caplog.text


# --- build_worker() passthrough ----------------------------------------------


async def _noop(payload: object) -> None:
    return None


def test_build_worker_passes_the_health_check_interval_through() -> None:
    functions = [register_job(_noop, config=_CONFIG)]
    worker = build_worker(functions, config=_CONFIG, health_check_interval_seconds=15)
    assert worker.health_check_interval == 15


def test_build_worker_keeps_arqs_default_interval_when_not_given() -> None:
    worker = build_worker([register_job(_noop, config=_CONFIG)], config=_CONFIG)
    assert worker.health_check_interval == 3600
