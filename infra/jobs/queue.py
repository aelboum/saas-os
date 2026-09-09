"""`infra/jobs`'s narrow queue/worker interface (docs/IMPLEMENTATION-
ROADMAP.md Phase 2.4, docs/ADR/0007-background-job-and-workflow-engine.md):
enqueue, execute, retry-on-failure, dead-letter -- and nothing else. No
multi-step or compensating-workflow semantics (ADR-0007: that is a future
durable-workflow-engine concern, not this module's).

Retry/backoff/dead-letter is decided by *this module*, not delegated to
arq's own built-in retry bookkeeping: a registered job's arq-level
`max_tries` is set to match `JobsConfig.max_tries` exactly (see
`register_job`), so arq always hands control back to `_with_retry_and_dead_letter`
on the final attempt instead of silently aborting the job itself. That
wrapper then either re-raises `arq.Retry` (more attempts remain) or records
a dead-letter entry and raises `JobDeadLetteredError` (attempts exhausted).

**P2.1 (worker runtime) -- observability, no new mechanism**: the same
wrapper now (a) binds the existing `infra.observability` correlation
context for the duration of each job execution -- `tenant_id` from the
payload, and `request_id` from the payload's `correlation_id` (captured by
`enqueue_job()` from the producer's own ambient context, so a job's log
lines correlate back to the HTTP request that enqueued it) -- and (b)
emits one structured log line per lifecycle event (`job_started`,
`job_succeeded`, `job_retry_scheduled`, `job_dead_lettered`). Every
`extra=` field is an identifier or a count (function name, arq job id,
attempt number, defer seconds, exception *type name*) -- never the
payload, a result, or an exception message, which could echo application
data (docs/SECURITY.md). `infra.observability` is itself `infra`, so this
introduces no new dependency direction.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any

from arq import ArqRedis, Retry, create_pool
from arq.connections import RedisSettings
from arq.typing import WorkerCoroutine
from arq.worker import Function, Worker, func

from infra.jobs.config import JobsConfig, get_jobs_config
from infra.jobs.dead_letter import record_dead_letter
from infra.jobs.errors import InvalidJobPayloadError, JobDeadLetteredError, JobsConfigurationError
from infra.jobs.payload import TenantJobPayload
from infra.observability import bind_correlation_context, get_correlation_context

logger = logging.getLogger(__name__)

JobHandler = Callable[[TenantJobPayload | None], Awaitable[Any]]


def _redis_settings(config: JobsConfig) -> RedisSettings:
    return RedisSettings.from_dsn(config.redis_url)


async def get_redis_pool(config: JobsConfig | None = None) -> ArqRedis:
    """A connected `arq` Redis pool -- the one place this module opens a
    Redis connection (`infra/jobs`'s own execution metadata, docs/DATA-
    ARCHITECTURE.md section 5), built from `JobsConfig.redis_url`.
    """
    return await create_pool(_redis_settings(config or get_jobs_config()))


def _with_retry_and_dead_letter(
    handler: JobHandler, *, config: JobsConfig | None
) -> WorkerCoroutine:
    function_name = handler.__name__

    @functools.wraps(handler)
    async def wrapped(ctx: dict[str, Any], payload: TenantJobPayload | None = None) -> Any:
        cfg = config or get_jobs_config()
        job_try = ctx["job_try"]
        job_id = ctx.get("job_id")
        # `getattr` (not attribute access): a payload pickled by a producer
        # running a pre-P2.1 build has no `correlation_id` attribute at all,
        # and must still execute rather than fail on a metadata field.
        tenant_id = getattr(payload, "tenant_id", None)
        correlation_id = getattr(payload, "correlation_id", None)
        log_fields = {"job_function": function_name, "job_id": job_id, "job_try": job_try}

        with bind_correlation_context(tenant_id=tenant_id, request_id=correlation_id):
            logger.info("job_started", extra=log_fields)
            try:
                result = await handler(payload)
            except Exception as exc:
                if job_try < cfg.max_tries:
                    defer = cfg.retry_backoff_base_seconds * (2 ** (job_try - 1))
                    logger.warning(
                        "job_retry_scheduled",
                        extra={
                            **log_fields,
                            "job_error_type": type(exc).__name__,
                            "job_retry_defer_seconds": defer,
                        },
                    )
                    raise Retry(defer=defer) from exc

                pool = await get_redis_pool(cfg)
                try:
                    await record_dead_letter(
                        pool,
                        cfg,
                        function_name=function_name,
                        payload=payload,
                        error=exc,
                        attempts=job_try,
                    )
                finally:
                    await pool.aclose()
                logger.error(
                    "job_dead_lettered",
                    extra={**log_fields, "job_error_type": type(exc).__name__},
                )
                raise JobDeadLetteredError(function_name, job_try) from exc

            logger.info("job_succeeded", extra=log_fields)
            return result

    return wrapped


def register_job(handler: JobHandler, *, config: JobsConfig | None = None) -> Function:
    """Wrap a plain `async def handler(payload) -> result` into an arq
    `Function` with this module's retry/dead-letter policy attached, and
    arq's own per-function `max_tries` pinned to match that policy exactly
    (see module docstring).
    """
    cfg = config or get_jobs_config()
    return func(
        _with_retry_and_dead_letter(handler, config=cfg),
        name=handler.__name__,
        max_tries=cfg.max_tries,
    )


async def enqueue_job(
    function_name: str,
    payload: TenantJobPayload | None = None,
    *,
    pool: ArqRedis | None = None,
    queue_name: str | None = None,
) -> str:
    """Enqueue a job by its registered name. Returns the arq job ID.

    `queue_name` is a thin passthrough to arq's own `_queue_name` (default
    `None` uses arq's standard queue, unchanged from before this
    parameter existed) -- it exists so a `Worker` bound to a non-default
    queue (`build_worker(..., queue_name=...)`) has a matching producer
    side, e.g. for test isolation against a shared Redis instance.

    `payload` must be `None` or a `TenantJobPayload` -- enforced here, at
    the queue boundary itself, not merely by `TenantJobPayload`'s own
    constructor (docs/MULTI-TENANCY.md section 4: "every job payload
    carries tenant_id"). This is checked before any Redis connection is
    opened, so an invalid payload never reaches the queue.

    P2.1: if the producer has an ambient correlation `request_id`
    (`infra.observability` -- e.g. the HTTP request currently being
    handled) and `payload.correlation_id` is unset, the payload is
    enqueued carrying that id so the worker's own log lines for this job
    correlate back to the producer. A caller-supplied `correlation_id` is
    never overwritten; a producer with no ambient context enqueues the
    payload exactly as given.
    """
    if payload is not None and not isinstance(payload, TenantJobPayload):
        raise InvalidJobPayloadError(function_name, type(payload))

    if payload is not None and payload.correlation_id is None:
        ambient_request_id = get_correlation_context().request_id
        if ambient_request_id is not None:
            payload = replace(payload, correlation_id=ambient_request_id)

    owns_pool = pool is None
    active_pool = pool or await get_redis_pool()
    try:
        job = await active_pool.enqueue_job(function_name, payload, _queue_name=queue_name)
    finally:
        if owns_pool:
            await active_pool.aclose()
    if job is None:
        raise JobsConfigurationError(
            f"Job {function_name!r} was not enqueued (a job with the same explicit "
            "job ID may already be queued)."
        )
    return job.job_id


def build_worker(
    functions: list[Function],
    *,
    config: JobsConfig | None = None,
    burst: bool = False,
    queue_name: str | None = None,
    health_check_interval_seconds: float | None = None,
) -> Worker:
    """Build an arq `Worker` bound to this module's Redis configuration.
    No functions are registered by default -- Phase 2.4 ships the runner
    only, not any business-logic job (docs/IMPLEMENTATION-ROADMAP.md).

    `health_check_interval_seconds` (P2.1) is a thin passthrough to arq's
    own `health_check_interval`: how often the running worker refreshes
    its Redis health sentinel key (`<queue_name>:health-check`, TTL
    `interval + 1s`). arq's default is 3600s -- far too coarse for a
    container health check to rely on; the production entrypoint
    (`api/worker.py`) passes a short interval and reads that same key
    back for its `--check` mode. `None` keeps arq's default (unchanged
    behavior for every existing caller).
    """
    cfg = config or get_jobs_config()
    kwargs: dict[str, Any] = {}
    if queue_name is not None:
        kwargs["queue_name"] = queue_name
    if health_check_interval_seconds is not None:
        kwargs["health_check_interval"] = health_check_interval_seconds
    return Worker(functions=functions, redis_settings=_redis_settings(cfg), burst=burst, **kwargs)
