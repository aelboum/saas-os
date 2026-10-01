"""`infra/jobs`'s narrow queue/worker interface (docs/IMPLEMENTATION-
ROADMAP.md Phase 2.4, docs/ADR/0007-background-job-and-workflow-engine.md):
enqueue, execute, retry-on-failure, dead-letter -- and nothing else. No
multi-step or compensating-workflow semantics (ADR-0007: that is a future
durable-workflow-engine concern, not this module's).

Retry/backoff/dead-letter is decided by *this module*, not delegated to
arq's own built-in retry bookkeeping: a registered job's arq-level
`max_tries` is set to match `JobsConfig.max_tries` exactly (see
`register_tenant_job`/`register_system_job`), so arq always hands control
back to `_with_retry_and_dead_letter`
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

**PRIV-03 Phase P10 (privacy re-audit RA-06) -- no job result is ever
stored.** arq's default keeps every finished job's *result record* in
Redis for an hour (`arq:result:<job_id>`, `Worker(keep_result=3600)`),
and that record is not just the return value: it is the pickled call --
function name, the complete `TenantJobPayload` argument (a notification's
recipient address, subject and body; a webhook event's data; a usage
event), the return value or the exception, and timings -- written for
successful, dead-lettered and closed-tenant no-op executions alike, keyed
by an opaque job id with no tenant scoping and untouched by tenant purge.
No production code reads a result (every Core handler returns `None`;
the outcome that matters is the row/e-mail/request the handler itself
produces), so `_register()` registers every function with
`keep_result=0` and `build_worker()` builds every `Worker` with
`keep_result=0`: arq then skips result serialization entirely and still
deletes the `arq:job:`/`arq:retry:` keys exactly as before. Both levels
are needed -- the per-function value governs the normal finish path, the
worker-level value governs arq's own failure path (`finish_failed_job`:
job expired, undeserializable, function not registered). Retry, backoff
and dead-letter behavior are unchanged; only the retained copy is gone.
"""

from __future__ import annotations

import functools
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any, cast

from arq import ArqRedis, Retry, create_pool
from arq.connections import RedisSettings
from arq.typing import WorkerCoroutine
from arq.worker import Function, Worker, func

from infra.jobs.config import JobsConfig, get_jobs_config
from infra.jobs.context import JobKind, SystemJobContext, TenantJobContext
from infra.jobs.dead_letter import record_dead_letter
from infra.jobs.errors import (
    InvalidJobPayloadError,
    JobContractViolationError,
    JobDeadLetteredError,
    JobsConfigurationError,
)
from infra.jobs.payload import TenantJobPayload
from infra.observability import bind_correlation_context, get_correlation_context

logger = logging.getLogger(__name__)

TenantJobHandler = Callable[[TenantJobContext, TenantJobPayload], Awaitable[Any]]
SystemJobHandler = Callable[[SystemJobContext], Awaitable[Any]]
JobHandler = TenantJobHandler | SystemJobHandler

# Foundation Enforcement FE-5: the declared kind of every job registered in
# this process, by arq function name -- what `enqueue_job()` checks a payload
# against. Registering the same name again with the same kind is fine (tests
# re-register real handlers with their own config); a different kind is a
# configuration error.
_REGISTERED_JOB_KINDS: dict[str, JobKind] = {}


def registered_job_kind(function_name: str) -> JobKind | None:
    """The declared kind of `function_name`, if registered in this process."""
    return _REGISTERED_JOB_KINDS.get(function_name)


def _contract_violation(kind: JobKind, payload: object) -> tuple[str | None, uuid.UUID | None]:
    """`(reason, tenant_uuid)`: `reason` is `None` when `payload` satisfies
    `kind`. Never inspects `payload.data`."""
    if kind is JobKind.SYSTEM:
        if payload is not None:
            return f"system job requires no payload, got {type(payload).__name__}", None
        return None, None
    if not isinstance(payload, TenantJobPayload):
        return f"tenant job requires a TenantJobPayload, got {type(payload).__name__}", None
    try:
        tenant_uuid = uuid.UUID(payload.tenant_id)
    except (ValueError, TypeError, AttributeError):
        return "tenant job requires a UUID tenant_id", None
    # Canonical form only (lower-case, hyphenated -- `str(uuid)`, what every
    # producer sends): `uuid.UUID()` also accepts braces, `urn:uuid:`, no
    # hyphens and upper case, and the raw string is what the dead-letter
    # entry and a tenant's dead-letter purge match on.
    if str(tenant_uuid) != payload.tenant_id:
        return "tenant job requires a canonical UUID tenant_id", None
    return None, tenant_uuid


def _redis_settings(config: JobsConfig) -> RedisSettings:
    return RedisSettings.from_dsn(config.redis_url)


async def get_redis_pool(config: JobsConfig | None = None) -> ArqRedis:
    """A connected `arq` Redis pool -- the one place this module opens a
    Redis connection (`infra/jobs`'s own execution metadata, docs/DATA-
    ARCHITECTURE.md section 5), built from `JobsConfig.redis_url`.
    """
    return await create_pool(_redis_settings(config or get_jobs_config()))


def _with_retry_and_dead_letter(
    handler: JobHandler, *, config: JobsConfig | None, kind: JobKind
) -> WorkerCoroutine:
    function_name = handler.__name__

    @functools.wraps(cast("Callable[..., Any]", handler))
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
            # FE-5: the payload must match the declared kind before the
            # handler may run. A mismatch is permanent: dead-lettered now,
            # never retried, handler never executed.
            reason, tenant_uuid = _contract_violation(kind, payload)
            if reason is not None:
                violation = JobContractViolationError(function_name, reason)
                pool = await get_redis_pool(cfg)
                try:
                    await record_dead_letter(
                        pool,
                        cfg,
                        function_name=function_name,
                        payload=payload,
                        error=violation,
                        attempts=job_try,
                    )
                finally:
                    await pool.aclose()
                logger.error(
                    "job_contract_violation",
                    extra={**log_fields, "job_error_type": type(violation).__name__},
                )
                raise JobDeadLetteredError(function_name, job_try) from violation

            logger.info("job_started", extra=log_fields)
            try:
                if kind is JobKind.TENANT:
                    assert tenant_uuid is not None and isinstance(payload, TenantJobPayload)
                    tenant_handler: TenantJobHandler = handler  # type: ignore[assignment]
                    result = await tenant_handler(
                        TenantJobContext(tenant_id=tenant_uuid, correlation_id=correlation_id),
                        payload,
                    )
                else:
                    system_handler: SystemJobHandler = handler  # type: ignore[assignment]
                    result = await system_handler(SystemJobContext(correlation_id=correlation_id))
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


def _register(handler: JobHandler, kind: JobKind, config: JobsConfig | None) -> Function:
    """Wrap a handler into an arq `Function` with this module's
    retry/dead-letter policy attached, arq's own per-function `max_tries`
    pinned to match that policy exactly, and `keep_result=0` so arq never
    writes an `arq:result:<job_id>` record for it -- the record would carry
    the whole payload (module docstring, PRIV-03 P10 / RA-06). The handler's
    return value still reaches this wrapper and the worker's log line; it is
    simply never persisted. The arq function name is the handler's own
    `__name__`, unchanged by FE-5, so already-queued jobs keep resolving."""
    name = handler.__name__
    declared = _REGISTERED_JOB_KINDS.setdefault(name, kind)
    if declared is not kind:
        raise JobsConfigurationError(
            f"Job {name!r} is already registered as a {declared.value} job, not {kind.value}."
        )
    cfg = config or get_jobs_config()
    return func(
        _with_retry_and_dead_letter(handler, config=cfg, kind=kind),
        name=name,
        keep_result=0,
        max_tries=cfg.max_tries,
    )


def register_tenant_job(handler: TenantJobHandler, *, config: JobsConfig | None = None) -> Function:
    """Register `async def handler(context: TenantJobContext, payload:
    TenantJobPayload)`. The worker only calls it with a valid
    `TenantJobPayload` whose `tenant_id` is a UUID (`context.tenant_id`);
    anything else is dead-lettered without retry (`infra/jobs/context.py`)."""
    return _register(handler, JobKind.TENANT, config)


def register_system_job(handler: SystemJobHandler, *, config: JobsConfig | None = None) -> Function:
    """Register `async def handler(context: SystemJobContext)` -- a
    platform job with no tenant. The worker only calls it when the payload
    is `None`; a tenant payload is dead-lettered without retry."""
    return _register(handler, JobKind.SYSTEM, config)


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
    # FE-5: a job registered in this process is also checked against its
    # declared kind here, before anything reaches Redis. (The worker checks
    # again on its side regardless.)
    kind = _REGISTERED_JOB_KINDS.get(function_name)
    if kind is not None:
        reason, _ = _contract_violation(kind, payload)
        if reason is not None:
            raise JobContractViolationError(function_name, reason)

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

    `keep_result=0` (PRIV-03 P10 / RA-06, module docstring) is the
    process-wide default every worker built here carries: it is what arq
    consults on its *own* failure path (`finish_failed_job` -- a job that
    expired before running, could not be deserialized, or names a function
    this worker does not have), where the per-function value
    `_register()` sets is never reached. Nothing this worker runs ever
    leaves a result record in Redis.
    """
    cfg = config or get_jobs_config()
    kwargs: dict[str, Any] = {}
    if queue_name is not None:
        kwargs["queue_name"] = queue_name
    if health_check_interval_seconds is not None:
        kwargs["health_check_interval"] = health_check_interval_seconds
    return Worker(
        functions=functions,
        redis_settings=_redis_settings(cfg),
        burst=burst,
        keep_result=0,
        **kwargs,
    )
