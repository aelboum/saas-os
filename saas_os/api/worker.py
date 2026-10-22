"""Production background-worker entrypoint (P2.1) -- the one long-running
process that actually executes the jobs `saas_os.infra.jobs.enqueue_job()` puts
on Redis. Before P2.1 every Core module that enqueues work (`saas_os.core.webhooks`
delivery, `saas_os.core.usage` ingestion, `saas_os.core.notifications` in-app/email
dispatch) shipped a registered handler "for a worker process to register"
-- and no worker process existed anywhere in the repository, so in a real
deployment those jobs were enqueued and never run.

    python -m saas_os.api.worker            # long-running worker (Compose `worker` service)
    python -m saas_os.api.worker --check    # container health probe (exit 0/1), see below

**Placement**: `api/` is this repository's composition root for runtime
processes (`saas_os/api/server.py` is the HTTP one; this is the job one) -- the
same package, the same non-`core`/`infra` layer, so the existing
import-linter contracts apply unchanged: `api` may not import `products`
or `control_plane`. That is also why `saas_os.control_plane.self_learning
.continuous_loop.CONTINUOUS_LOOP_JOB_FUNCTIONS` is deliberately *not*
registered here: this worker does not require the AI Control Plane (this
checkpoint's own requirement), and the AI plane's own job stays an
in-process capability until a phase explicitly decides to run it.

**What is reused, and nothing new**: `saas_os.infra.jobs.build_worker()` (the one
arq `Worker` constructor), `saas_os.infra.jobs.get_jobs_config()` (`REDIS_URL`
through `saas_os.infra.secrets.SecretsProvider` -- this module never reads
`os.environ` for a secret), the already-registered `*_JOB_FUNCTIONS` lists
each Core module exports (their retry/backoff/dead-letter wrapper is
`saas_os.infra.jobs.register_tenant_job`/`register_system_job`'s, untouched),
`saas_os.infra.observability`'s
`configure_logging()`/`configure_tracing()` (the same calls `saas_os/api/main.py`'s
`lifespan` makes), and `saas_os.infra.db.validate_application_role()` (P1.2's
fail-closed startup guard). No second queue, worker framework, tenant
model, or configuration mechanism is introduced.

**Startup, fail closed**: configuration errors (`REDIS_URL`/`DATABASE_URL`
unset or malformed) and an unsafe database role all raise before the
worker ever polls Redis; `main()` turns any startup exception into a
non-zero process exit (logged as an exception *type name* plus the
error's own message -- every error class involved already guarantees it
never embeds a credential or connection string). An unreachable Redis at
startup surfaces through arq's own bounded connect/retry policy
(`RedisSettings.conn_retries`, 5 attempts) and then exits non-zero the
same way. There is no fallback to a localhost Redis, a development
credential, an unauthenticated connection, an in-memory queue, or fake
execution -- the process either runs against the configured Redis with
the configured, RLS-safe database role, or it does not run.

**Why the P1.2 role guard runs here too**: every registered job handler
opens `saas_os.infra.db.tenant_session_scope()`; a worker whose `DATABASE_URL`
pointed at a superuser/BYPASSRLS role would execute tenant-scoped writes
with Row-Level Security silently bypassed. The guard is the same
function, against the same process-wide engine, with the same no-opt-out
property `saas_os/api/main.py` already has -- the worker gets no broader
database privilege than the HTTP process.

**Shutdown**: arq's `Worker.run()` installs `SIGINT`/`SIGTERM` handlers
that cancel in-flight job tasks, then `Worker.close()` deletes the health
sentinel, closes the Redis pool, and the process exits 0 (a job
cancelled mid-flight is re-run by arq on the next pickup -- at-least-once
semantics, unchanged). On Windows, where an event loop cannot register
signal handlers, arq logs that limitation and the process ends on
`TerminateProcess` instead; production runs on Linux containers.

**Health (`--check`)**: no HTTP server is started for the worker. arq
itself refreshes a Redis sentinel key (`arq:queue:health-check`) every
`_HEALTH_CHECK_INTERVAL_SECONDS` while the worker's main loop is alive,
with a TTL one second longer than that interval -- so the key's mere
presence proves the worker is actually polling, not just that a Python
process exists. `--check` reads that key through the same
`saas_os.infra.jobs`/`SecretsProvider` path and exits 0 (present) or 1 (absent,
or Redis unreachable). `docker-compose.yml`'s `worker` service uses it as
the container `healthcheck`. Its one limitation: a worker stuck inside a
single very long job still refreshes the key between polls, so this
proves liveness of the poll loop, not per-job progress.

**Consumer jobs (P roadmap, P3)**: a consuming project runs this same
entrypoint with its own jobs added -- `main(extra_functions=...,
extra_cron_jobs=...)` from its own `python -m <product>.worker` module --
instead of re-implementing the startup order, the role guard and the
health probe. The dependency direction is unchanged: the product imports
`saas_os.api.worker`, `api` imports no product. Extras are accepted only if every
one was built by `saas_os.infra.jobs.register_tenant_job`/`register_system_job`,
or by `system_cron` for a schedule -- checked by the identity of the
wrapped coroutine (`saas_os.infra.jobs.queue.is_registered_job`), not by name, so
the typed-context, retry and dead-letter wrapper always applies -- and
none shares a name with a platform job or with another extra: arq keys
functions by name and would otherwise let a later entry silently replace
`_deliver_webhook` or the outbox dispatcher. Either violation is a
`JobsConfigurationError` at startup, i.e. a non-zero exit, never a
partially configured worker.

**Redis durability boundary**: this worker executes whatever the
configured Redis still holds. The queue and dead-letter list are exactly
as durable as that Redis instance -- `docker-compose.yml`'s `redis`
service has no persistence configured, so a Redis restart discards queued
and dead-lettered jobs. P2.1 makes the existing job infrastructure
*execute*; it does not, and does not claim to, make the queue durable --
Redis persistence/DR is a separate remediation (P2.x perimeter/DR work).
"""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Sequence

from arq.constants import default_queue_name, health_check_key_suffix
from arq.cron import CronJob
from arq.worker import Function

from saas_os.core.email import EmailConfigurationError, validate_email_configuration
from saas_os.infra.db import get_engine, validate_application_role
from saas_os.infra.db.config import DatabaseConfigurationError
from saas_os.infra.db.platform_config import (
    PlatformConfigCredentialExposedError,
    assert_no_platform_config_credential,
)
from saas_os.infra.db.role_guard import UnsafeDatabaseRoleError
from saas_os.infra.jobs import JobsConfig, JobsConfigurationError, build_worker, get_jobs_config
from saas_os.infra.jobs.queue import get_redis_pool, is_registered_job, system_cron
from saas_os.infra.observability import configure_logging, configure_tracing

# The only exception classes whose *message* may be logged at startup:
# each one's own docstring guarantees it never embeds a credential or
# connection string. Any other exception is logged by type name only --
# a third-party parser could echo the DSN it failed to parse.
_SAFE_TO_LOG_MESSAGE = (
    JobsConfigurationError,
    DatabaseConfigurationError,
    UnsafeDatabaseRoleError,
    PlatformConfigCredentialExposedError,
    EmailConfigurationError,
)

logger = logging.getLogger(__name__)

# Short enough that a container health check (docker-compose.yml: every
# 30s) always finds a fresh sentinel; the key's TTL is this + 1s.
_HEALTH_CHECK_INTERVAL_SECONDS = 15.0

# The one queue this worker consumes -- arq's default, the same one every
# `enqueue_job()` call without an explicit `queue_name` produces onto.
_QUEUE_NAME = default_queue_name
_HEALTH_CHECK_KEY = _QUEUE_NAME + health_check_key_suffix

_EXIT_OK = 0
_EXIT_STARTUP_FAILURE = 1
_EXIT_UNHEALTHY = 1


def registered_job_functions() -> list[Function]:
    """Every job handler a production worker executes -- exactly the
    already-registered `*_JOB_FUNCTIONS` each Core module exports, in one
    list. Nothing is registered here that a Core module did not already
    register itself via `saas_os.infra.jobs.register_tenant_job`/`register_system_job`.

    Imported here, not at module scope, for two reasons found by the
    real-process runtime test (`tests/api/test_worker_runtime_integration.py`):

    - Each Core module calls `saas_os.infra.jobs.register_tenant_job()`/
      `register_system_job()` at *import* time,
      which resolves `REDIS_URL` -- so importing them at module scope
      would turn a missing `REDIS_URL` into an unhandled traceback during
      `import saas_os.api.worker` instead of the structured, fail-closed
      `worker_startup_failed` exit `main()` guarantees.
    - The handlers' tables declare foreign keys to `core.tenants` and
      `core.tenant_memberships`. SQLAlchemy resolves a foreign key at
      flush time only if the *referenced* table's model is registered on
      the shared `saas_os.infra.db` metadata in this process -- the HTTP process
      gets that for free because `saas_os.api.dependencies` imports
      `saas_os.core.tenancy`/`saas_os.core.identity`; a worker that imported only the
      three job modules dead-lettered every usage event with
      `NoReferencedTableError`. The two explicit model imports below make
      the worker's ORM metadata complete, and nothing more.
    """
    import saas_os.core.tenancy  # noqa: F401 -- registers core.tenants on the shared metadata
    from saas_os.api.outbox_dispatcher import OUTBOX_JOB_FUNCTIONS
    from saas_os.core.billing.provider_event_jobs import BILLING_EVENT_RETENTION_JOB_FUNCTIONS
    from saas_os.core.identity import (
        SESSION_CLEANUP_JOB_FUNCTIONS,  # noqa: F401 -- also registers core.tenant_memberships
    )
    from saas_os.core.notifications import NOTIFICATION_JOB_FUNCTIONS
    from saas_os.core.usage import USAGE_JOB_FUNCTIONS
    from saas_os.core.webhooks import WEBHOOK_JOB_FUNCTIONS

    return [
        *SESSION_CLEANUP_JOB_FUNCTIONS,
        *NOTIFICATION_JOB_FUNCTIONS,
        *USAGE_JOB_FUNCTIONS,
        *WEBHOOK_JOB_FUNCTIONS,
        *OUTBOX_JOB_FUNCTIONS,
        *BILLING_EVENT_RETENTION_JOB_FUNCTIONS,
    ]


def registered_cron_jobs() -> list[CronJob]:
    """The periodic system jobs a production worker runs: the durable
    outbox dispatch cycle, every `OUTBOX_POLL_SECONDS` (RE-2), and the audit
    digests, every minute (ADR-0053; most runs find no settled window).
    Imported lazily for the same reasons as `registered_job_functions()`."""
    from saas_os.api.outbox_dispatcher import OUTBOX_DISPATCH_CYCLE
    from saas_os.core.audit_digest.jobs import AUDIT_DIGEST_CYCLE
    from saas_os.core.outbox import get_outbox_dispatch_config

    return [
        system_cron(OUTBOX_DISPATCH_CYCLE, every_seconds=get_outbox_dispatch_config().poll_seconds),
        system_cron(AUDIT_DIGEST_CYCLE, every_seconds=60),
    ]


def _checked_extras(
    taken: set[str], extras: Sequence[Function] | Sequence[CronJob], *, what: str
) -> list:
    """`extras` as a list, after refusing any entry that would weaken the
    worker (module docstring, "Consumer jobs"): one that `saas_os.infra.jobs` did
    not build, or one whose name is already in `taken`. Accepted names are
    added to `taken`, which the caller shares across jobs and cron jobs --
    arq keeps both in one name-keyed mapping."""
    for extra in extras:
        if not is_registered_job(extra):
            raise JobsConfigurationError(
                f"An extra {what} is not registered through saas_os.infra.jobs "
                "(register_tenant_job/register_system_job/system_cron)."
            )
        if extra.name in taken:
            raise JobsConfigurationError(
                f"Extra {what} {extra.name!r} collides with an already-registered job."
            )
        taken.add(extra.name)
    return list(extras)


def build_production_worker(
    config: JobsConfig | None = None,
    *,
    extra_functions: Sequence[Function] = (),
    extra_cron_jobs: Sequence[CronJob] = (),
):
    """The real, long-running (non-burst) arq `Worker` this process runs,
    on the default queue, with the short health-sentinel interval the
    `--check` probe relies on. Returns the `Worker` without starting it
    (tests construct it without polling Redis).

    `extra_functions`/`extra_cron_jobs` are a consuming project's own jobs
    (module docstring, "Consumer jobs"), added to -- never replacing --
    the platform's."""
    functions = registered_job_functions()
    cron_jobs = registered_cron_jobs()
    # arq keeps functions and cron jobs in one name-keyed mapping, so an
    # extra of either kind is checked against every platform name and
    # against every other extra: a scheduled job is passed as a cron job
    # only, never also as a function.
    taken = {fn.name for fn in functions} | {job.name for job in cron_jobs if job.name}
    functions += _checked_extras(taken, extra_functions, what="job")
    cron_jobs += _checked_extras(taken, extra_cron_jobs, what="cron job")
    return build_worker(
        functions,
        config=config or get_jobs_config(),
        burst=False,
        queue_name=_QUEUE_NAME,
        health_check_interval_seconds=_HEALTH_CHECK_INTERVAL_SECONDS,
        cron_jobs=cron_jobs,
    )


async def check_health(config: JobsConfig | None = None) -> int:
    """`--check` mode: exit 0 iff a running worker's health sentinel is
    present in Redis (module docstring). Uses the existing
    `saas_os.infra.jobs.queue.get_redis_pool()` -- the same `SecretsProvider`-
    sourced configuration path as the worker itself -- never a second
    Redis client or a DSN read from the environment here."""
    try:
        pool = await get_redis_pool(config or get_jobs_config())
    except Exception as exc:  # noqa: BLE001 -- any failure to reach Redis is "unhealthy"
        logger.warning("worker_health_check_failed", extra={"error_type": type(exc).__name__})
        return _EXIT_UNHEALTHY
    try:
        sentinel = await pool.get(_HEALTH_CHECK_KEY)
    except Exception as exc:  # noqa: BLE001
        logger.warning("worker_health_check_failed", extra={"error_type": type(exc).__name__})
        return _EXIT_UNHEALTHY
    finally:
        await pool.aclose()

    if not sentinel:
        logger.warning("worker_health_check_failed", extra={"error_type": "NoHealthSentinel"})
        return _EXIT_UNHEALTHY
    return _EXIT_OK


def main(
    argv: list[str] | None = None,
    *,
    extra_functions: Sequence[Function] = (),
    extra_cron_jobs: Sequence[CronJob] = (),
) -> int:
    """Process entrypoint. Returns the exit code (`python -m saas_os.api.worker`
    passes it to `sys.exit`). Startup failures fail closed: any exception
    before the worker's main loop starts is logged and becomes a non-zero
    exit -- never a silent fallback (module docstring).

    A consuming project's own worker module calls this with its own
    `extra_functions`/`extra_cron_jobs` (module docstring, "Consumer
    jobs"); `--check` behaves identically either way."""
    args = sys.argv[1:] if argv is None else argv
    configure_logging()

    if args == ["--check"]:
        return asyncio.run(check_health())
    if args:
        logger.error("worker_invalid_arguments", extra={"argument_count": len(args)})
        return _EXIT_STARTUP_FAILURE

    configure_tracing()
    try:
        # Order: queue configuration (REDIS_URL via SecretsProvider) ->
        # database role guard -> worker construction (which imports the
        # Core job modules, see registered_job_functions()). Each step
        # fails closed before the next one runs.
        config = get_jobs_config()
        # ADR-0056 D4: the worker never holds the platform-configuration
        # credential.
        assert_no_platform_config_credential()
        # ADR-0057: an explicitly configured email provider is validated
        # here -- configuration, credentials, the production guards; no
        # network call -- so a bad setting stops the worker instead of
        # dead-lettering mail later. Unset `EMAIL_PROVIDER`: nothing checked.
        email_provider = validate_email_configuration()
        role = validate_application_role(get_engine())
        if extra_functions or extra_cron_jobs:
            worker = build_production_worker(
                config, extra_functions=extra_functions, extra_cron_jobs=extra_cron_jobs
            )
        else:
            worker = build_production_worker(config)
    except Exception as exc:  # noqa: BLE001 -- every startup failure must exit non-zero
        detail = str(exc) if isinstance(exc, _SAFE_TO_LOG_MESSAGE) else None
        logger.error(
            "worker_startup_failed",
            extra={"error_type": type(exc).__name__, "error_detail": detail},
        )
        return _EXIT_STARTUP_FAILURE

    logger.info(
        "worker_starting",
        extra={
            "queue_name": _QUEUE_NAME,
            "job_functions": sorted(worker.functions),
            "database_role": role.role_name,
            "email_provider": email_provider,
            "health_check_interval_seconds": _HEALTH_CHECK_INTERVAL_SECONDS,
        },
    )
    try:
        worker.run()
    except Exception as exc:  # noqa: BLE001 -- e.g. Redis unreachable after arq's own retries
        logger.error("worker_failed", extra={"error_type": type(exc).__name__})
        return _EXIT_STARTUP_FAILURE
    logger.info("worker_stopped", extra={"queue_name": _QUEUE_NAME})
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
