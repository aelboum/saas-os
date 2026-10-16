"""`saas_os/api/worker.py`'s consumer-job seam (docs/P-ROADMAP.md, P3): a consuming
project adds its own jobs to the production worker without re-implementing
the entrypoint, and can never replace or bypass a platform job by doing so.
No Redis or PostgreSQL here -- the wiring only, like `test_worker_unit.py`.
"""

from __future__ import annotations

import logging

import pytest
from arq.cron import cron
from arq.worker import func

import saas_os.api.worker as worker_module
from saas_os.infra.db.role_guard import ApplicationRoleValidation
from saas_os.infra.jobs import (
    JobsConfig,
    JobsConfigurationError,
    TenantJobPayload,
    register_system_job,
    register_tenant_job,
)
from saas_os.infra.jobs.context import SystemJobContext, TenantJobContext
from saas_os.infra.jobs.queue import system_cron

_CONFIG = JobsConfig(redis_url="redis://localhost:6379/0")
_PLATFORM_JOBS = {
    "_dispatch_notification_job",
    "_ingest_usage_event_job",
    "_deliver_webhook",
    "_cleanup_expired_sessions_job",
    "_run_outbox_event",
    "_prune_billing_provider_events_job",  # ADR-0048: ledger retention
}
_PLATFORM_CRON_JOBS = {"_dispatch_outbox_cycle", "_audit_digest_cycle"}  # ADR-0053


async def _consumer_tenant_job(context: TenantJobContext, payload: TenantJobPayload) -> None:
    return None


async def _consumer_system_job(context: SystemJobContext) -> None:
    return None


async def _deliver_webhook(context: TenantJobContext, payload: TenantJobPayload) -> None:
    """Named exactly like the platform's webhook delivery job."""
    return None


async def _dispatch_outbox_cycle(context: SystemJobContext) -> None:
    """Named exactly like the platform's outbox dispatch cron."""
    return None


async def _never_registered(ctx: dict[str, object]) -> None:
    return None


_TENANT_JOB = register_tenant_job(_consumer_tenant_job, config=_CONFIG)
_SYSTEM_JOB = register_system_job(_consumer_system_job, config=_CONFIG)


@pytest.fixture(autouse=True)
def _known_queue_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_module, "configure_logging", lambda: None)
    monkeypatch.setattr(worker_module, "configure_tracing", lambda: None)
    monkeypatch.setattr(worker_module, "get_jobs_config", lambda: _CONFIG)


def test_consumer_jobs_are_added_to_the_platform_jobs_never_instead_of_them() -> None:
    worker = worker_module.build_production_worker(_CONFIG, extra_functions=[_TENANT_JOB])
    assert set(worker.functions) == (
        _PLATFORM_JOBS | _PLATFORM_CRON_JOBS | {"_consumer_tenant_job"}
    )


def test_consumer_cron_job_is_added_next_to_the_outbox_dispatch_cycle() -> None:
    schedule = system_cron(_SYSTEM_JOB, every_seconds=30)
    worker = worker_module.build_production_worker(_CONFIG, extra_cron_jobs=[schedule])
    assert {job.name for job in worker.cron_jobs} == (
        _PLATFORM_CRON_JOBS | {"_consumer_system_job"}
    )
    assert set(worker.functions) == (
        _PLATFORM_JOBS | _PLATFORM_CRON_JOBS | {"_consumer_system_job"}
    )


def test_a_job_passed_both_as_a_function_and_as_a_cron_job_is_refused() -> None:
    """arq keys both in one mapping: the cron entry would replace the
    function and run it with the schedule's single attempt."""
    schedule = system_cron(_SYSTEM_JOB, every_seconds=30)
    with pytest.raises(JobsConfigurationError, match="collides"):
        worker_module.build_production_worker(
            _CONFIG, extra_functions=[_SYSTEM_JOB], extra_cron_jobs=[schedule]
        )


def test_a_raw_function_under_a_registered_name_is_refused() -> None:
    """The check is the wrapped coroutine's identity, not the name: a raw
    arq function reusing a registered job's name has no wrapper."""
    forged = func(_never_registered, name="_consumer_tenant_job")
    with pytest.raises(JobsConfigurationError, match="not registered through saas_os.infra.jobs"):
        worker_module.build_production_worker(_CONFIG, extra_functions=[forged])


def test_a_raw_cron_job_under_a_registered_name_is_refused() -> None:
    forged = cron(_never_registered, name="_consumer_system_job", second=0)
    with pytest.raises(JobsConfigurationError, match="not registered through saas_os.infra.jobs"):
        worker_module.build_production_worker(_CONFIG, extra_cron_jobs=[forged])


def test_a_coroutine_carrying_a_name_attribute_is_refused() -> None:
    """arq would key a bare coroutine by its `__qualname__`, so one named
    like a platform job could replace it whatever `.name` claims."""

    async def _deliver_webhook(ctx: dict[str, object]) -> None:
        return None

    _deliver_webhook.name = "_consumer_tenant_job"  # type: ignore[attr-defined]
    with pytest.raises(JobsConfigurationError, match="not registered through saas_os.infra.jobs"):
        worker_module.build_production_worker(
            _CONFIG,
            extra_functions=[_deliver_webhook],  # type: ignore[list-item]
        )


def test_a_registered_job_renamed_to_a_platform_job_is_refused() -> None:
    renamed = func(_TENANT_JOB.coroutine, name="_deliver_webhook")
    with pytest.raises(JobsConfigurationError, match="collides"):
        worker_module.build_production_worker(_CONFIG, extra_functions=[renamed])


def test_no_extras_leaves_the_worker_exactly_as_before() -> None:
    worker = worker_module.build_production_worker(_CONFIG)
    assert set(worker.functions) == _PLATFORM_JOBS | _PLATFORM_CRON_JOBS


def test_consumer_job_cannot_take_the_name_of_a_platform_job() -> None:
    import saas_os.core.webhooks  # noqa: F401 -- registers the platform's own `_deliver_webhook`

    # `register_tenant_job` accepts a second handler under this name (same
    # kind as the platform's), so the worker is the last line.
    hijack = register_tenant_job(_deliver_webhook, config=_CONFIG)
    with pytest.raises(JobsConfigurationError, match="collides"):
        worker_module.build_production_worker(_CONFIG, extra_functions=[hijack])


def test_consumer_job_cannot_take_the_name_of_a_platform_cron_job() -> None:
    worker_module.registered_cron_jobs()  # registers the platform's `_dispatch_outbox_cycle`
    hijack = register_system_job(_dispatch_outbox_cycle, config=_CONFIG)
    with pytest.raises(JobsConfigurationError, match="collides"):
        worker_module.build_production_worker(_CONFIG, extra_functions=[hijack])


def test_consumer_cron_job_cannot_take_the_name_of_a_platform_job() -> None:
    import saas_os.core.identity  # noqa: F401 -- registers the platform's session-cleanup system job

    (cleanup,) = (
        fn
        for fn in worker_module.registered_job_functions()
        if fn.name == "_cleanup_expired_sessions_job"
    )
    with pytest.raises(JobsConfigurationError, match="collides"):
        worker_module.build_production_worker(
            _CONFIG, extra_cron_jobs=[system_cron(cleanup, every_seconds=30)]
        )


def test_the_same_consumer_job_twice_is_refused() -> None:
    with pytest.raises(JobsConfigurationError, match="collides"):
        worker_module.build_production_worker(_CONFIG, extra_functions=[_TENANT_JOB, _TENANT_JOB])


def test_a_job_not_registered_through_infra_jobs_is_refused() -> None:
    """A raw arq function has no typed-context check, retry policy or
    dead-letter wrapper (ADR-0030); the worker refuses to run one."""
    raw = func(_never_registered, name="_never_registered")
    with pytest.raises(JobsConfigurationError, match="not registered through saas_os.infra.jobs"):
        worker_module.build_production_worker(_CONFIG, extra_functions=[raw])


def test_a_bare_coroutine_is_refused() -> None:
    with pytest.raises(JobsConfigurationError, match="not registered through saas_os.infra.jobs"):
        worker_module.build_production_worker(
            _CONFIG,
            extra_functions=[_never_registered],  # type: ignore[list-item]
        )


def test_main_exits_nonzero_before_running_when_an_extra_collides(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(worker_module, "get_engine", lambda: object())
    monkeypatch.setattr(
        worker_module,
        "validate_application_role",
        lambda engine: ApplicationRoleValidation(role_name="saas_os_app"),
    )
    import saas_os.core.webhooks  # noqa: F401 -- registers the platform's own `_deliver_webhook`

    hijack = register_tenant_job(_deliver_webhook, config=_CONFIG)

    with caplog.at_level(logging.ERROR, logger="saas_os.api.worker"):
        assert worker_module.main([], extra_functions=[hijack]) == 1

    (record,) = [r for r in caplog.records if r.getMessage() == "worker_startup_failed"]
    assert record.error_type == "JobsConfigurationError"  # type: ignore[attr-defined]


def test_main_passes_consumer_jobs_through_to_the_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    built: dict[str, object] = {}

    class _Worker:
        functions = {"_consumer_tenant_job": object()}

        def run(self) -> None:
            built["ran"] = True

    def _build(config: JobsConfig | None = None, **extras: object) -> _Worker:
        built.update(extras)
        return _Worker()

    monkeypatch.setattr(worker_module, "get_engine", lambda: object())
    monkeypatch.setattr(
        worker_module,
        "validate_application_role",
        lambda engine: ApplicationRoleValidation(role_name="saas_os_app"),
    )
    monkeypatch.setattr(worker_module, "build_production_worker", _build)

    assert worker_module.main([], extra_functions=[_TENANT_JOB]) == 0
    assert built["extra_functions"] == [_TENANT_JOB]
    assert built["ran"] is True


def test_the_role_guard_still_runs_before_any_consumer_job_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from saas_os.infra.db.role_guard import UnsafeDatabaseRoleError

    def _unsafe(engine: object) -> ApplicationRoleValidation:
        raise UnsafeDatabaseRoleError("the role can bypass RLS")

    def _must_not_build(*args: object, **kwargs: object) -> None:
        raise AssertionError("the worker must not be built under an unsafe database role")

    monkeypatch.setattr(worker_module, "get_engine", lambda: object())
    monkeypatch.setattr(worker_module, "validate_application_role", _unsafe)
    monkeypatch.setattr(worker_module, "build_production_worker", _must_not_build)

    assert worker_module.main([], extra_functions=[_TENANT_JOB]) == 1
