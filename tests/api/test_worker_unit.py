"""Unit tests for `api/worker.py`, the P2.1 production worker entrypoint --
no real Redis or PostgreSQL here (that is
`tests/api/test_worker_runtime_integration.py`'s job). These prove the
wiring: the already-registered Core job functions are what the worker
runs, Redis configuration arrives only through `infra.secrets`, every
startup failure exits non-zero, `--check` reads the arq sentinel, and no
HTTP server / AI Control Plane / product code is involved.
"""

from __future__ import annotations

import ast
import inspect
import logging

import api.worker as worker_module
import pytest
from infra.db.role_guard import ApplicationRoleValidation, UnsafeDatabaseRoleError
from infra.jobs.config import get_jobs_config
from infra.secrets.provider import SecretsProvider

from infra.jobs import JobsConfig, JobsConfigurationError

_EXPECTED_JOB_NAMES = {"_dispatch_notification_job", "_ingest_usage_event_job", "_deliver_webhook"}
_CONFIG = JobsConfig(redis_url="redis://localhost:6379/0")


class _FakeSecrets(SecretsProvider):
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str | None:
        return self._values.get(name)


class _FakeWorker:
    def __init__(self, *, fail: Exception | None = None) -> None:
        self.functions = {name: object() for name in _EXPECTED_JOB_NAMES}
        self.ran = False
        self._fail = fail

    def run(self) -> None:
        self.ran = True
        if self._fail is not None:
            raise self._fail


def _safe_role(engine: object) -> ApplicationRoleValidation:
    return ApplicationRoleValidation(role_name="saas_os_app")


@pytest.fixture(autouse=True)
def _isolate_jobs_config(monkeypatch: pytest.MonkeyPatch):
    get_jobs_config.cache_clear()
    # `configure_logging()` reconfigures the root logger with `force=True`,
    # which would discard pytest's own caplog handler mid-test; the real
    # calls are exercised by the runtime integration test, not here.
    monkeypatch.setattr(worker_module, "configure_logging", lambda: None)
    monkeypatch.setattr(worker_module, "configure_tracing", lambda: None)
    # A known-good queue configuration for the lifecycle tests, so they do
    # not depend on REDIS_URL being present in the test environment; the
    # missing-REDIS_URL test overrides this with the real resolution path.
    monkeypatch.setattr(worker_module, "get_jobs_config", lambda: _CONFIG)
    yield
    get_jobs_config.cache_clear()


# --- Worker construction ---------------------------------------------------


def test_registered_job_functions_are_exactly_the_core_exports() -> None:
    names = {fn.name for fn in worker_module.registered_job_functions()}
    assert names == _EXPECTED_JOB_NAMES


def test_no_ai_control_plane_job_is_registered() -> None:
    names = {fn.name for fn in worker_module.registered_job_functions()}
    assert "_run_continuous_learning_cycle_job" not in names


def test_build_production_worker_includes_every_registered_job() -> None:
    worker = worker_module.build_production_worker(_CONFIG)
    assert set(worker.functions) == _EXPECTED_JOB_NAMES


def test_build_production_worker_is_long_running_on_the_default_queue() -> None:
    worker = worker_module.build_production_worker(_CONFIG)
    assert worker.burst is False
    assert worker.queue_name == worker_module._QUEUE_NAME == "arq:queue"
    assert worker.health_check_interval == worker_module._HEALTH_CHECK_INTERVAL_SECONDS
    assert worker.health_check_key == worker_module._HEALTH_CHECK_KEY


def test_redis_configuration_comes_through_the_secrets_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setattr(
        "infra.jobs.config.get_secrets_provider",
        lambda: _FakeSecrets({"REDIS_URL": "redis://from-secrets-provider:6390/2"}),
    )
    monkeypatch.setattr(worker_module, "get_jobs_config", get_jobs_config)  # real resolution
    worker = worker_module.build_production_worker()
    assert worker.redis_settings is not None
    assert worker.redis_settings.host == "from-secrets-provider"
    assert worker.redis_settings.port == 6390
    assert worker.redis_settings.database == 2


def test_worker_module_never_reads_the_environment_directly() -> None:
    """AST-level, not text-level: the module docstring legitimately
    *mentions* `os.environ` to say it is never used; the code must contain
    no `import os` and no `os.environ`/`os.getenv` access at all."""
    tree = ast.parse(inspect.getsource(worker_module))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }
    assert "os" not in imported
    assert not any(
        isinstance(node, ast.ImportFrom) and node.module == "os" for node in ast.walk(tree)
    )
    attribute_accesses = {
        f"{node.value.id}.{node.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
    }
    assert "os.environ" not in attribute_accesses
    assert "os.getenv" not in attribute_accesses


def test_worker_module_starts_no_http_server_and_imports_no_upper_layer() -> None:
    source = inspect.getsource(worker_module)
    assert "uvicorn" not in source
    assert "create_app" not in source
    assert "import control_plane" not in source
    assert "from control_plane" not in source
    assert "import products" not in source
    assert "from products" not in source


def test_worker_registers_the_orm_models_its_jobs_foreign_keys_reference() -> None:
    """Found by the real-process runtime test: without `core.tenancy`/
    `core.identity` imported in the worker process, every usage-event
    job dead-lettered with `NoReferencedTableError`. The shared metadata
    must know `core.tenants` and `core.tenant_memberships` once the job
    functions have been resolved."""
    from infra.db import Base

    worker_module.registered_job_functions()
    assert "core.tenants" in Base.metadata.tables
    assert "core.tenant_memberships" in Base.metadata.tables
    assert "core.usage_events" in Base.metadata.tables
    assert "core.notifications" in Base.metadata.tables
    assert "core.webhook_subscriptions" in Base.metadata.tables


# --- Lifecycle: fail closed --------------------------------------------------


def test_main_fails_closed_when_redis_url_is_missing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setattr("infra.jobs.config.get_secrets_provider", lambda: _FakeSecrets({}))
    monkeypatch.setattr(worker_module, "get_jobs_config", get_jobs_config)  # real resolution
    guard_called = False

    def _guard(engine: object) -> ApplicationRoleValidation:
        nonlocal guard_called
        guard_called = True
        return _safe_role(engine)

    monkeypatch.setattr(worker_module, "get_engine", lambda: object())
    monkeypatch.setattr(worker_module, "validate_application_role", _guard)

    with caplog.at_level(logging.ERROR, logger="api.worker"):
        assert worker_module.main([]) == 1

    records = [r for r in caplog.records if r.getMessage() == "worker_startup_failed"]
    assert records[0].error_type == "JobsConfigurationError"  # type: ignore[attr-defined]
    assert guard_called is False  # configuration is validated before any database access


def test_main_fails_closed_on_an_unsafe_database_role(monkeypatch: pytest.MonkeyPatch) -> None:
    def _unsafe(engine: object) -> ApplicationRoleValidation:
        raise UnsafeDatabaseRoleError("Application database role 'x' is a PostgreSQL superuser")

    built = False

    def _must_not_build(config: object = None) -> _FakeWorker:
        nonlocal built
        built = True
        return _FakeWorker()

    monkeypatch.setattr(worker_module, "get_engine", lambda: object())
    monkeypatch.setattr(worker_module, "validate_application_role", _unsafe)
    monkeypatch.setattr(worker_module, "build_production_worker", _must_not_build)

    assert worker_module.main([]) == 1
    assert built is False


def test_main_has_no_way_to_skip_the_role_guard() -> None:
    source = inspect.getsource(worker_module.main)
    assert "validate_application_role(get_engine())" in source


def test_startup_failure_log_never_contains_an_unknown_exceptions_message(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def _explode(engine: object) -> ApplicationRoleValidation:
        raise ValueError("invalid dsn 'redis://:supersecretpw@host:6379/0'")

    monkeypatch.setattr(worker_module, "get_engine", lambda: object())
    monkeypatch.setattr(worker_module, "validate_application_role", _explode)

    with caplog.at_level(logging.ERROR, logger="api.worker"):
        assert worker_module.main([]) == 1

    records = [r for r in caplog.records if r.getMessage() == "worker_startup_failed"]
    assert len(records) == 1
    assert records[0].error_type == "ValueError"  # type: ignore[attr-defined]
    assert records[0].error_detail is None  # type: ignore[attr-defined]
    assert "supersecretpw" not in caplog.text


def test_startup_failure_log_includes_the_message_only_for_known_safe_errors(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def _config_error(engine: object) -> ApplicationRoleValidation:
        raise JobsConfigurationError("REDIS_URL is not set.")

    monkeypatch.setattr(worker_module, "get_engine", lambda: object())
    monkeypatch.setattr(worker_module, "validate_application_role", _config_error)

    with caplog.at_level(logging.ERROR, logger="api.worker"):
        assert worker_module.main([]) == 1

    records = [r for r in caplog.records if r.getMessage() == "worker_startup_failed"]
    assert records[0].error_detail == "REDIS_URL is not set."  # type: ignore[attr-defined]


def test_main_rejects_unknown_arguments() -> None:
    assert worker_module.main(["--reload"]) == 1


# --- Lifecycle: run and stop -------------------------------------------------


def test_main_runs_the_worker_and_exits_zero_on_a_clean_stop(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    fake = _FakeWorker()
    monkeypatch.setattr(worker_module, "get_engine", lambda: object())
    monkeypatch.setattr(worker_module, "validate_application_role", _safe_role)
    monkeypatch.setattr(worker_module, "build_production_worker", lambda config=None: fake)

    with caplog.at_level(logging.INFO, logger="api.worker"):
        assert worker_module.main([]) == 0

    assert fake.ran is True
    messages = [r.getMessage() for r in caplog.records]
    assert "worker_starting" in messages
    assert "worker_stopped" in messages


def test_main_exits_nonzero_if_the_worker_itself_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeWorker(fail=ConnectionError("redis gone"))
    monkeypatch.setattr(worker_module, "get_engine", lambda: object())
    monkeypatch.setattr(worker_module, "validate_application_role", _safe_role)
    monkeypatch.setattr(worker_module, "build_production_worker", lambda config=None: fake)

    assert worker_module.main([]) == 1


# --- Health probe (--check) --------------------------------------------------


class _FakePool:
    def __init__(self, sentinel: bytes | None, *, fail: bool = False) -> None:
        self._sentinel = sentinel
        self._fail = fail
        self.closed = False
        self.requested_key: str | None = None

    async def get(self, key: str) -> bytes | None:
        self.requested_key = key
        if self._fail:
            raise ConnectionError("redis unreachable")
        return self._sentinel

    async def aclose(self) -> None:
        self.closed = True


def _use_pool(monkeypatch: pytest.MonkeyPatch, pool: _FakePool) -> None:
    async def _fake_get_redis_pool(config: object = None) -> _FakePool:
        return pool

    monkeypatch.setattr(worker_module, "get_redis_pool", _fake_get_redis_pool)


def test_check_returns_zero_when_the_worker_sentinel_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _FakePool(b"j_complete=1")
    _use_pool(monkeypatch, pool)
    assert worker_module.main(["--check"]) == 0
    assert pool.requested_key == "arq:queue:health-check"
    assert pool.closed is True


def test_check_returns_one_when_no_worker_sentinel_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    pool = _FakePool(None)
    _use_pool(monkeypatch, pool)
    assert worker_module.main(["--check"]) == 1
    assert pool.closed is True


def test_check_returns_one_when_redis_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_pool(monkeypatch, _FakePool(None, fail=True))
    assert worker_module.main(["--check"]) == 1


def test_check_never_touches_the_database_role_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    def _must_not_run(engine: object) -> ApplicationRoleValidation:
        raise AssertionError("--check must not open a database connection")

    monkeypatch.setattr(worker_module, "validate_application_role", _must_not_run)
    _use_pool(monkeypatch, _FakePool(b"ok"))
    assert worker_module.main(["--check"]) == 0
