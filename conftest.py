"""Root pytest configuration -- hermetic default suite (post-audit F-01
remediation).

Several Core modules register their background-job handlers at *import*
time: `saas_os.core.webhooks`, `saas_os.core.usage`, and `saas_os.core.notifications` each build a
module-level `*_JOB_FUNCTIONS` list via `saas_os.infra.jobs.register_job()`, and
`register_job()` resolves `REDIS_URL` through the active `SecretsProvider`
right then. Any test module that imports `api.*` or one of those Core
modules therefore fails at *collection* -- `JobsConfigurationError:
REDIS_URL is not set` -- in an environment with no developer `.env` file.
That is exactly what CI is: `.github/workflows/ci.yml`'s `backend` job
provides no `.env`, no secret, and no Redis, and the suite must still
collect and run there (38 collection errors before this file existed).

This file supplies a test-only placeholder `REDIS_URL` for the pytest
process when, and only when, the active `SecretsProvider` cannot already
resolve one -- an explicitly exported variable or a developer's own
`.env` always wins, so nothing changes for a configured environment. The
placeholder is a loopback address no default-suite test ever connects to
(every test that talks to a real Redis is marked `integration` and
excluded from the default run); it exists solely so import-time job
registration can complete:

    no .env + no secrets + no external Redis + pytest  ->  collects and runs

CP-07 J-INFRA-04: `saas_os.infra.secrets.config._provider_from_env()` now
requires `ENVIRONMENT` to be set explicitly -- it no longer silently
defaults an unset value to `"development"` (a production deployment
that forgot to set it must fail loudly, not resolve to the permissive
posture). Bare `pytest` -- a developer's shell, or CI's `backend` job,
neither of which sets `ENVIRONMENT` -- would otherwise fail at
*collection*, the exact regression `_ensure_hermetic_redis_url()` above
already exists to prevent for `REDIS_URL`. `_ensure_environment_is_set()`
below applies the identical, narrowly-scoped pattern: `os.environ.setdefault`
only ever supplies `"test"` when nothing -- not a developer's own shell
export, not a real deployment's `.env`/`docker-compose.prod.yml` --
already set it. This file is never imported by `saas_os.api.server`/`saas_os.api.worker`
(module docstring above), so this default can never reach a real
deployment.

Runtime code is untouched. `saas_os.infra.jobs.config.get_jobs_config()` still
fails closed on a missing `REDIS_URL` (proven by
`tests/api/test_worker_unit.py::test_main_fails_closed_when_redis_url_is_missing`
and `tests/infra/jobs/test_jobs_config.py`), and `saas_os.api.server`/`saas_os.api.worker`
never import a `conftest`. The hermeticity guarantee itself is proven from
a scrubbed subprocess environment by
`tests/architecture/test_ci_hermeticity.py`.

Why the repository root and not `tests/conftest.py`: pytest's default
`prepend` import mode inserts a conftest's own directory into `sys.path`
when that directory is not a package. `tests/` contains `api/`, `core/`,
`infra/`, `control_plane/`, `contracts/` -- the same names as the real
top-level packages -- so a `tests/conftest.py` would put `tests/` ahead of
everything else and make `import infra` resolve to the *test* directory
as a namespace package (the editable-install finder runs after the path
finder). Inserting the repository root instead is harmless: it is where
the real regular packages already live.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator

import pytest

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import get_engine
from saas_os.infra.db.session import get_session_factory
from saas_os.infra.jobs.config import get_jobs_config
from saas_os.infra.secrets import get_secrets_provider

# Loopback, never a real deployment value, never connected to by the
# default suite (see module docstring).
_HERMETIC_REDIS_URL = "redis://127.0.0.1:6379/0"

# F-02 remediation: `saas_os.core.webhooks.service.subscribe()`/`_deliver_webhook()`
# now encrypt/decrypt the signing secret via `saas_os.core.crypto.EncryptionService`,
# whose default `SecretsBackedKeyProvider` resolves
# `FIELD_ENCRYPTION_ACTIVE_KEY_VERSION`/`FIELD_ENCRYPTION_KEY_<VERSION>`
# through the active `SecretsProvider` at first use -- exactly the same
# "no .env + no secrets + pytest" collection/call-time failure this file
# already exists to prevent for `REDIS_URL` above, now for any default-suite
# test that (directly or via `saas_os.core.webhooks`) calls `subscribe()`. A fixed,
# clearly-test-only 32-byte key, applied only when genuinely unset, mirrors
# `_ensure_hermetic_redis_url()`'s identical discipline: never a real key,
# never overriding a developer's own `.env` or a real deployment's secret.
_HERMETIC_FIELD_ENCRYPTION_KEY_VERSION = "test-v1"
_HERMETIC_FIELD_ENCRYPTION_KEY_B64 = (
    "p3EiRyKLPdlQI+1rfWLP3AlUt5ITRGh2AOY7gu4YbFU="  # pragma: allowlist secret
)


def _ensure_environment_is_set() -> None:
    """CP-07 J-INFRA-04: `os.environ.setdefault` -- an explicitly exported
    `ENVIRONMENT` (a developer's shell, CI, or a real deployment's
    `.env`/compose file) always wins; this only ever fills a genuinely
    absent value, and only for this pytest process."""
    os.environ.setdefault("ENVIRONMENT", "test")


def _ensure_hermetic_redis_url() -> None:
    try:
        if not get_secrets_provider().get("REDIS_URL"):
            os.environ["REDIS_URL"] = _HERMETIC_REDIS_URL
    finally:
        # Leave no cached provider singleton behind: the first real caller
        # constructs it exactly as it would have without this file, and
        # tests that `monkeypatch.setenv("ENVIRONMENT", ...)` then
        # `cache_clear()` observe the same starting state as before.
        get_secrets_provider.cache_clear()


def _ensure_hermetic_field_encryption_key() -> None:
    try:
        provider = get_secrets_provider()
        if not provider.get("FIELD_ENCRYPTION_ACTIVE_KEY_VERSION"):
            os.environ["FIELD_ENCRYPTION_ACTIVE_KEY_VERSION"] = (
                _HERMETIC_FIELD_ENCRYPTION_KEY_VERSION
            )
        key_name = f"FIELD_ENCRYPTION_KEY_{_HERMETIC_FIELD_ENCRYPTION_KEY_VERSION.upper()}"
        if not provider.get(key_name):
            os.environ[key_name] = _HERMETIC_FIELD_ENCRYPTION_KEY_B64
    finally:
        get_secrets_provider.cache_clear()


_ensure_environment_is_set()
_ensure_hermetic_redis_url()
_ensure_hermetic_field_encryption_key()


@pytest.fixture(autouse=True)
def _hermetic_credential_failure_limit(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """The failed-credential limit in `saas_os.api.dependencies` reads Redis
    before every authentication. The default suite has no Redis (module
    docstring), so for a test not marked `integration` the two limiter
    calls it makes are replaced by an in-memory counter with the same
    semantics; integration tests use the real limiter against real Redis
    (`tests/api/test_credential_failure_limit_integration.py`). Patched
    for every default-suite test, importing the module if need be, so no
    default-suite test can reach a real Redis through it."""
    if request.node.get_closest_marker("integration") is not None:
        yield
        return
    import saas_os.api.dependencies as deps
    from saas_os.infra.ratelimit import RateLimitResult

    counts: dict[str, int] = {}

    async def _peek(key: str, *, config: object, client: object = None) -> RateLimitResult:
        limit = getattr(config, "requests_per_window", 60)
        count = counts.get(key, 0)
        return RateLimitResult(
            allowed=count < limit, remaining=max(limit - count, 0), retry_after_seconds=60
        )

    async def _check(key: str, *, config: object, client: object = None) -> RateLimitResult:
        limit = getattr(config, "requests_per_window", 60)
        counts[key] = counts.get(key, 0) + 1
        return RateLimitResult(
            allowed=counts[key] <= limit,
            remaining=max(limit - counts[key], 0),
            retry_after_seconds=60,
        )

    monkeypatch.setattr(deps, "peek_rate_limit", _peek)
    monkeypatch.setattr(deps, "check_rate_limit", _check)
    yield


@pytest.fixture(autouse=True)
def _restore_root_logger_state() -> Iterator[None]:
    """RA-11-F7: `saas_os.infra.observability.logging.configure_logging()` calls
    `logging.basicConfig(..., force=True)`, which unconditionally closes
    and removes every handler currently on the root logger and installs
    its own JSON `StreamHandler(sys.stdout)` -- process-global state, by
    design, with no restoration of its own. Under `capsys`, the stream it
    binds is a per-test buffer already closed at that test's teardown, so
    the leaked handler raises `ValueError: I/O operation on closed file`
    on every INFO+ record any *later* test emits (168 such blocks
    reproduced across the default suite with `-s`, none of them changing
    a single test's pass/fail outcome -- `logging.Handler.emit()`'s own
    except-clause routes the failure to `handleError()`, which prints to
    stderr and never re-raises), and the root level stays at whatever
    `configure_logging()` last set it to.

    Snapshot the root logger's level and its exact handler objects (not
    reconstructions) before each test, restore both afterward. Any
    handler still on the root logger that was not there before -- the
    leaked JSON handler, or anything else a test installed -- is closed
    (safe: the base `logging.Handler.close()` only does registry
    bookkeeping, it never touches a handler's stream) and dropped.
    Pytest's own original handlers are put back untouched and are never
    closed *here* -- they are pytest's own infrastructure, not this
    fixture's to dispose of, and each already tolerates being closed by
    `configure_logging()` itself: its `_FileHandler` (`logging.FileHandler`
    under the hood) lazily reopens its target -- `os.devnull` by default
    -- on the next write, and its `_LiveLoggingNullHandler` never touches
    a stream at all. This fixture only has to stop a *newly installed*
    handler bound to an already-dead stream from remaining attached.
    """
    root = logging.getLogger()
    original_level = root.level
    original_handlers = root.handlers[:]
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            if handler not in original_handlers:
                try:
                    handler.close()
                except Exception:  # noqa: BLE001 -- best-effort cleanup, never mask the test
                    pass
        root.handlers[:] = original_handlers
        root.setLevel(original_level)


@pytest.fixture(autouse=True)
def _restore_db_config_cache() -> Iterator[None]:
    """S-05 (saas_os/infra/db/config.py, saas_os/infra/jobs/config.py): `get_database_config()`/
    `get_migrations_database_config()`/`get_engine()`/`get_session_factory()`/
    `get_jobs_config()` are all `@lru_cache` process-wide singletons, and
    each reads `ENVIRONMENT`/`DB_REQUIRE_TLS`/`REDIS_REQUIRE_TLS` to decide
    whether to demand an encrypted transport. Several integration test
    modules have a `monkeypatch.setenv("ENVIRONMENT", "production")`
    fixture to exercise production-shaped config -- exactly `monkeypatch`'s
    documented, auto-reverting pattern. Each such fixture now also pins
    `DB_REQUIRE_TLS=false`/`REDIS_REQUIRE_TLS=false` explicitly for the
    same reason `_apply_tls_requirement()`'s own docstring gives that
    escape hatch: these are disposable, plaintext CI service containers,
    never a real production connection (see e.g.
    `tests/control_plane/data_authorization/test_data_authorization_integration.py`
    and `tests/control_plane/test_tenant_lifecycle_fencing_integration.py`).
    This fixture is the defense-in-depth backstop, not the primary fix: even
    with every fixture correctly scoped, `monkeypatch` reverting an env var
    does not invalidate an `lru_cache` keyed on it, so a config built while
    a transient `ENVIRONMENT=production` was in effect would otherwise stay
    cached -- and TLS-required -- for every later test in the same process,
    against containers that were never configured for TLS. Same fix shape
    as `_restore_root_logger_state` above: process-global state, reset
    after every test regardless of which one touched it. Cheap even when
    nothing touched the cache (`lru_cache.cache_clear()` is a no-op on an
    empty cache), and never disposes a still-referenced `Engine` out from
    under a test already holding one -- only evicts the memo, so the next
    caller simply rebuilds from the (by-then-restored) environment.
    """
    try:
        yield
    finally:
        get_database_config.cache_clear()
        get_migrations_database_config.cache_clear()
        get_jobs_config.cache_clear()
        get_engine.cache_clear()
        get_session_factory.cache_clear()


_REFERENCE_CONSUMER_MIGRATIONS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "examples",
    "reference-consumer",
    "reference_consumer",
    "migrations",
)


def _saas_os_schema_is_migrated() -> bool:
    """`True` only for a configured, reachable database on which SaaS OS's
    own migrations have already run (the consumer's tables reference
    `core`). Anything else returns `False` -- integration tests then skip
    themselves exactly as before."""
    from sqlalchemy import text

    from saas_os.infra.db.engine import build_engine

    try:
        config = get_migrations_database_config()
    except Exception:  # noqa: BLE001 -- not configured
        return False
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            return conn.execute(text("SELECT to_regclass('core.tenants')")).scalar() is not None
    except Exception:  # noqa: BLE001 -- unreachable
        return False
    finally:
        engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def _reference_consumer_schema(request: pytest.FixtureRequest) -> None:
    """Apply the reference consumer's own migrations once, before any test.

    `examples/reference-consumer/reference_consumer/app.py` builds its app
    at import time, and `create_app()` registers the consumer's
    `WidgetPurgeParticipant` in Core's process-wide purge-participant
    registry. Collecting `tests/test_reference_consumer_route_security_
    integration.py` imports that module, so every later
    `saas_os.core.tenancy.purge_tenant()` in the same pytest process also purges
    `reference_consumer.widgets` -- a table from the consumer's own,
    separate migration history (ADR-0016) that only
    `tests/test_reference_consumer_integration.py` used to apply, and that
    file runs last. On a freshly migrated database every purge test before
    it failed with `relation "reference_consumer.widgets" does not exist`:
    a suite-ordering artifact, not a product defect.

    Uses the same mechanism as the reference consumer's own end-to-end
    driver (an Alembic `Config` whose `script_location` is the consumer's
    migration directory; its `env.py` reuses
    `saas_os.infra.db.config.get_migrations_database_config()`). `upgrade head` is
    idempotent. A no-op unless the session collected integration tests and
    the database is configured, reachable and already migrated by SaaS OS
    -- the hermetic default suite never touches a database because of
    this. Lives here, not in a `tests/conftest.py`: a conftest inside
    `tests/` would put `tests/` on `sys.path` before any package import,
    letting the `tests/control_plane` directory shadow the real
    `control_plane` package."""
    if not any(item.get_closest_marker("integration") for item in request.session.items):
        return
    if not _saas_os_schema_is_migrated():
        return

    from alembic import command
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", _REFERENCE_CONSUMER_MIGRATIONS)
    command.upgrade(config, "head")
