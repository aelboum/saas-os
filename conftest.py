"""Root pytest configuration -- hermetic default suite (post-audit F-01
remediation).

Several Core modules register their background-job handlers at *import*
time: `core.webhooks`, `core.usage`, and `core.notifications` each build a
module-level `*_JOB_FUNCTIONS` list via `infra.jobs.register_job()`, and
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

CP-07 J-INFRA-04: `infra.secrets.config._provider_from_env()` now
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
already set it. This file is never imported by `api.server`/`api.worker`
(module docstring above), so this default can never reach a real
deployment.

Runtime code is untouched. `infra.jobs.config.get_jobs_config()` still
fails closed on a missing `REDIS_URL` (proven by
`tests/api/test_worker_unit.py::test_main_fails_closed_when_redis_url_is_missing`
and `tests/infra/jobs/test_jobs_config.py`), and `api.server`/`api.worker`
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
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import get_engine
from infra.db.session import get_session_factory
from infra.jobs.config import get_jobs_config

from infra.secrets import get_secrets_provider

# Loopback, never a real deployment value, never connected to by the
# default suite (see module docstring).
_HERMETIC_REDIS_URL = "redis://127.0.0.1:6379/0"


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


_ensure_environment_is_set()
_ensure_hermetic_redis_url()


@pytest.fixture(autouse=True)
def _restore_root_logger_state() -> Iterator[None]:
    """RA-11-F7: `infra.observability.logging.configure_logging()` calls
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
    """S-05 (infra/db/config.py, infra/jobs/config.py): `get_database_config()`/
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
