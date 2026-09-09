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

import os

from infra.secrets import get_secrets_provider

# Loopback, never a real deployment value, never connected to by the
# default suite (see module docstring).
_HERMETIC_REDIS_URL = "redis://127.0.0.1:6379/0"


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


_ensure_hermetic_redis_url()
