"""F-01 regression (post-audit): the default, non-`integration` test
suite must collect and execute in a clean, CI-shaped environment --

    no developer `.env`
    no `REDIS_URL` / `DATABASE_URL` / `MIGRATIONS_DATABASE_URL`
    no production secret of any kind
    no reachable Redis or PostgreSQL
    plain `pytest`

`.github/workflows/ci.yml`'s `backend` job is exactly that environment.
Before the repository-root `conftest.py` supplied its test-only placeholder `REDIS_URL`,
38 test modules failed at collection there with
`infra.jobs.errors.JobsConfigurationError: REDIS_URL is not set` (import-
time `infra.jobs.register_job()` calls in `core.webhooks`/`core.usage`/
`core.notifications`), so the backend job was red on every push and no
backend regression was actually being caught by CI.

Both tests below run `pytest` in a *subprocess* whose environment has
been scrubbed of every secret-bearing/connection variable and whose
`SECRETS_ENV_FILE` points at a file that does not exist (so the
development `EnvFileSecretsProvider` resolves nothing from the developer's
real `.env`, even on a machine that has one). This is the only faithful
way to prove the property: the outer pytest process may itself have been
started with a `.env` present, and the repository-root `conftest.py` has already run
inside it.

Nothing here weakens the runtime's own fail-closed behavior -- see
the repository-root `conftest.py`'s docstring for the exact boundary.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Every variable the default suite must NOT need. Scrubbed from the
# subprocess environment regardless of what the outer process has.
_SCRUBBED_VARIABLES = frozenset(
    {
        "ENVIRONMENT",
        "REDIS_URL",
        "DATABASE_URL",
        "MIGRATIONS_DATABASE_URL",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "POSTGRES_DB",
        "APP_DB_USER",
        "APP_DB_PASSWORD",
        "ZITADEL_ISSUER_URL",
        "ZITADEL_CLIENT_ID",
        "ZITADEL_CLIENT_SECRET",
        "OIDC_REDIRECT_URI",
        "STRIPE_API_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "SMTP_HOST",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "GITHUB_TOKEN",
        "BACKUP_ENCRYPTION_RECIPIENT",
        "BACKUP_ENCRYPTION_IDENTITY",
        "BACKUP_S3_ENDPOINT_URL",
        "BACKUP_S3_BUCKET",
        "BACKUP_S3_ACCESS_KEY_ID",
        "BACKUP_S3_SECRET_ACCESS_KEY",
    }
)

# A module that imports `api.main` (and therefore every job-registering
# Core module) and was one of the 38 collection failures before the fix.
_PREVIOUSLY_NON_HERMETIC_MODULE = "tests/api/test_cors_unit.py"


def _scrubbed_environment(tmp_path: Path) -> dict[str, str]:
    env = {
        key: value for key, value in os.environ.items() if key.upper() not in _SCRUBBED_VARIABLES
    }
    # `infra.secrets.config` honors this override for the development
    # provider: pointing it at a file that does not exist guarantees the
    # subprocess sees no `.env` content, whatever the outer machine has.
    env["SECRETS_ENV_FILE"] = str(tmp_path / "no-such.env")
    assert "REDIS_URL" not in env
    assert "DATABASE_URL" not in env
    return env


def _run_pytest(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_default_suite_collects_with_no_env_file_and_no_redis_url(tmp_path: Path) -> None:
    """The whole default suite (pyproject's `-m "not integration"` applies
    in the subprocess too) collects cleanly from a scrubbed environment --
    zero collection errors, exit 0."""
    result = _run_pytest(["--collect-only"], _scrubbed_environment(tmp_path))
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]
    # pytest's own collection-failure markers -- not a substring search
    # over node ids, many of which legitimately contain "error".
    assert "errors during collection" not in result.stdout, result.stdout[-4000:]
    assert not [line for line in result.stdout.splitlines() if line.startswith("ERROR ")], (
        result.stdout[-4000:]
    )
    assert "tests collected" in result.stdout


def test_a_previously_non_hermetic_module_executes_with_no_env_file(tmp_path: Path) -> None:
    """Collection alone is not execution: a module that imports the real
    FastAPI app (and so every import-time job registration) runs its
    tests to completion, and passes, from the same scrubbed environment."""
    assert (REPO_ROOT / _PREVIOUSLY_NON_HERMETIC_MODULE).is_file()
    result = _run_pytest([_PREVIOUSLY_NON_HERMETIC_MODULE], _scrubbed_environment(tmp_path))
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]
    assert " passed" in result.stdout
    assert "REDIS_URL is not set" not in result.stdout + result.stderr
