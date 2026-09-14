"""`SecretsProvider` selection (docs/IMPLEMENTATION-ROADMAP.md Phase 2.3,
docs/ADR/0012-secrets-management.md).

Reads `ENVIRONMENT` directly from the process environment to pick the
implementation -- the same conventional variable `core/config/settings.py`
and `infra/observability/config.py` already read directly, independently,
without importing each other or `core` (`infra` depends on nothing above
it, docs/ARCHITECTURE.md section 2). `ENVIRONMENT` itself is not a secret,
so reading it directly here (rather than through the provider it's used
to select) is not a boundary violation.

CP-07 J-INFRA-04: `ENVIRONMENT` is required -- there is no default. An
earlier version of this function defaulted an *unset* `ENVIRONMENT` to
`"development"`, the same as explicitly setting it: a production
deployment that forgot to set `ENVIRONMENT` at all (e.g. a custom
secrets-injection path that never used this repository's own
`docker-compose.prod.yml`/`.env` convention) would silently get the
permissive, `.env`-file-reading `EnvFileSecretsProvider` instead of the
strict `EnvironmentSecretsProvider` -- a misconfiguration that must fail
loudly, not resolve to the more permissive posture (the same "every
branch that is not the one explicit safe case raises" discipline
`infra/db/role_guard.py` already holds its own fail-closed startup guard
to). `conftest.py` (repository root) is the one sanctioned place that
supplies a test-only `ENVIRONMENT` default, mirroring how it already
supplies a test-only `REDIS_URL` placeholder -- never here, and never in
any application runtime path.
"""

from __future__ import annotations

import os
from functools import lru_cache

from infra.secrets.provider import SecretsConfigurationError, SecretsProvider
from infra.secrets.providers import EnvFileSecretsProvider, EnvironmentSecretsProvider

_VALID_ENVIRONMENTS = frozenset({"development", "test", "production"})


def _provider_from_env() -> SecretsProvider:
    environment = os.environ.get("ENVIRONMENT")
    if environment is None:
        raise SecretsConfigurationError(
            "ENVIRONMENT is not set. Refusing to default to a permissive "
            "posture -- set it explicitly to one of "
            f"{sorted(_VALID_ENVIRONMENTS)} (see docs/ADR/0012-secrets-management.md)."
        )
    if environment not in _VALID_ENVIRONMENTS:
        allowed = sorted(_VALID_ENVIRONMENTS)
        raise SecretsConfigurationError(
            f"ENVIRONMENT must be one of {allowed}, got: {environment!r}"
        )

    if environment == "development":
        env_file = os.environ.get("SECRETS_ENV_FILE", ".env")
        return EnvFileSecretsProvider(path=env_file)

    return EnvironmentSecretsProvider()


@lru_cache
def get_secrets_provider() -> SecretsProvider:
    """Process-wide cached provider singleton, selected once from
    `ENVIRONMENT`. Tests that need a different `ENVIRONMENT` (or a
    different resolved secret) should call `get_secrets_provider.cache_clear()`
    after `monkeypatch.setenv(...)` -- the same convention used by
    `get_database_config`/`get_observability_config`.
    """
    return _provider_from_env()
