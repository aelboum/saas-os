"""`SecretsProvider` selection (docs/IMPLEMENTATION-ROADMAP.md Phase 2.3,
docs/ADR/0012-secrets-management.md).

Reads `ENVIRONMENT` directly from the process environment to pick the
implementation -- the same conventional variable `core/config/settings.py`
and `infra/observability/config.py` already read directly, independently,
without importing each other or `core` (`infra` depends on nothing above
it, docs/ARCHITECTURE.md section 2). `ENVIRONMENT` itself is not a secret,
so reading it directly here (rather than through the provider it's used
to select) is not a boundary violation.
"""

from __future__ import annotations

import os
from functools import lru_cache

from infra.secrets.provider import SecretsConfigurationError, SecretsProvider
from infra.secrets.providers import EnvFileSecretsProvider, EnvironmentSecretsProvider

_VALID_ENVIRONMENTS = frozenset({"development", "test", "production"})


def _provider_from_env() -> SecretsProvider:
    environment = os.environ.get("ENVIRONMENT", "development")
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
