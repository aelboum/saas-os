"""`saas_os/core/api_keys` configuration (ledger row 954; ADR-0045 section
11f, amendment of 2026-10-31). Same shape as `saas_os/core/tenancy/config.py`:
a plain, non-secret tunable read from the environment, validated, cached
process-wide.

One tunable:

- `API_KEY_MAX_PER_USER` -- the most unrevoked user-owned API keys one user
  may hold, counted across every tenant. Default 50. It bounds what
  `revoke_user_api_keys` (a platform operation) revokes in one statement and
  the per-key evidence rows it writes, which were bounded by nothing but the
  user's own key count. An expired key that was never revoked still counts:
  the platform revocation reaches it too, and its owner can revoke it to
  free the slot. Service-account keys are not user-owned and do not count.

Missing configuration falls back to the default, never to "unbounded". A
value that is not an integer from 1 to 100000 is a configuration error,
raised when the configuration is read, so a key creation fails closed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from saas_os.core.api_keys.errors import ApiKeyConfigurationError

_DEFAULT_MAX_PER_USER = 50
_MAX_PER_USER_CEILING = 100_000


@dataclass(frozen=True)
class ApiKeyConfig:
    max_per_user: int = _DEFAULT_MAX_PER_USER

    def __post_init__(self) -> None:
        if not 1 <= self.max_per_user <= _MAX_PER_USER_CEILING:
            raise ApiKeyConfigurationError(
                f"API_KEY_MAX_PER_USER must be from 1 to {_MAX_PER_USER_CEILING}, "
                f"got: {self.max_per_user}"
            )


def _api_key_config_from_env() -> ApiKeyConfig:
    raw = os.environ.get("API_KEY_MAX_PER_USER")
    if raw is None or not raw.strip():
        return ApiKeyConfig()
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ApiKeyConfigurationError(
            f"API_KEY_MAX_PER_USER must be an integer, got: {raw!r}"
        ) from exc
    return ApiKeyConfig(max_per_user=value)


@lru_cache
def get_api_key_config() -> ApiKeyConfig:
    """Process-wide cached configuration, read once from the environment.
    Tests that need a different value call `get_api_key_config.cache_clear()`
    after `monkeypatch.setenv(...)`."""
    return _api_key_config_from_env()
