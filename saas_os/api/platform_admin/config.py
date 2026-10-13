"""Configuration of the opt-in platform-admin HTTP surface
(docs/ADR/0045-installation-scoped-platform-authority.md section 7).

Two settings:

`PLATFORM_ADMIN_HTTP_ENABLED`
    The deployment's half of the two opt-ins. The platform-admin router is
    served only if a product mounts it in code *and* this is `true`.
    Unset or `false`: not enabled, and an application that mounted the
    router fails startup. Any other value is a configuration error.

`PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS`
    How old the presenting session may be on a route that changes platform
    authority (decision D2). Default and maximum 900; a deployment may
    lower it, to no less than 60. A value outside 60 to 900 is a
    configuration error: there is one limit, and it cannot be raised.

Both are read at application startup by `saas_os.api.platform`'s lifespan,
so an invalid value stops the application before it serves a request.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

MAX_AUTHORITY_SESSION_AGE_SECONDS = 900
MIN_AUTHORITY_SESSION_AGE_SECONDS = 60

_ENABLED = "PLATFORM_ADMIN_HTTP_ENABLED"
_MAX_AGE = "PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS"


class PlatformAdminHttpConfigurationError(ValueError):
    """One of the two settings has a value outside what it accepts."""


@dataclass(frozen=True)
class PlatformAdminHttpConfig:
    enabled: bool = False
    authority_session_max_age_seconds: int = MAX_AUTHORITY_SESSION_AGE_SECONDS

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise PlatformAdminHttpConfigurationError(f"{_ENABLED} must be true or false.")
        age = self.authority_session_max_age_seconds
        if (
            isinstance(age, bool)
            or not isinstance(age, int)
            or not MIN_AUTHORITY_SESSION_AGE_SECONDS <= age <= MAX_AUTHORITY_SESSION_AGE_SECONDS
        ):
            raise PlatformAdminHttpConfigurationError(
                f"{_MAX_AGE} must be an integer between {MIN_AUTHORITY_SESSION_AGE_SECONDS} "
                f"and {MAX_AUTHORITY_SESSION_AGE_SECONDS}, got: {age!r}"
            )


def _config_from_env() -> PlatformAdminHttpConfig:
    raw_enabled = os.environ.get(_ENABLED)
    if raw_enabled is None or raw_enabled == "false":
        enabled = False
    elif raw_enabled == "true":
        enabled = True
    else:
        # Exactly `true` or `false`: a typo must not be read as either.
        raise PlatformAdminHttpConfigurationError(
            f"{_ENABLED} must be exactly 'true' or 'false', got: {raw_enabled!r}"
        )
    raw_age = os.environ.get(_MAX_AGE)
    if raw_age is None:
        return PlatformAdminHttpConfig(enabled=enabled)
    try:
        age = int(raw_age)
    except ValueError as exc:
        raise PlatformAdminHttpConfigurationError(
            f"{_MAX_AGE} must be an integer, got: {raw_age!r}"
        ) from exc
    return PlatformAdminHttpConfig(enabled=enabled, authority_session_max_age_seconds=age)


@lru_cache
def get_platform_admin_http_config() -> PlatformAdminHttpConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need a different value call
    `get_platform_admin_http_config.cache_clear()` after
    `monkeypatch.setenv(...)`."""
    return _config_from_env()
