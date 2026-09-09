"""`core/webhooks` replay-protection configuration (P1.10). Mirrors
`infra/ratelimit/config.py`'s own shape exactly: a plain, non-secret
tunable read directly from the environment (never through
`infra.secrets` -- a tolerance window is not a credential), validated,
and cached process-wide.

`WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS` bounds how old (or how far in the
future) a delivery's timestamp may be before `verify_webhook_signature()`
rejects it -- the actual replay-protection mechanism for a captured,
still-cryptographically-valid old signature (module docstring,
`core/webhooks/service.py`). The default (300 seconds / 5 minutes)
mirrors Stripe's own published default tolerance for exactly the same
purpose -- a conservative, industry-precedented value, not an arbitrary
guess. Missing configuration always falls back to this safe default
(never to "no tolerance check at all") -- replay protection must never
be silently disabled by an absent environment variable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from core.webhooks.errors import WebhookConfigurationError

_DEFAULT_TOLERANCE_SECONDS = 300


@dataclass(frozen=True)
class WebhookSecurityConfig:
    tolerance_seconds: int = _DEFAULT_TOLERANCE_SECONDS

    def __post_init__(self) -> None:
        if self.tolerance_seconds < 1:
            raise WebhookConfigurationError(
                f"WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS must be >= 1, got: {self.tolerance_seconds}"
            )


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise WebhookConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _webhook_security_config_from_env() -> WebhookSecurityConfig:
    tolerance_raw = os.environ.get("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS")
    return WebhookSecurityConfig(
        tolerance_seconds=(
            _parse_int("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS", tolerance_raw)
            if tolerance_raw is not None
            else _DEFAULT_TOLERANCE_SECONDS
        )
    )


@lru_cache
def get_webhook_security_config() -> WebhookSecurityConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need a different tolerance should call
    `get_webhook_security_config.cache_clear()` after
    `monkeypatch.setenv(...)`.
    """
    return _webhook_security_config_from_env()
