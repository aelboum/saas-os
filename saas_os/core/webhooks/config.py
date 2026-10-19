"""`saas_os/core/webhooks` replay-protection configuration (P1.10). Mirrors
`saas_os/infra/ratelimit/config.py`'s own shape exactly: a plain, non-secret
tunable read directly from the environment (never through
`saas_os.infra.secrets` -- a tolerance window is not a credential), validated,
and cached process-wide.

`WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS` bounds how old (or how far in the
future) a delivery's timestamp may be before `verify_webhook_signature()`
rejects it -- the actual replay-protection mechanism for a captured,
still-cryptographically-valid old signature (module docstring,
`saas_os/core/webhooks/service.py`). The default (300 seconds / 5 minutes)
mirrors Stripe's own published default tolerance for exactly the same
purpose -- a conservative, industry-precedented value, not an arbitrary
guess. Missing configuration always falls back to this safe default
(never to "no tolerance check at all") -- replay protection must never
be silently disabled by an absent environment variable.

`WEBHOOK_ALLOWED_PORTS` (ADR-0035 amendment of 2026-10-19) optionally
limits the ports a webhook URL may use: a comma-separated list such as
`443,80`. Unset, any port is allowed (ADR-0035's contract). Set to anything
that is not a list of ports from 1 to 65535 -- including an empty value --
it is a configuration error, never "allow everything".
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from saas_os.core.webhooks.errors import WebhookConfigurationError

_DEFAULT_TOLERANCE_SECONDS = 300
_ALLOWED_PORTS_VARIABLE = "WEBHOOK_ALLOWED_PORTS"


@dataclass(frozen=True)
class WebhookSecurityConfig:
    tolerance_seconds: int = _DEFAULT_TOLERANCE_SECONDS
    # None: any port. Otherwise the only ports a webhook URL may use.
    allowed_ports: frozenset[int] | None = None

    def __post_init__(self) -> None:
        if self.tolerance_seconds < 1:
            raise WebhookConfigurationError(
                f"WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS must be >= 1, got: {self.tolerance_seconds}"
            )
        if self.allowed_ports is not None and (
            not self.allowed_ports or any(not 1 <= port <= 65535 for port in self.allowed_ports)
        ):
            raise WebhookConfigurationError(
                f"{_ALLOWED_PORTS_VARIABLE} must list ports from 1 to 65535"
            )


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise WebhookConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _parse_ports(raw: str) -> frozenset[int]:
    items = [item.strip() for item in raw.split(",")]
    if not all(item.isascii() and item.isdigit() for item in items):
        raise WebhookConfigurationError(
            f"{_ALLOWED_PORTS_VARIABLE} must be a comma-separated list of ports, got: {raw!r}"
        )
    return frozenset(int(item) for item in items)


def _webhook_security_config_from_env() -> WebhookSecurityConfig:
    tolerance_raw = os.environ.get("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS")
    ports_raw = os.environ.get(_ALLOWED_PORTS_VARIABLE)
    return WebhookSecurityConfig(
        tolerance_seconds=(
            _parse_int("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS", tolerance_raw)
            if tolerance_raw is not None
            else _DEFAULT_TOLERANCE_SECONDS
        ),
        allowed_ports=_parse_ports(ports_raw) if ports_raw is not None else None,
    )


@lru_cache
def get_webhook_security_config() -> WebhookSecurityConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need a different tolerance should call
    `get_webhook_security_config.cache_clear()` after
    `monkeypatch.setenv(...)`.
    """
    return _webhook_security_config_from_env()
