"""`core/email` configuration (P1.12). Mirrors `infra/ratelimit/config.py`'s
own shape: plain, non-secret connection tunables read directly from the
environment, validated, cached process-wide.

Deliberately excludes the SMTP username/password -- those are secrets
(docs/ADR/0012-secrets-management.md) and are read only where they are
actually used, inside `core/email/smtp_provider.py::SmtpEmailProvider.__init__()`,
through `infra.secrets.get_secrets_provider()`, never stored on this
dataclass or anywhere else in `core/email` (this checkpoint's own
Critical secret rule: no new secret-consuming call site outside
`SecretsProvider`, and no secret persisted in a cached configuration
object a log line or exception could ever repr()/format()).

Missing configuration is not a hard startup failure by itself -- `core/email`
is not wired as a mandatory dependency of `api/main.py`'s own startup
`lifespan` (this checkpoint's own "must not crash unrelated application
startup unless email is explicitly configured as mandatory"); a
`get_email_config()` call only fails, deterministically, if and when
something actually tries to send an email with no configuration present.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from core.email.errors import EmailConfigurationError

_DEFAULT_SMTP_PORT = 587
_DEFAULT_USE_TLS = True
_DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class EmailConfig:
    smtp_host: str
    smtp_port: int = _DEFAULT_SMTP_PORT
    use_tls: bool = _DEFAULT_USE_TLS
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS
    default_sender: str | None = None

    def __post_init__(self) -> None:
        if not self.smtp_host or not self.smtp_host.strip():
            raise EmailConfigurationError("SMTP_HOST must be a non-empty string.")
        if not 1 <= self.smtp_port <= 65535:
            raise EmailConfigurationError(
                f"SMTP_PORT must be between 1 and 65535, got: {self.smtp_port}"
            )
        if self.timeout_seconds < 1:
            raise EmailConfigurationError(
                f"EMAIL_TIMEOUT_SECONDS must be >= 1, got: {self.timeout_seconds}"
            )
        if self.default_sender is not None and not self.default_sender.strip():
            raise EmailConfigurationError("EMAIL_DEFAULT_SENDER must not be blank if set.")


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise EmailConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise EmailConfigurationError(f"{name} must be a boolean-like value, got: {raw!r}")


def _email_config_from_env() -> EmailConfig:
    smtp_host = os.environ.get("SMTP_HOST")
    if not smtp_host:
        raise EmailConfigurationError(
            "SMTP_HOST is not set. Copy .env.example to .env and set a value "
            "(see docs/ADR/0012-secrets-management.md)."
        )

    port_raw = os.environ.get("SMTP_PORT")
    use_tls_raw = os.environ.get("SMTP_USE_TLS")
    timeout_raw = os.environ.get("EMAIL_TIMEOUT_SECONDS")
    default_sender = os.environ.get("EMAIL_DEFAULT_SENDER") or None

    return EmailConfig(
        smtp_host=smtp_host,
        smtp_port=(
            _parse_int("SMTP_PORT", port_raw) if port_raw is not None else _DEFAULT_SMTP_PORT
        ),
        use_tls=(
            _parse_bool("SMTP_USE_TLS", use_tls_raw)
            if use_tls_raw is not None
            else _DEFAULT_USE_TLS
        ),
        timeout_seconds=(
            _parse_int("EMAIL_TIMEOUT_SECONDS", timeout_raw)
            if timeout_raw is not None
            else _DEFAULT_TIMEOUT_SECONDS
        ),
        default_sender=default_sender,
    )


@lru_cache
def get_email_config() -> EmailConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need a different configuration should call
    `get_email_config.cache_clear()` after `monkeypatch.setenv(...)`.
    Raises `EmailConfigurationError` if `SMTP_HOST` is unset -- callers
    that need email to be optional (module docstring) catch this rather
    than requiring it eagerly at import/startup time.
    """
    return _email_config_from_env()
