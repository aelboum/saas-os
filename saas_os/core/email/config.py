"""`saas_os/core/email` configuration (P1.12; provider selection ADR-0057).
Mirrors `saas_os/infra/ratelimit/config.py`'s own shape: plain, non-secret
tunables read directly from the environment, validated.

Three independent groups, deliberately kept apart (ADR-0057):

- **Provider selection** -- `EMAIL_PROVIDER` (`get_email_provider_name()`):
  one of the built-in names in `EMAIL_PROVIDER_NAMES`, or unset. Unset keeps
  the pre-ADR-0057 behavior exactly: the SMTP provider, configured by
  `SMTP_HOST`.
- **Sender** -- `EMAIL_DEFAULT_SENDER` (`get_email_default_sender()`): the
  deployment-wide `From:` address, independent of any one provider's
  transport settings, so a non-SMTP provider never needs `SMTP_HOST` just to
  name a sender.
- **SMTP transport** -- `SMTP_HOST`/`SMTP_PORT`/`SMTP_TLS_MODE` (or its
  legacy alias `SMTP_USE_TLS`)/`SMTP_REQUIRE_TLS`/`EMAIL_TIMEOUT_SECONDS`
  (`EmailConfig`, `get_email_config()`), and the development-only Mailpit
  endpoint (`MailpitConfig`, `get_mailpit_config()`).

Deliberately excludes the SMTP username/password -- those are secrets
(docs/ADR/0012-secrets-management.md) and are read only where they are
actually used, inside `saas_os/core/email/smtp_provider.py::SmtpEmailProvider.__init__()`,
through `saas_os.infra.secrets.get_secrets_provider()`, never stored on these
dataclasses or anywhere else in `saas_os/core/email` (P1.12's Critical secret
rule: no new secret-consuming call site outside `SecretsProvider`, and no
secret persisted in a configuration object a log line or exception could
ever repr()/format()).

**Production TLS (ADR-0057, following ADR-0021)**: when `ENVIRONMENT=production`,
`SMTP_REQUIRE_TLS` defaults to true and a plaintext SMTP transport
(`SMTP_TLS_MODE=none`, or `SMTP_USE_TLS=false`) is refused. An operator with
a justified reason may set `SMTP_REQUIRE_TLS=false` explicitly -- the same
application-level override `DB_REQUIRE_TLS`/`REDIS_REQUIRE_TLS` provide. No
setting disables certificate validation (`smtp_provider.py`).

**Mailpit is never a production provider**: `get_mailpit_config()` refuses
to resolve unless `ENVIRONMENT` is explicitly `development` or `test`, with
no override (ADR-0057).

Missing configuration is not a hard startup failure by itself -- `saas_os/core/email`
is not wired as a mandatory dependency of `saas_os/api/main.py`'s own startup
`lifespan` (P1.12's "must not crash unrelated application startup unless
email is explicitly configured as mandatory"); a `get_email_config()` call
only fails, deterministically, if and when something actually tries to send
an email with no configuration present. Setting `EMAIL_PROVIDER` explicitly
is that "configured as mandatory" signal: the worker then validates the
configuration at startup (`saas_os/core/email/selection.py::validate_email_configuration()`).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from saas_os.core.email.errors import EmailConfigurationError

_DEFAULT_SMTP_PORT = 587
_DEFAULT_TLS_MODE = "starttls"
_DEFAULT_TIMEOUT_SECONDS = 10
_DEFAULT_MAILPIT_HOST = "mailpit"
_DEFAULT_MAILPIT_PORT = 1025

# The fixed, built-in provider names (ADR-0057). A new adapter is added by a
# SaaS-OS change: a name here, and a factory in `selection.py`.
EMAIL_PROVIDER_NAMES = ("smtp", "mailpit")

# `starttls`: plaintext connect, then STARTTLS (port 587). `implicit`: TLS
# from the first byte (port 465). `none`: plaintext, development only unless
# `SMTP_REQUIRE_TLS=false` is set explicitly.
SMTP_TLS_MODES = ("starttls", "implicit", "none")

# Mailpit may only be selected in these environments -- an explicit allow
# list, so an unset or unrecognized `ENVIRONMENT` is refused too.
_MAILPIT_ENVIRONMENTS = frozenset({"development", "test"})

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True)
class EmailConfig:
    """SMTP transport settings. `use_tls` is the pre-ADR-0057 boolean and
    `tls_mode` the full setting; either may be given, and after construction
    both are always set and consistent (`use_tls` is true exactly when
    `tls_mode` is not `none`). Giving both with conflicting meanings is a
    configuration error, never a silent preference for one."""

    smtp_host: str
    smtp_port: int = _DEFAULT_SMTP_PORT
    use_tls: bool | None = None
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS
    default_sender: str | None = None
    tls_mode: str | None = None
    require_tls: bool = False

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

        tls_mode = self.tls_mode
        if tls_mode is None:
            tls_mode = "none" if self.use_tls is False else _DEFAULT_TLS_MODE
        elif tls_mode not in SMTP_TLS_MODES:
            raise EmailConfigurationError(
                f"SMTP_TLS_MODE must be one of {list(SMTP_TLS_MODES)}, got: {tls_mode!r}"
            )
        elif self.use_tls is not None and self.use_tls != (tls_mode != "none"):
            raise EmailConfigurationError(
                f"SMTP_USE_TLS={str(self.use_tls).lower()} contradicts "
                f"SMTP_TLS_MODE={tls_mode!r}; set only SMTP_TLS_MODE."
            )
        if self.require_tls and tls_mode == "none":
            raise EmailConfigurationError(
                "SMTP TLS is required (ENVIRONMENT=production, or SMTP_REQUIRE_TLS=true) but "
                "SMTP_TLS_MODE is 'none'. Use 'starttls' or 'implicit'; set "
                "SMTP_REQUIRE_TLS=false only for a deliberately plaintext relay "
                "(see docs/ADR/0057-deployment-level-email-provider-selection.md)."
            )
        object.__setattr__(self, "tls_mode", tls_mode)
        object.__setattr__(self, "use_tls", tls_mode != "none")


@dataclass(frozen=True)
class MailpitConfig:
    """The development-only Mailpit SMTP endpoint (ADR-0057). Never TLS,
    never credentials: Mailpit is a local mail catcher, not a relay."""

    smtp_host: str = _DEFAULT_MAILPIT_HOST
    smtp_port: int = _DEFAULT_MAILPIT_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if not self.smtp_host or not self.smtp_host.strip():
            raise EmailConfigurationError("MAILPIT_SMTP_HOST must be a non-empty string.")
        if not 1 <= self.smtp_port <= 65535:
            raise EmailConfigurationError(
                f"MAILPIT_SMTP_PORT must be between 1 and 65535, got: {self.smtp_port}"
            )
        if self.timeout_seconds < 1:
            raise EmailConfigurationError(
                f"EMAIL_TIMEOUT_SECONDS must be >= 1, got: {self.timeout_seconds}"
            )


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise EmailConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise EmailConfigurationError(f"{name} must be a boolean-like value, got: {raw!r}")


def _timeout_from_env() -> int:
    raw = os.environ.get("EMAIL_TIMEOUT_SECONDS")
    return _parse_int("EMAIL_TIMEOUT_SECONDS", raw) if raw is not None else _DEFAULT_TIMEOUT_SECONDS


def _require_tls_default() -> bool:
    """ADR-0021's convention, applied to SMTP: required in production unless
    `SMTP_REQUIRE_TLS` explicitly says otherwise; not required elsewhere
    unless `SMTP_REQUIRE_TLS` explicitly says so."""
    override = os.environ.get("SMTP_REQUIRE_TLS")
    if override is not None:
        return _parse_bool("SMTP_REQUIRE_TLS", override)
    return os.environ.get("ENVIRONMENT") == "production"


def _email_config_from_env() -> EmailConfig:
    smtp_host = os.environ.get("SMTP_HOST")
    if not smtp_host:
        raise EmailConfigurationError(
            "SMTP_HOST is not set. Copy .env.example to .env and set a value "
            "(see docs/ADR/0012-secrets-management.md)."
        )

    port_raw = os.environ.get("SMTP_PORT")
    use_tls_raw = os.environ.get("SMTP_USE_TLS")
    tls_mode_raw = os.environ.get("SMTP_TLS_MODE") or None

    return EmailConfig(
        smtp_host=smtp_host,
        smtp_port=(
            _parse_int("SMTP_PORT", port_raw) if port_raw is not None else _DEFAULT_SMTP_PORT
        ),
        use_tls=_parse_bool("SMTP_USE_TLS", use_tls_raw) if use_tls_raw is not None else None,
        tls_mode=tls_mode_raw.strip().lower() if tls_mode_raw is not None else None,
        require_tls=_require_tls_default(),
        timeout_seconds=_timeout_from_env(),
        default_sender=os.environ.get("EMAIL_DEFAULT_SENDER") or None,
    )


@lru_cache
def get_email_config() -> EmailConfig:
    """Process-wide cached SMTP configuration singleton, read once from the
    environment. Tests that need a different configuration should call
    `get_email_config.cache_clear()` after `monkeypatch.setenv(...)`.
    Raises `EmailConfigurationError` if `SMTP_HOST` is unset -- callers
    that need email to be optional (module docstring) catch this rather
    than requiring it eagerly at import/startup time.
    """
    return _email_config_from_env()


def get_email_provider_name() -> str | None:
    """The explicitly configured provider name, or `None` when
    `EMAIL_PROVIDER` is unset or empty (the legacy SMTP default, module
    docstring). An unknown name is a configuration error -- never a silent
    fallback to another provider. Not cached: it is one environment read."""
    raw = os.environ.get("EMAIL_PROVIDER")
    if raw is None or not raw.strip():
        return None
    name = raw.strip().lower()
    if name not in EMAIL_PROVIDER_NAMES:
        raise EmailConfigurationError(
            f"EMAIL_PROVIDER must be one of {list(EMAIL_PROVIDER_NAMES)}, got: {raw!r}"
        )
    return name


def get_email_default_sender() -> str | None:
    """`EMAIL_DEFAULT_SENDER`, independent of any provider's transport
    settings (ADR-0057). `None` when unset or empty; a whitespace-only value
    is a configuration error, as it always was on `EmailConfig`."""
    raw = os.environ.get("EMAIL_DEFAULT_SENDER")
    if raw is None or raw == "":
        return None
    if not raw.strip():
        raise EmailConfigurationError("EMAIL_DEFAULT_SENDER must not be blank if set.")
    return raw


def assert_mailpit_environment() -> None:
    """Refuse Mailpit outside an explicit development or test environment
    (ADR-0057: never in production, no override). Called both when the
    Mailpit configuration is resolved and when a Mailpit provider is
    constructed, so neither path alone can route production mail to it."""
    environment = os.environ.get("ENVIRONMENT")
    if environment not in _MAILPIT_ENVIRONMENTS:
        raise EmailConfigurationError(
            "EMAIL_PROVIDER=mailpit is a development-only provider and is refused unless "
            f"ENVIRONMENT is one of {sorted(_MAILPIT_ENVIRONMENTS)}, got: {environment!r}."
        )


def get_mailpit_config() -> MailpitConfig:
    """The Mailpit endpoint from `MAILPIT_SMTP_HOST`/`MAILPIT_SMTP_PORT`
    (defaults: the `mailpit` Compose service on port 1025). Never reads any
    `SMTP_*` setting, so production SMTP settings and the development mail
    catcher cannot be swapped for each other by a mistaken variable."""
    assert_mailpit_environment()
    port_raw = os.environ.get("MAILPIT_SMTP_PORT")
    return MailpitConfig(
        smtp_host=os.environ.get("MAILPIT_SMTP_HOST") or _DEFAULT_MAILPIT_HOST,
        smtp_port=(
            _parse_int("MAILPIT_SMTP_PORT", port_raw)
            if port_raw is not None
            else _DEFAULT_MAILPIT_PORT
        ),
        timeout_seconds=_timeout_from_env(),
    )
