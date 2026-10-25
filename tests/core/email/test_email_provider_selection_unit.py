"""ADR-0057 -- deployment-level email provider selection: `EMAIL_PROVIDER`,
the sender read independently of SMTP, SMTP TLS modes and the production TLS
requirement, the development-only Mailpit provider, and the worker's startup
validation. Pure unit tests: no network (provider construction never
connects), no database.
"""

from __future__ import annotations

import pytest

from saas_os.core.email import selection
from saas_os.core.email.config import (
    EMAIL_PROVIDER_NAMES,
    EmailConfig,
    MailpitConfig,
    get_email_config,
    get_email_default_sender,
    get_email_provider_name,
    get_mailpit_config,
)
from saas_os.core.email.errors import EmailConfigurationError
from saas_os.core.email.resend_provider import ResendEmailProvider
from saas_os.core.email.selection import get_email_provider, validate_email_configuration
from saas_os.core.email.smtp_provider import MailpitEmailProvider, SmtpEmailProvider
from saas_os.infra.secrets.provider import SecretsProvider

_EMAIL_ENV = (
    "EMAIL_PROVIDER",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USE_TLS",
    "SMTP_TLS_MODE",
    "SMTP_REQUIRE_TLS",
    "EMAIL_TIMEOUT_SECONDS",
    "EMAIL_DEFAULT_SENDER",
    "MAILPIT_SMTP_HOST",
    "MAILPIT_SMTP_PORT",
)


class _RecordingSecrets(SecretsProvider):
    """Records every secret name requested -- proves which provider reads
    credentials and which never does."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values
        self.requested: list[str] = []

    def get(self, name: str) -> str | None:
        self.requested.append(name)
        return self._values.get(name)


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch):
    for name in _EMAIL_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_email_config.cache_clear()
    yield monkeypatch
    get_email_config.cache_clear()


@pytest.fixture
def secrets(monkeypatch: pytest.MonkeyPatch) -> _RecordingSecrets:
    recording = _RecordingSecrets({"SMTP_USERNAME": "relay-user", "SMTP_PASSWORD": "relay-pass"})
    recording._values["RESEND_API_KEY"] = "re_selection_test_key"  # pragma: allowlist secret
    monkeypatch.setattr("saas_os.core.email.smtp_provider.get_secrets_provider", lambda: recording)
    monkeypatch.setattr(
        "saas_os.core.email.resend_provider.get_secrets_provider", lambda: recording
    )
    return recording


# --- SMTP TLS modes ----------------------------------------------------------


def test_default_tls_mode_is_starttls() -> None:
    config = EmailConfig(smtp_host="smtp.example.com")
    assert config.tls_mode == "starttls"
    assert config.use_tls is True


def test_legacy_use_tls_false_means_tls_mode_none() -> None:
    config = EmailConfig(smtp_host="smtp.example.com", use_tls=False)
    assert config.tls_mode == "none"
    assert config.use_tls is False


@pytest.mark.parametrize("mode", ["starttls", "implicit"])
def test_tls_modes_imply_use_tls(mode: str) -> None:
    assert EmailConfig(smtp_host="smtp.example.com", tls_mode=mode).use_tls is True


def test_rejects_unknown_tls_mode() -> None:
    with pytest.raises(EmailConfigurationError):
        EmailConfig(smtp_host="smtp.example.com", tls_mode="tls-no-verify")


@pytest.mark.parametrize(
    ("use_tls", "mode"), [(False, "starttls"), (False, "implicit"), (True, "none")]
)
def test_rejects_contradictory_use_tls_and_tls_mode(use_tls: bool, mode: str) -> None:
    with pytest.raises(EmailConfigurationError):
        EmailConfig(smtp_host="smtp.example.com", use_tls=use_tls, tls_mode=mode)


@pytest.mark.parametrize(
    ("use_tls", "mode"), [(True, "starttls"), (True, "implicit"), (False, "none")]
)
def test_accepts_consistent_use_tls_and_tls_mode(use_tls: bool, mode: str) -> None:
    config = EmailConfig(smtp_host="smtp.example.com", use_tls=use_tls, tls_mode=mode)
    assert config.tls_mode == mode


def test_require_tls_refuses_plaintext() -> None:
    with pytest.raises(EmailConfigurationError):
        EmailConfig(smtp_host="smtp.example.com", tls_mode="none", require_tls=True)


# --- Production TLS requirement (ADR-0057 following ADR-0021) --------------


def test_production_refuses_plaintext_smtp_by_default(env) -> None:
    env.setenv("ENVIRONMENT", "production")
    env.setenv("SMTP_HOST", "smtp.example.com")
    env.setenv("SMTP_TLS_MODE", "none")
    with pytest.raises(EmailConfigurationError):
        get_email_config()


def test_production_refuses_legacy_use_tls_false_by_default(env) -> None:
    env.setenv("ENVIRONMENT", "production")
    env.setenv("SMTP_HOST", "smtp.example.com")
    env.setenv("SMTP_USE_TLS", "false")
    with pytest.raises(EmailConfigurationError):
        get_email_config()


def test_production_plaintext_needs_the_explicit_operator_override(env) -> None:
    env.setenv("ENVIRONMENT", "production")
    env.setenv("SMTP_HOST", "relay.internal")
    env.setenv("SMTP_TLS_MODE", "none")
    env.setenv("SMTP_REQUIRE_TLS", "false")
    config = get_email_config()
    assert config.tls_mode == "none"
    assert config.require_tls is False


@pytest.mark.parametrize("mode", ["starttls", "implicit"])
def test_production_accepts_tls(env, mode: str) -> None:
    env.setenv("ENVIRONMENT", "production")
    env.setenv("SMTP_HOST", "smtp.example.com")
    env.setenv("SMTP_TLS_MODE", mode)
    config = get_email_config()
    assert (config.tls_mode, config.require_tls) == (mode, True)


def test_production_default_tls_is_starttls(env) -> None:
    """A legacy production deployment that sets only `SMTP_HOST` keeps
    working: the default was already STARTTLS."""
    env.setenv("ENVIRONMENT", "production")
    env.setenv("SMTP_HOST", "smtp.example.com")
    assert get_email_config().tls_mode == "starttls"


def test_development_allows_plaintext_without_override(env) -> None:
    env.setenv("ENVIRONMENT", "development")
    env.setenv("SMTP_HOST", "localhost")
    env.setenv("SMTP_TLS_MODE", "none")
    assert get_email_config().require_tls is False


def test_smtp_require_tls_true_applies_outside_production(env) -> None:
    env.setenv("SMTP_HOST", "localhost")
    env.setenv("SMTP_TLS_MODE", "none")
    env.setenv("SMTP_REQUIRE_TLS", "true")
    with pytest.raises(EmailConfigurationError):
        get_email_config()


def test_invalid_smtp_require_tls_value_raises(env) -> None:
    env.setenv("SMTP_HOST", "smtp.example.com")
    env.setenv("SMTP_REQUIRE_TLS", "sometimes")
    with pytest.raises(EmailConfigurationError):
        get_email_config()


def test_contradictory_tls_environment_raises(env) -> None:
    env.setenv("SMTP_HOST", "smtp.example.com")
    env.setenv("SMTP_USE_TLS", "false")
    env.setenv("SMTP_TLS_MODE", "implicit")
    with pytest.raises(EmailConfigurationError):
        get_email_config()


def test_tls_mode_environment_is_case_insensitive(env) -> None:
    env.setenv("SMTP_HOST", "smtp.example.com")
    env.setenv("SMTP_TLS_MODE", "Implicit")
    assert get_email_config().tls_mode == "implicit"


# --- EMAIL_PROVIDER ----------------------------------------------------------


def test_provider_name_is_none_when_unset_or_blank(env) -> None:
    assert get_email_provider_name() is None
    env.setenv("EMAIL_PROVIDER", "  ")
    assert get_email_provider_name() is None


@pytest.mark.parametrize("name", ["smtp", "mailpit", "resend", "SMTP", " Mailpit ", "Resend"])
def test_provider_name_accepts_built_in_names(env, name: str) -> None:
    env.setenv("EMAIL_PROVIDER", name)
    assert get_email_provider_name() == name.strip().lower()


@pytest.mark.parametrize("name", ["ses", "postmark", "fake", "smtp,mailpit"])
def test_provider_name_rejects_unsupported_providers(env, name: str) -> None:
    env.setenv("EMAIL_PROVIDER", name)
    with pytest.raises(EmailConfigurationError) as excinfo:
        get_email_provider_name()
    assert "smtp" in str(excinfo.value)
    assert "mailpit" in str(excinfo.value)
    assert "resend" in str(excinfo.value)


def test_the_provider_map_is_fixed_and_read_only() -> None:
    factories = selection._PROVIDER_FACTORIES  # noqa: SLF001
    assert set(factories) == set(EMAIL_PROVIDER_NAMES)
    with pytest.raises(TypeError):
        factories["custom"] = SmtpEmailProvider  # type: ignore[index]


# --- Sender --------------------------------------------------------------------


def test_default_sender_is_independent_of_smtp_host(env) -> None:
    env.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    assert get_email_default_sender() == "no-reply@example.com"


def test_default_sender_unset_or_empty_is_none(env) -> None:
    assert get_email_default_sender() is None
    env.setenv("EMAIL_DEFAULT_SENDER", "")
    assert get_email_default_sender() is None


def test_default_sender_blank_is_rejected(env) -> None:
    env.setenv("EMAIL_DEFAULT_SENDER", "   ")
    with pytest.raises(EmailConfigurationError):
        get_email_default_sender()


# --- Mailpit configuration ---------------------------------------------------


@pytest.mark.parametrize("environment", ["development", "test"])
def test_mailpit_config_defaults(env, environment: str) -> None:
    env.setenv("ENVIRONMENT", environment)
    config = get_mailpit_config()
    assert (config.smtp_host, config.smtp_port) == ("mailpit", 1025)


def test_mailpit_config_reads_only_mailpit_variables(env) -> None:
    env.setenv("SMTP_HOST", "smtp.production.example")
    env.setenv("SMTP_PORT", "465")
    env.setenv("MAILPIT_SMTP_HOST", "localhost")
    env.setenv("MAILPIT_SMTP_PORT", "11025")
    config = get_mailpit_config()
    assert (config.smtp_host, config.smtp_port) == ("localhost", 11025)


@pytest.mark.parametrize("environment", ["production", None, "staging", ""])
def test_mailpit_config_is_refused_outside_development_and_test(
    env, environment: str | None
) -> None:
    if environment is None:
        env.delenv("ENVIRONMENT", raising=False)
    else:
        env.setenv("ENVIRONMENT", environment)
    with pytest.raises(EmailConfigurationError):
        get_mailpit_config()


def test_mailpit_config_rejects_invalid_port(env) -> None:
    env.setenv("MAILPIT_SMTP_PORT", "not-a-port")
    with pytest.raises(EmailConfigurationError):
        get_mailpit_config()
    env.setenv("MAILPIT_SMTP_PORT", "0")
    with pytest.raises(EmailConfigurationError):
        get_mailpit_config()


def test_mailpit_config_carries_no_secret_or_tls_field() -> None:
    assert set(MailpitConfig.__dataclass_fields__) == {
        "smtp_host",
        "smtp_port",
        "timeout_seconds",
    }


# --- Selection -------------------------------------------------------------------


def test_unset_provider_selects_smtp_exactly_as_before(env, secrets) -> None:
    """Legacy compatibility: a deployment with only `SMTP_*` set."""
    env.setenv("SMTP_HOST", "smtp.example.com")
    provider = get_email_provider()
    assert type(provider) is SmtpEmailProvider
    assert provider._config.smtp_host == "smtp.example.com"  # noqa: SLF001


def test_unset_provider_without_smtp_host_is_not_configured(env, secrets) -> None:
    with pytest.raises(EmailConfigurationError):
        get_email_provider()


def test_explicit_smtp_reads_credentials_through_the_secrets_provider(env, secrets) -> None:
    env.setenv("EMAIL_PROVIDER", "smtp")
    env.setenv("SMTP_HOST", "smtp.example.com")
    provider = get_email_provider()
    assert type(provider) is SmtpEmailProvider
    assert secrets.requested == ["SMTP_USERNAME", "SMTP_PASSWORD"]


def test_explicit_smtp_requires_smtp_host(env, secrets) -> None:
    env.setenv("EMAIL_PROVIDER", "smtp")
    with pytest.raises(EmailConfigurationError):
        get_email_provider()


def test_mailpit_selection_never_reads_smtp_credentials(env, secrets) -> None:
    env.setenv("EMAIL_PROVIDER", "mailpit")
    env.setenv("SMTP_HOST", "smtp.production.example")
    provider = get_email_provider()
    assert type(provider) is MailpitEmailProvider
    assert secrets.requested == []
    assert provider._username is None  # noqa: SLF001
    assert provider._password is None  # noqa: SLF001
    assert provider._config.smtp_host == "mailpit"  # noqa: SLF001
    assert provider._config.tls_mode == "none"  # noqa: SLF001


def test_mailpit_is_refused_in_production(env, secrets) -> None:
    env.setenv("ENVIRONMENT", "production")
    env.setenv("EMAIL_PROVIDER", "mailpit")
    with pytest.raises(EmailConfigurationError) as excinfo:
        get_email_provider()
    assert "development-only" in str(excinfo.value)


def test_mailpit_production_refusal_has_no_override(env, secrets) -> None:
    """Neither the plaintext override nor any Mailpit variable re-enables it."""
    env.setenv("ENVIRONMENT", "production")
    env.setenv("EMAIL_PROVIDER", "mailpit")
    env.setenv("SMTP_REQUIRE_TLS", "false")
    env.setenv("MAILPIT_SMTP_HOST", "mailpit")
    with pytest.raises(EmailConfigurationError):
        get_email_provider()


def test_mailpit_provider_construction_is_guarded_on_its_own(env, monkeypatch) -> None:
    """Defense in depth: even if the configuration check were bypassed,
    constructing `MailpitEmailProvider` directly in production refuses."""
    env.setenv("ENVIRONMENT", "production")
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_mailpit_config", lambda: MailpitConfig()
    )
    with pytest.raises(EmailConfigurationError):
        MailpitEmailProvider()


def test_resend_selection_reads_only_the_resend_key(env, secrets) -> None:
    """ADR-0058: Resend reads `RESEND_API_KEY` and no SMTP credential or
    setting -- not even a broken one."""
    env.setenv("EMAIL_PROVIDER", "resend")
    env.setenv("SMTP_HOST", "smtp.production.example")
    env.setenv("SMTP_PORT", "not-a-port")
    provider = get_email_provider()
    assert type(provider) is ResendEmailProvider
    assert secrets.requested == ["RESEND_API_KEY"]


def test_resend_selection_uses_the_shared_email_timeout(env, secrets) -> None:
    env.setenv("EMAIL_PROVIDER", "resend")
    env.setenv("EMAIL_TIMEOUT_SECONDS", "4")
    provider = get_email_provider()
    assert isinstance(provider, ResendEmailProvider)
    assert provider._config.timeout_seconds == 4  # noqa: SLF001


def test_resend_without_an_api_key_fails_selection(env, monkeypatch) -> None:
    empty = _RecordingSecrets({})
    monkeypatch.setattr("saas_os.core.email.resend_provider.get_secrets_provider", lambda: empty)
    env.setenv("EMAIL_PROVIDER", "resend")
    with pytest.raises(EmailConfigurationError, match="RESEND_API_KEY"):
        get_email_provider()


def test_a_failing_resend_configuration_never_falls_back_to_smtp(env, monkeypatch) -> None:
    """A complete SMTP configuration is present, but Resend was selected:
    selection fails rather than silently switching provider."""
    smtp_only = _RecordingSecrets({"SMTP_USERNAME": "u", "SMTP_PASSWORD": "p"})
    monkeypatch.setattr(
        "saas_os.core.email.resend_provider.get_secrets_provider", lambda: smtp_only
    )
    monkeypatch.setattr("saas_os.core.email.smtp_provider.get_secrets_provider", lambda: smtp_only)
    env.setenv("EMAIL_PROVIDER", "resend")
    env.setenv("SMTP_HOST", "smtp.example.com")
    with pytest.raises(EmailConfigurationError):
        get_email_provider()


@pytest.mark.parametrize("environment", ["production", "development", "test"])
def test_resend_is_allowed_in_every_environment(env, secrets, environment: str) -> None:
    env.setenv("ENVIRONMENT", environment)
    env.setenv("EMAIL_PROVIDER", "resend")
    assert type(get_email_provider()) is ResendEmailProvider


def test_unknown_provider_fails_selection(env, secrets) -> None:
    env.setenv("EMAIL_PROVIDER", "ses")
    with pytest.raises(EmailConfigurationError):
        get_email_provider()


def test_send_email_default_uses_the_selected_provider(env, monkeypatch) -> None:
    from saas_os.core.email.provider import EmailMessage, FakeEmailProvider
    from saas_os.core.email.service import send_email

    fake = FakeEmailProvider()
    monkeypatch.setattr("saas_os.core.email.selection.get_email_provider", lambda: fake)
    send_email(
        EmailMessage(sender="a@example.com", to=("b@example.com",), subject="s", text_body="t")
    )
    assert len(fake.sent) == 1


def test_explicit_provider_argument_still_wins(env, monkeypatch) -> None:
    from saas_os.core.email.provider import EmailMessage, FakeEmailProvider
    from saas_os.core.email.service import send_email

    def _must_not_select():
        raise AssertionError("selection must not run when provider= is passed")

    monkeypatch.setattr("saas_os.core.email.selection.get_email_provider", _must_not_select)
    env.setenv("EMAIL_PROVIDER", "not-a-provider")
    fake = FakeEmailProvider()
    send_email(
        EmailMessage(sender="a@example.com", to=("b@example.com",), subject="s", text_body="t"),
        provider=fake,
    )
    assert len(fake.sent) == 1


# --- Startup validation ----------------------------------------------------------


def test_startup_validation_is_a_no_op_when_provider_is_unset(env) -> None:
    """Email stays optional: nothing configured, nothing checked."""
    assert validate_email_configuration() is None


def test_startup_validation_accepts_a_complete_smtp_configuration(env, secrets) -> None:
    env.setenv("EMAIL_PROVIDER", "smtp")
    env.setenv("SMTP_HOST", "smtp.example.com")
    env.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    assert validate_email_configuration() == "smtp"


def test_startup_validation_accepts_mailpit_in_development(env, secrets) -> None:
    env.setenv("ENVIRONMENT", "development")
    env.setenv("EMAIL_PROVIDER", "mailpit")
    env.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    assert validate_email_configuration() == "mailpit"


def test_startup_validation_requires_a_sender(env, secrets) -> None:
    env.setenv("EMAIL_PROVIDER", "smtp")
    env.setenv("SMTP_HOST", "smtp.example.com")
    with pytest.raises(EmailConfigurationError):
        validate_email_configuration()


def test_startup_validation_refuses_mailpit_in_production(env, secrets) -> None:
    env.setenv("ENVIRONMENT", "production")
    env.setenv("EMAIL_PROVIDER", "mailpit")
    env.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    with pytest.raises(EmailConfigurationError):
        validate_email_configuration()


def test_startup_validation_refuses_production_plaintext(env, secrets) -> None:
    env.setenv("ENVIRONMENT", "production")
    env.setenv("EMAIL_PROVIDER", "smtp")
    env.setenv("SMTP_HOST", "smtp.example.com")
    env.setenv("SMTP_TLS_MODE", "none")
    env.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    with pytest.raises(EmailConfigurationError):
        validate_email_configuration()


def test_startup_validation_refuses_half_configured_credentials(env, monkeypatch) -> None:
    half = _RecordingSecrets({"SMTP_USERNAME": "relay-user"})
    monkeypatch.setattr("saas_os.core.email.smtp_provider.get_secrets_provider", lambda: half)
    env.setenv("EMAIL_PROVIDER", "smtp")
    env.setenv("SMTP_HOST", "smtp.example.com")
    env.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    with pytest.raises(EmailConfigurationError) as excinfo:
        validate_email_configuration()
    assert "relay-user" not in str(excinfo.value)


def test_startup_validation_makes_no_network_call(env, secrets, monkeypatch) -> None:
    import smtplib

    def _no_network(*args: object, **kwargs: object):
        raise AssertionError("startup validation must not connect")

    monkeypatch.setattr(smtplib, "SMTP", _no_network)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _no_network)
    env.setenv("EMAIL_PROVIDER", "smtp")
    env.setenv("SMTP_HOST", "smtp.example.com")
    env.setenv("SMTP_TLS_MODE", "implicit")
    env.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    assert validate_email_configuration() == "smtp"


def test_startup_validation_accepts_a_complete_resend_configuration(env, secrets) -> None:
    env.setenv("ENVIRONMENT", "production")
    env.setenv("EMAIL_PROVIDER", "resend")
    env.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    assert validate_email_configuration() == "resend"


def test_startup_validation_refuses_resend_without_an_api_key(env, monkeypatch) -> None:
    empty = _RecordingSecrets({})
    monkeypatch.setattr("saas_os.core.email.resend_provider.get_secrets_provider", lambda: empty)
    env.setenv("EMAIL_PROVIDER", "resend")
    env.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    with pytest.raises(EmailConfigurationError, match="RESEND_API_KEY"):
        validate_email_configuration()


def test_startup_validation_requires_a_sender_for_resend(env, secrets) -> None:
    env.setenv("EMAIL_PROVIDER", "resend")
    with pytest.raises(EmailConfigurationError, match="EMAIL_DEFAULT_SENDER"):
        validate_email_configuration()


def test_resend_startup_validation_makes_no_network_call(env, secrets, monkeypatch) -> None:
    from saas_os.infra.egress import StrictEgressClient

    async def _no_network(*args: object, **kwargs: object):
        raise AssertionError("startup validation must not connect")

    monkeypatch.setattr(StrictEgressClient, "post", _no_network)
    monkeypatch.setattr("saas_os.infra.egress.client.default_resolver", _no_network)
    env.setenv("EMAIL_PROVIDER", "resend")
    env.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    assert validate_email_configuration() == "resend"
