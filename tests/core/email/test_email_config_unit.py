"""P1.12 -- pure unit tests for `core/email/config.py`: validation,
missing/invalid configuration, and safe fallback behavior. No network
needed.
"""

from __future__ import annotations

import pytest
from core.email.config import EmailConfig, get_email_config
from core.email.errors import EmailConfigurationError


def test_valid_configuration_constructs_cleanly() -> None:
    config = EmailConfig(smtp_host="smtp.example.com")
    assert config.smtp_port == 587
    assert config.use_tls is True
    assert config.timeout_seconds == 10
    assert config.default_sender is None


def test_rejects_empty_smtp_host() -> None:
    with pytest.raises(EmailConfigurationError):
        EmailConfig(smtp_host="")


def test_rejects_blank_smtp_host() -> None:
    with pytest.raises(EmailConfigurationError):
        EmailConfig(smtp_host="   ")


def test_rejects_out_of_range_port() -> None:
    with pytest.raises(EmailConfigurationError):
        EmailConfig(smtp_host="smtp.example.com", smtp_port=0)
    with pytest.raises(EmailConfigurationError):
        EmailConfig(smtp_host="smtp.example.com", smtp_port=70000)


def test_rejects_non_positive_timeout() -> None:
    with pytest.raises(EmailConfigurationError):
        EmailConfig(smtp_host="smtp.example.com", timeout_seconds=0)


def test_rejects_blank_default_sender_if_provided() -> None:
    with pytest.raises(EmailConfigurationError):
        EmailConfig(smtp_host="smtp.example.com", default_sender="   ")


def test_accepts_a_real_default_sender() -> None:
    config = EmailConfig(smtp_host="smtp.example.com", default_sender="no-reply@example.com")
    assert config.default_sender == "no-reply@example.com"


# --- get_email_config() / environment ------------------------------------


def test_missing_smtp_host_raises_deterministically(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SMTP_HOST", raising=False)
    get_email_config.cache_clear()
    try:
        with pytest.raises(EmailConfigurationError):
            get_email_config()
    finally:
        get_email_config.cache_clear()


def test_valid_environment_produces_expected_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "2525")
    monkeypatch.setenv("SMTP_USE_TLS", "false")
    monkeypatch.setenv("EMAIL_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    get_email_config.cache_clear()
    try:
        config = get_email_config()
        assert config.smtp_host == "smtp.example.com"
        assert config.smtp_port == 2525
        assert config.use_tls is False
        assert config.timeout_seconds == 5
        assert config.default_sender == "no-reply@example.com"
    finally:
        get_email_config.cache_clear()


def test_invalid_port_env_var_raises_rather_than_silently_defaulting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "not-a-number")
    get_email_config.cache_clear()
    try:
        with pytest.raises(EmailConfigurationError):
            get_email_config()
    finally:
        get_email_config.cache_clear()


def test_invalid_use_tls_env_var_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USE_TLS", "maybe")
    get_email_config.cache_clear()
    try:
        with pytest.raises(EmailConfigurationError):
            get_email_config()
    finally:
        get_email_config.cache_clear()


def test_config_never_carries_a_secret_field() -> None:
    """SMTP_USERNAME/SMTP_PASSWORD must never appear on this dataclass --
    they are read only inside SmtpEmailProvider, through SecretsProvider
    (this checkpoint's own Critical secret rule)."""
    fields = set(EmailConfig.__dataclass_fields__)
    assert "username" not in fields
    assert "password" not in fields
    assert "smtp_username" not in fields
    assert "smtp_password" not in fields
