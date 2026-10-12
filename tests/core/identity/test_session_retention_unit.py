"""RA-12-5 -- pure unit tests for `saas_os.core.identity.config.SessionRetentionConfig`
and `saas_os.core.identity.session_retention.SessionCleanupResult`'s own shape. No
database needed; the actual cleanup behavior is covered by
`tests/core/identity/test_session_retention_integration.py`.
"""

from __future__ import annotations

import pytest

from saas_os.core.identity.config import SessionRetentionConfig, get_session_retention_config
from saas_os.core.identity.errors import SessionRetentionConfigurationError
from saas_os.core.identity.session_retention import SessionCleanupResult


def test_defaults_are_safe_and_bounded() -> None:
    config = SessionRetentionConfig()
    assert config.revoked_grace_period_seconds == 86_400
    assert config.cleanup_batch_size == 500
    assert config.cleanup_interval_seconds == 3_600


@pytest.mark.parametrize(
    "kwargs",
    [
        {"revoked_grace_period_seconds": 0},
        {"revoked_grace_period_seconds": -1},
        {"cleanup_batch_size": 0},
        {"cleanup_batch_size": -5},
        {"cleanup_interval_seconds": 0},
        {"cleanup_interval_seconds": -60},
    ],
)
def test_rejects_non_positive_values(kwargs: dict[str, int]) -> None:
    with pytest.raises(SessionRetentionConfigurationError):
        SessionRetentionConfig(**kwargs)


def test_get_session_retention_config_reads_environment_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SESSION_REVOKED_GRACE_PERIOD_SECONDS", "3600")
    monkeypatch.setenv("SESSION_CLEANUP_BATCH_SIZE", "50")
    monkeypatch.setenv("SESSION_CLEANUP_INTERVAL_SECONDS", "900")
    get_session_retention_config.cache_clear()
    try:
        config = get_session_retention_config()
        assert config.revoked_grace_period_seconds == 3600
        assert config.cleanup_batch_size == 50
        assert config.cleanup_interval_seconds == 900
    finally:
        get_session_retention_config.cache_clear()


def test_get_session_retention_config_rejects_non_integer_env_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SESSION_CLEANUP_BATCH_SIZE", "not-a-number")
    get_session_retention_config.cache_clear()
    try:
        with pytest.raises(SessionRetentionConfigurationError):
            get_session_retention_config()
    finally:
        get_session_retention_config.cache_clear()


def test_result_total_deleted_sums_both_categories() -> None:
    result = SessionCleanupResult(
        expired_deleted=3, revoked_deleted=2, batches=2, duration_seconds=0.01
    )
    assert result.total_deleted == 5


def test_result_carries_only_bounded_counts_never_identifiers() -> None:
    """RA-12-5 security regression #6: the result type structurally
    cannot carry a token hash, session id, or user id -- it has no field
    for one."""
    field_names = {f for f in SessionCleanupResult.__dataclass_fields__}
    assert field_names == {"expired_deleted", "revoked_deleted", "batches", "duration_seconds"}
