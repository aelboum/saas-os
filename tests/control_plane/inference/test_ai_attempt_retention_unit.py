"""AI attempt retention settings and guards (owner decision of 2026-11-13):
off unless `AI_ATTEMPT_RETENTION_ENABLED=true`; 100 days by default; a
period below 93 days (the tenant usage read's reach) or a malformed value
fails closed without echoing it; a disabled run touches no database; an
enabled run refuses a short period, a naive clock and an actor that is not a
`SystemActor`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from saas_os.control_plane.inference import attempt_retention as retention
from saas_os.control_plane.inference.attempt_retention import (
    AIAttemptRetentionConfigurationError,
    AIAttemptRetentionSettings,
    ai_attempt_retention_settings,
    purge_expired_ai_attempts,
)
from saas_os.control_plane.inference.tenant_usage import MAX_WINDOW
from saas_os.core.authority import SystemActor, SystemActorKind

ACTOR = SystemActor(kind=SystemActorKind.MAINTENANCE, name="retention_unit")


def test_off_with_100_days_by_default() -> None:
    assert ai_attempt_retention_settings({}) == AIAttemptRetentionSettings(False, 100)


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"AI_ATTEMPT_RETENTION_ENABLED": "true"}, AIAttemptRetentionSettings(True, 100)),
        ({"AI_ATTEMPT_RETENTION_ENABLED": " TRUE "}, AIAttemptRetentionSettings(True, 100)),
        ({"AI_ATTEMPT_RETENTION_ENABLED": "false"}, AIAttemptRetentionSettings(False, 100)),
        (
            {"AI_ATTEMPT_RETENTION_ENABLED": "true", "AI_ATTEMPT_RETENTION_DAYS": "93"},
            AIAttemptRetentionSettings(True, 93),
        ),
        ({"AI_ATTEMPT_RETENTION_DAYS": "400"}, AIAttemptRetentionSettings(False, 400)),
    ],
)
def test_valid_settings(env: dict[str, str], expected: AIAttemptRetentionSettings) -> None:
    assert ai_attempt_retention_settings(env) == expected


@pytest.mark.parametrize(
    "env",
    [
        {"AI_ATTEMPT_RETENTION_ENABLED": "yes-SENTINEL"},
        {"AI_ATTEMPT_RETENTION_ENABLED": "1"},
        {"AI_ATTEMPT_RETENTION_DAYS": "92"},
        {"AI_ATTEMPT_RETENTION_DAYS": "0"},
        {"AI_ATTEMPT_RETENTION_DAYS": "-100"},
        {"AI_ATTEMPT_RETENTION_DAYS": "100.5"},
        {"AI_ATTEMPT_RETENTION_DAYS": "SENTINEL"},
        {"AI_ATTEMPT_RETENTION_DAYS": "36501"},
    ],
)
def test_invalid_settings_fail_closed_without_echo(env: dict[str, str]) -> None:
    with pytest.raises(AIAttemptRetentionConfigurationError) as excinfo:
        ai_attempt_retention_settings(env)
    assert "SENTINEL" not in str(excinfo.value)
    for value in env.values():
        assert value.strip() not in str(excinfo.value)


def test_the_minimum_covers_the_usage_read() -> None:
    assert retention.MINIMUM_RETENTION_DAYS == MAX_WINDOW.days == 93


def test_a_disabled_run_touches_no_database(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_database() -> list[object]:
        raise AssertionError("the database was reached")

    monkeypatch.setattr(retention, "_tenant_ids", _no_database)
    result = purge_expired_ai_attempts(actor=ACTOR, settings=AIAttemptRetentionSettings(False, 100))
    assert (result.enabled, result.deleted, result.tenants_scanned) == (False, 0, 0)


def test_an_enabled_run_refuses_a_short_period_and_a_naive_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(retention, "_tenant_ids", lambda: [])
    with pytest.raises(AIAttemptRetentionConfigurationError):
        purge_expired_ai_attempts(actor=ACTOR, settings=AIAttemptRetentionSettings(True, 30))
    with pytest.raises(ValueError, match="timezone-aware"):
        purge_expired_ai_attempts(
            actor=ACTOR,
            settings=AIAttemptRetentionSettings(True, 100),
            now=datetime(2026, 11, 13),  # noqa: DTZ001 -- the refused case
        )
    with pytest.raises(TypeError):
        purge_expired_ai_attempts(
            actor="worker",  # type: ignore[arg-type]
            settings=AIAttemptRetentionSettings(True, 100),
            now=datetime.now(UTC),
        )
