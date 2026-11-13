"""Monthly AI usage rollup expiry settings and guards (owner decisions of
2026-11-13): off unless `AI_USAGE_ROLLUP_RETENTION_ENABLED=true`; 24 months
by default; fewer than 24 (the monthly read's reach and the database floor
of migration `e8a3c6f1d9b4`) or a malformed value fails closed without
echoing it; the cutoff is the first instant of a UTC month; a disabled run
touches no database; an enabled run refuses a short period, a naive clock and
an actor that is not a `SystemActor`."""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta, timezone

import pytest

from saas_os.control_plane.inference import usage_rollup_retention as retention
from saas_os.control_plane.inference.tenant_usage import MAX_MONTHS
from saas_os.control_plane.inference.usage_rollup_retention import (
    AIUsageRollupRetentionConfigurationError,
    AIUsageRollupRetentionSettings,
    ai_usage_rollup_retention_settings,
    expire_ai_usage_rollups,
    rollup_cutoff,
)
from saas_os.core.authority import SystemActor, SystemActorKind

ACTOR = SystemActor(kind=SystemActorKind.MAINTENANCE, name="rollup_retention_unit")


def test_off_with_24_months_by_default() -> None:
    assert ai_usage_rollup_retention_settings({}) == AIUsageRollupRetentionSettings(False, 24)


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        (
            {"AI_USAGE_ROLLUP_RETENTION_ENABLED": "true"},
            AIUsageRollupRetentionSettings(True, 24),
        ),
        (
            {"AI_USAGE_ROLLUP_RETENTION_ENABLED": " TRUE "},
            AIUsageRollupRetentionSettings(True, 24),
        ),
        (
            {"AI_USAGE_ROLLUP_RETENTION_ENABLED": "false"},
            AIUsageRollupRetentionSettings(False, 24),
        ),
        ({"AI_USAGE_ROLLUP_RETENTION_MONTHS": "84"}, AIUsageRollupRetentionSettings(False, 84)),
    ],
)
def test_valid_settings(env: dict[str, str], expected: AIUsageRollupRetentionSettings) -> None:
    assert ai_usage_rollup_retention_settings(env) == expected


@pytest.mark.parametrize(
    "env",
    [
        {"AI_USAGE_ROLLUP_RETENTION_ENABLED": "yes-SENTINEL"},
        {"AI_USAGE_ROLLUP_RETENTION_ENABLED": "1"},
        {"AI_USAGE_ROLLUP_RETENTION_MONTHS": "23"},
        {"AI_USAGE_ROLLUP_RETENTION_MONTHS": "0"},
        {"AI_USAGE_ROLLUP_RETENTION_MONTHS": "-24"},
        {"AI_USAGE_ROLLUP_RETENTION_MONTHS": "24.5"},
        {"AI_USAGE_ROLLUP_RETENTION_MONTHS": "SENTINEL"},
        {"AI_USAGE_ROLLUP_RETENTION_MONTHS": "1201"},
    ],
)
def test_invalid_settings_fail_closed_without_echo(env: dict[str, str]) -> None:
    with pytest.raises(AIUsageRollupRetentionConfigurationError) as excinfo:
        ai_usage_rollup_retention_settings(env)
    assert "SENTINEL" not in str(excinfo.value)
    for value in env.values():
        assert value.strip() not in str(excinfo.value)


def test_the_minimum_covers_the_monthly_read_and_matches_the_database_floor() -> None:
    migration = importlib.import_module(
        "saas_os.infra.db.migrations.versions.e8a3c6f1d9b4_allow_ai_usage_monthly_expiry"
    )
    assert retention.MINIMUM_RETENTION_MONTHS == MAX_MONTHS == migration.FLOOR_MONTHS == 24


@pytest.mark.parametrize(
    ("at", "months", "expected"),
    [
        (datetime(2026, 11, 13, 12, tzinfo=UTC), 24, datetime(2024, 11, 1, tzinfo=UTC)),
        (datetime(2026, 1, 1, tzinfo=UTC), 1, datetime(2025, 12, 1, tzinfo=UTC)),
        (datetime(2026, 12, 31, 23, 59, tzinfo=UTC), 12, datetime(2025, 12, 1, tzinfo=UTC)),
        # 2026-12-01 01:00 at UTC+02:00 is still November in UTC.
        (
            datetime(2026, 12, 1, 1, tzinfo=timezone(timedelta(hours=2))),
            0,
            datetime(2026, 11, 1, tzinfo=UTC),
        ),
    ],
)
def test_the_cutoff_is_a_utc_month_start(at: datetime, months: int, expected: datetime) -> None:
    assert rollup_cutoff(at, months) == expected


def test_a_disabled_run_touches_no_database(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_database() -> list[object]:
        raise AssertionError("the database was reached")

    monkeypatch.setattr(retention, "_tenant_ids", _no_database)
    result = expire_ai_usage_rollups(
        actor=ACTOR, settings=AIUsageRollupRetentionSettings(False, 24)
    )
    assert (result.enabled, result.deleted, result.tenants_scanned) == (False, 0, 0)


def test_an_enabled_run_refuses_a_short_period_and_a_naive_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(retention, "_tenant_ids", lambda: [])
    with pytest.raises(AIUsageRollupRetentionConfigurationError):
        expire_ai_usage_rollups(actor=ACTOR, settings=AIUsageRollupRetentionSettings(True, 12))
    with pytest.raises(ValueError, match="timezone-aware"):
        expire_ai_usage_rollups(
            actor=ACTOR,
            settings=AIUsageRollupRetentionSettings(True, 24),
            now=datetime(2026, 11, 13),  # noqa: DTZ001 -- the refused case
        )
    with pytest.raises(TypeError):
        expire_ai_usage_rollups(
            actor="worker",  # type: ignore[arg-type]
            settings=AIUsageRollupRetentionSettings(True, 24),
            now=datetime.now(UTC),
        )
