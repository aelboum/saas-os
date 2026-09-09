"""Liveness tests (docs/IMPLEMENTATION-ROADMAP.md Phase 2.5)."""

from __future__ import annotations

import pytest
from infra.health.results import CheckResult

from infra.health import HealthStatus, check_liveness


def test_liveness_reports_healthy() -> None:
    result = check_liveness()
    assert result.status == HealthStatus.HEALTHY


def test_liveness_result_is_a_check_result_named_process() -> None:
    result = check_liveness()
    assert isinstance(result, CheckResult)
    assert result.name == "process"
    assert result.detail is None


def test_liveness_is_deterministic() -> None:
    assert check_liveness() == check_liveness()


def test_liveness_succeeds_without_database_or_redis_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-vacuous: liveness must succeed even with DATABASE_URL/REDIS_URL
    both unset -- proving it genuinely never reaches infra/db or
    infra/jobs, not merely that it happens not to today.
    """
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    result = check_liveness()
    assert result.status == HealthStatus.HEALTHY
