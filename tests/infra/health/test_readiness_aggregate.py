"""`check_readiness()` aggregation tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.5: "health endpoint reports healthy when dependencies are up,
unhealthy when a dependency is deliberately taken down"). Each combination
substitutes `_check_database`/`_check_redis` with a fixed result, proving
`check_readiness()` genuinely aggregates both checks rather than returning
a hard-coded status -- if either substitution were ignored, the
corresponding assertion below would fail.
"""

from __future__ import annotations

import pytest
from infra.health.readiness import check_readiness
from infra.health.results import CheckResult, HealthStatus

pytestmark = pytest.mark.anyio


def _fake_check_database(status: HealthStatus):  # noqa: ANN201
    def _check(*, engine: object = None, config: object = None) -> CheckResult:
        return CheckResult(
            name="database",
            status=status,
            detail=None if status == HealthStatus.HEALTHY else "Fake",
        )

    return _check


def _fake_check_redis(status: HealthStatus):  # noqa: ANN201
    async def _check(*, pool: object = None, config: object = None) -> CheckResult:
        return CheckResult(
            name="redis", status=status, detail=None if status == HealthStatus.HEALTHY else "Fake"
        )

    return _check


async def test_ready_when_database_and_redis_are_both_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "infra.health.readiness._check_database", _fake_check_database(HealthStatus.HEALTHY)
    )
    monkeypatch.setattr(
        "infra.health.readiness._check_redis", _fake_check_redis(HealthStatus.HEALTHY)
    )

    report = await check_readiness()

    assert report.status == HealthStatus.HEALTHY
    assert {c.name: c.status for c in report.checks} == {
        "database": HealthStatus.HEALTHY,
        "redis": HealthStatus.HEALTHY,
    }


async def test_not_ready_when_database_unhealthy_and_redis_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "infra.health.readiness._check_database", _fake_check_database(HealthStatus.UNHEALTHY)
    )
    monkeypatch.setattr(
        "infra.health.readiness._check_redis", _fake_check_redis(HealthStatus.HEALTHY)
    )

    report = await check_readiness()

    assert report.status == HealthStatus.UNHEALTHY
    assert {c.name: c.status for c in report.checks} == {
        "database": HealthStatus.UNHEALTHY,
        "redis": HealthStatus.HEALTHY,
    }


async def test_not_ready_when_database_healthy_and_redis_unhealthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "infra.health.readiness._check_database", _fake_check_database(HealthStatus.HEALTHY)
    )
    monkeypatch.setattr(
        "infra.health.readiness._check_redis", _fake_check_redis(HealthStatus.UNHEALTHY)
    )

    report = await check_readiness()

    assert report.status == HealthStatus.UNHEALTHY
    assert {c.name: c.status for c in report.checks} == {
        "database": HealthStatus.HEALTHY,
        "redis": HealthStatus.UNHEALTHY,
    }


async def test_not_ready_when_database_and_redis_both_unhealthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "infra.health.readiness._check_database", _fake_check_database(HealthStatus.UNHEALTHY)
    )
    monkeypatch.setattr(
        "infra.health.readiness._check_redis", _fake_check_redis(HealthStatus.UNHEALTHY)
    )

    report = await check_readiness()

    assert report.status == HealthStatus.UNHEALTHY
    assert {c.name: c.status for c in report.checks} == {
        "database": HealthStatus.UNHEALTHY,
        "redis": HealthStatus.UNHEALTHY,
    }
