"""Unit tests for the P1.8 health/readiness HTTP endpoints -- no real
PostgreSQL/Redis needed. `infra.health.check_liveness`/`check_readiness`'s
own aggregation logic is already fully covered by `tests/infra/health/*`
(Phase 2.5); these tests only prove the HTTP wiring `api/health.py` adds:
status codes, response shape, liveness never touching a dependency check,
and no leakage of dependency/exception detail into the response body.
"""

from __future__ import annotations

from collections.abc import Iterator

import api.health as health_module
import api.main as main_module
import pytest
from fastapi.testclient import TestClient
from infra.db.role_guard import ApplicationRoleValidation
from infra.health.results import CheckResult, HealthStatus, ReadinessReport

pytestmark = pytest.mark.anyio


def _stub_safe_role(engine: object) -> ApplicationRoleValidation:
    return ApplicationRoleValidation(role_name="safe_role")


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    # Mirrors tests/api/test_main_lifespan_unit.py: the P1.2 startup guard
    # still runs for these tests (create_app()'s lifespan is never
    # skipped), it is just pointed at a stubbed-safe role so no real
    # PostgreSQL is needed to exercise the HTTP layer under test here.
    monkeypatch.setattr(main_module, "get_engine", lambda: object())
    monkeypatch.setattr(main_module, "validate_application_role", _stub_safe_role)
    app = main_module.create_app()
    with TestClient(app) as test_client:
        yield test_client


# --- Liveness ----------------------------------------------------------


def test_liveness_returns_200_and_healthy_status(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_liveness_never_calls_readiness_aggregation(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Liveness must not require PostgreSQL/Redis -- proven here by making
    the readiness aggregator explode if liveness ever called it."""

    async def _must_not_be_called() -> ReadinessReport:
        raise AssertionError("liveness must never invoke check_readiness")

    monkeypatch.setattr(health_module, "check_readiness", _must_not_be_called)
    response = client.get("/healthz")
    assert response.status_code == 200


def test_liveness_does_not_require_authentication(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code != 401
    assert response.status_code != 403


# --- Readiness -----------------------------------------------------------


async def test_readiness_returns_200_when_all_dependencies_healthy(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _fake_readiness() -> ReadinessReport:
        return ReadinessReport(
            status=HealthStatus.HEALTHY,
            checks=(
                CheckResult(name="database", status=HealthStatus.HEALTHY),
                CheckResult(name="redis", status=HealthStatus.HEALTHY),
            ),
        )

    monkeypatch.setattr(health_module, "check_readiness", _fake_readiness)
    response = client.get("/readyz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert {c["name"]: c["status"] for c in body["checks"]} == {
        "database": "healthy",
        "redis": "healthy",
    }


async def test_readiness_returns_503_when_database_unhealthy(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _fake_readiness() -> ReadinessReport:
        return ReadinessReport(
            status=HealthStatus.UNHEALTHY,
            checks=(
                CheckResult(
                    name="database", status=HealthStatus.UNHEALTHY, detail="OperationalError"
                ),
                CheckResult(name="redis", status=HealthStatus.HEALTHY),
            ),
        )

    monkeypatch.setattr(health_module, "check_readiness", _fake_readiness)
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["status"] == "unhealthy"


async def test_readiness_returns_503_when_redis_unhealthy(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _fake_readiness() -> ReadinessReport:
        return ReadinessReport(
            status=HealthStatus.UNHEALTHY,
            checks=(
                CheckResult(name="database", status=HealthStatus.HEALTHY),
                CheckResult(name="redis", status=HealthStatus.UNHEALTHY, detail="ConnectionError"),
            ),
        )

    monkeypatch.setattr(health_module, "check_readiness", _fake_readiness)
    response = client.get("/readyz")
    assert response.status_code == 503


def test_readiness_does_not_require_authentication(client: TestClient) -> None:
    response = client.get("/readyz")
    assert response.status_code != 401
    assert response.status_code != 403


# --- Security: no leaked diagnostic/dependency detail ---------------------


async def test_readiness_response_never_includes_check_detail_field(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _fake_readiness() -> ReadinessReport:
        return ReadinessReport(
            status=HealthStatus.UNHEALTHY,
            checks=(
                CheckResult(
                    name="database",
                    status=HealthStatus.UNHEALTHY,
                    detail="postgresql://saas_os_app:secret@db:5432/saas_os",
                ),
            ),
        )

    monkeypatch.setattr(health_module, "check_readiness", _fake_readiness)
    response = client.get("/readyz")
    assert response.status_code == 503
    assert "secret" not in response.text
    assert "postgresql://" not in response.text
    for check in response.json()["checks"]:
        assert "detail" not in check
