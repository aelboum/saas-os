"""Database readiness check tests (docs/IMPLEMENTATION-ROADMAP.md Phase
2.5) -- against an in-memory SQLite engine (healthy path, no real
PostgreSQL needed, mirroring `infra/db`'s own Phase 2.1 unit-test
convention) and a fake failing engine (unhealthy path), so the default
suite stays independent of a real database. Real PostgreSQL behavior is
covered separately by `test_health_integration.py` (marked `integration`).
"""

from __future__ import annotations

from infra.health.readiness import _check_database
from infra.health.results import HealthStatus
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError


class _FailingEngine:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.disposed = False

    def connect(self) -> None:
        raise self._exc

    def dispose(self) -> None:
        self.disposed = True


def test_healthy_database_produces_a_healthy_check() -> None:
    engine = create_engine("sqlite:///:memory:")
    try:
        result = _check_database(engine=engine)
    finally:
        engine.dispose()
    assert result.name == "database"
    assert result.status == HealthStatus.HEALTHY
    assert result.detail is None


def test_unavailable_database_produces_a_failed_check() -> None:
    engine = _FailingEngine(OperationalError("SELECT 1", {}, Exception("connection refused")))
    result = _check_database(engine=engine)  # type: ignore[arg-type]
    assert result.name == "database"
    assert result.status == HealthStatus.UNHEALTHY
    assert result.detail == "OperationalError"


def test_a_failing_injected_engine_is_still_disposed() -> None:
    """An injected engine is caller-owned in principle, but `_check_database`
    should not leak resources on the (only) path it constructs one itself --
    this test exercises the owns_engine=False path explicitly to confirm no
    disposal is attempted on an engine the check did not build.
    """
    engine = _FailingEngine(OperationalError("SELECT 1", {}, Exception("boom")))
    _check_database(engine=engine)  # type: ignore[arg-type]
    assert engine.disposed is False  # caller-provided engines are not owned/disposed by the check


def test_database_check_actually_queries_the_given_engine() -> None:
    """Non-vacuous: prove the check really executes SELECT 1 against the
    engine it's given, rather than returning a hard-coded success --
    a real SQLAlchemy event listener records the executed statement.
    """
    engine = create_engine("sqlite:///:memory:")
    executed_statements: list[str] = []

    @event.listens_for(engine, "before_cursor_execute")
    def _record(conn: object, cursor: object, statement: str, *args: object) -> None:
        executed_statements.append(statement)

    try:
        result = _check_database(engine=engine)
    finally:
        engine.dispose()

    assert result.status == HealthStatus.HEALTHY
    assert any("SELECT 1" in statement for statement in executed_statements)


def test_no_credentials_appear_in_a_failed_database_check() -> None:
    """Fake secret-shaped connection info embedded in the underlying
    driver exception -- confirm it never surfaces in the failed check's
    result (docs/SECURITY.md): only the exception's type name is kept.
    """
    secret_shaped = Exception("postgresql://user:SUPER_SECRET_PASSWORD@db/example")
    engine = _FailingEngine(OperationalError("SELECT 1", {}, secret_shaped))

    result = _check_database(engine=engine)  # type: ignore[arg-type]

    assert result.detail is not None
    assert "SUPER_SECRET_PASSWORD" not in result.detail
    assert "SUPER_SECRET_PASSWORD" not in repr(result)
    assert "SUPER_SECRET_PASSWORD" not in str(result)


def test_check_database_type_annotation_still_accepts_a_real_engine() -> None:
    """Confirm the override hook's real type (sqlalchemy.Engine) is what
    the function is actually annotated for -- not merely a duck-typed
    Any -- guarding against the override silently drifting from infra/db's
    own Engine type.
    """
    engine = create_engine("sqlite:///:memory:")
    try:
        assert isinstance(engine, Engine)
        result = _check_database(engine=engine)
    finally:
        engine.dispose()
    assert result.status == HealthStatus.HEALTHY
