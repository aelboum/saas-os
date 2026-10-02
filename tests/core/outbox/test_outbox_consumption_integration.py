"""RE-5: the consumer-idempotency primitive (`core.outbox.consumption`)
against real PostgreSQL.

Identity, concurrency (two connections; the second claimant provably waits
on the first's uncommitted claim -- `pg_blocking_pids` -- and then either
skips or proceeds depending on whether the first committed), rollback and
failure semantics, tenant isolation (RLS, not application filtering) and
purge. No sleeps: thread events and PostgreSQL's own lock reporting.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from typing import Any

import pytest
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

import core.rbac  # noqa: F401 -- registers the mappers core.audit_log references by name
from core.outbox import (
    InvalidOutboxEventError,
    claim_event_consumption,
    event_consumption_recorded,
    purge_tenant_outbox_events,
    record_event_consumption,
)
from core.tenancy import TenantStatus, create_tenant, transition_tenant_status

pytestmark = pytest.mark.integration

_CONSUMER = "usage.ingestion"


@pytest.fixture(autouse=True)
def _require_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.outbox_consumptions LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable/migrated to RE-5: {exc}")
    finally:
        probe.dispose()


def _admin(sql: str, params: Mapping[str, object]) -> list[Any]:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            result = session.execute(text(sql), params)
            return list(result) if sql.lstrip().upper().startswith("SELECT") else []
    finally:
        engine.dispose()


class _Tenants:
    def __init__(self) -> None:
        self.ids: list[uuid.UUID] = []

    def new(self) -> uuid.UUID:
        tenant_id = create_tenant(f"re5-{uuid.uuid4().hex[:10]}").id
        self.ids.append(tenant_id)
        return tenant_id

    def cleanup(self) -> None:
        for tenant_id in self.ids:
            params = {"t": str(tenant_id)}
            for table in ("outbox_consumptions", "outbox_events"):
                _admin(f"DELETE FROM core.{table} WHERE tenant_id = :t", params)  # noqa: S608
            _admin(
                "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t",
                params,
            )
            _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
            _admin("DELETE FROM core.tenants WHERE id = :t", params)


@pytest.fixture
def tenants() -> Iterator[_Tenants]:
    registry = _Tenants()
    try:
        yield registry
    finally:
        registry.cleanup()


def _claim(tenant_id: uuid.UUID, event_id: uuid.UUID, consumer: str = _CONSUMER) -> bool:
    with tenant_session_scope(tenant_id) as session:
        return claim_event_consumption(
            session, tenant_id=tenant_id, consumer=consumer, event_id=event_id
        )


def _recorded(tenant_id: uuid.UUID, event_id: uuid.UUID, consumer: str = _CONSUMER) -> bool:
    with tenant_session_scope(tenant_id) as session:
        return event_consumption_recorded(
            session, tenant_id=tenant_id, consumer=consumer, event_id=event_id
        )


class _Boom(Exception):
    pass


# --- Identity ----------------------------------------------------------------------


def test_the_same_event_and_consumer_is_a_duplicate(tenants: _Tenants) -> None:
    tenant_id, event_id = tenants.new(), uuid.uuid4()
    assert _claim(tenant_id, event_id) is True
    assert _claim(tenant_id, event_id) is False
    assert _recorded(tenant_id, event_id) is True


def test_a_different_consumer_is_independent(tenants: _Tenants) -> None:
    tenant_id, event_id = tenants.new(), uuid.uuid4()
    assert _claim(tenant_id, event_id, "usage.ingestion") is True
    assert _claim(tenant_id, event_id, "notification.dispatch") is True
    assert _recorded(tenant_id, event_id, "webhook.delivery") is False


def test_a_different_tenant_is_independent(tenants: _Tenants) -> None:
    tenant_a, tenant_b, event_id = tenants.new(), tenants.new(), uuid.uuid4()
    assert _claim(tenant_a, event_id) is True
    assert _claim(tenant_b, event_id) is True  # same ids, no collision
    assert _claim(tenant_b, event_id) is False


def test_a_different_event_is_independent(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    assert _claim(tenant_id, uuid.uuid4()) is True
    assert _claim(tenant_id, uuid.uuid4()) is True


@pytest.mark.parametrize(
    ("tenant_id", "consumer", "event_id"),
    [
        ("not-a-uuid", _CONSUMER, uuid.uuid4()),
        (uuid.uuid4(), "", uuid.uuid4()),
        (uuid.uuid4(), "nodot", uuid.uuid4()),
        (uuid.uuid4(), _CONSUMER, None),
        (uuid.uuid4(), _CONSUMER, str(uuid.uuid4())),
    ],
)
def test_an_invalid_identity_is_refused_before_touching_the_database(
    tenant_id: object, consumer: object, event_id: object
) -> None:
    class _NoSession:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"session.{name} used for an invalid identity")

    with pytest.raises(InvalidOutboxEventError):
        claim_event_consumption(
            _NoSession(),  # type: ignore[arg-type]
            tenant_id=tenant_id,  # type: ignore[arg-type]
            consumer=consumer,  # type: ignore[arg-type]
            event_id=event_id,  # type: ignore[arg-type]
        )


# --- Rollback and failure ---------------------------------------------------------------


def test_a_rolled_back_claim_leaves_the_event_eligible(tenants: _Tenants) -> None:
    """The consumer's transaction failed (or its worker died): no record."""
    tenant_id, event_id = tenants.new(), uuid.uuid4()
    with pytest.raises(_Boom), tenant_session_scope(tenant_id) as session:
        assert claim_event_consumption(
            session, tenant_id=tenant_id, consumer=_CONSUMER, event_id=event_id
        )
        raise _Boom

    assert _recorded(tenant_id, event_id) is False
    assert _claim(tenant_id, event_id) is True  # a later attempt proceeds


def test_the_claim_commits_with_the_business_write_or_not_at_all(tenants: _Tenants) -> None:
    tenant_id, event_id = tenants.new(), uuid.uuid4()
    with pytest.raises(DBAPIError), tenant_session_scope(tenant_id) as session:
        assert claim_event_consumption(
            session, tenant_id=tenant_id, consumer=_CONSUMER, event_id=event_id
        )
        session.execute(text("SELECT 1/0"))  # the business work fails
    assert _recorded(tenant_id, event_id) is False


def test_a_database_failure_is_never_read_as_already_consumed(tenants: _Tenants) -> None:
    tenant_id = tenants.new()

    class _FailingSession:
        def begin_nested(self) -> Any:
            raise OperationalError("SELECT 1", {}, Exception("connection lost"))

    with pytest.raises(OperationalError):
        claim_event_consumption(
            _FailingSession(),  # type: ignore[arg-type]
            tenant_id=tenant_id,
            consumer=_CONSUMER,
            event_id=uuid.uuid4(),
        )


def test_a_missing_tenant_raises_instead_of_suppressing() -> None:
    """An integrity failure that is not an existing record (here: the FK to
    a tenant that does not exist) is re-raised, never "already consumed"."""
    ghost = uuid.uuid4()
    with pytest.raises(DBAPIError), tenant_session_scope(ghost) as session:
        claim_event_consumption(session, tenant_id=ghost, consumer=_CONSUMER, event_id=ghost)


def test_record_event_consumption_reports_a_repeat(tenants: _Tenants) -> None:
    tenant_id, event_id = tenants.new(), uuid.uuid4()
    assert record_event_consumption(tenant_id, consumer=_CONSUMER, event_id=event_id) is True
    assert record_event_consumption(tenant_id, consumer=_CONSUMER, event_id=event_id) is False


# --- Concurrency ---------------------------------------------------------------------


def _wait_until_blocked_by(blocker_pid: int) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with engine.connect() as conn:
                if conn.execute(
                    text("SELECT pid FROM pg_stat_activity WHERE :p = ANY(pg_blocking_pids(pid))"),
                    {"p": blocker_pid},
                ).all():
                    return
            threading.Event().wait(0.02)
        raise AssertionError("the second claimant never waited on the first")
    finally:
        engine.dispose()


@pytest.mark.parametrize("first_commits", [True, False], ids=["first-commits", "first-rolls-back"])
def test_a_concurrent_claimant_waits_for_the_first_and_follows_its_outcome(
    tenants: _Tenants, first_commits: bool
) -> None:
    tenant_id, event_id = tenants.new(), uuid.uuid4()
    holding, release = threading.Event(), threading.Event()
    first: dict[str, Any] = {}

    def _first() -> None:
        try:
            with tenant_session_scope(tenant_id) as session:
                first["claimed"] = claim_event_consumption(
                    session, tenant_id=tenant_id, consumer=_CONSUMER, event_id=event_id
                )
                first["pid"] = session.execute(text("SELECT pg_backend_pid()")).scalar_one()
                holding.set()
                assert release.wait(30)
                if not first_commits:
                    raise _Boom
        except _Boom:
            pass

    thread = threading.Thread(target=_first)
    thread.start()
    assert holding.wait(30)
    second: dict[str, Any] = {}
    claimant = threading.Thread(
        target=lambda: second.setdefault("claimed", _claim(tenant_id, event_id))
    )
    claimant.start()
    try:
        _wait_until_blocked_by(first["pid"])  # a real database wait, not a race
        assert claimant.is_alive()
    finally:
        release.set()
        thread.join(30)
        claimant.join(30)

    assert first["claimed"] is True
    # Exactly one of the two executions proceeds.
    assert second["claimed"] is (not first_commits)
    assert _recorded(tenant_id, event_id) is True


# --- Tenant isolation ----------------------------------------------------------------


def test_a_tenant_cannot_see_or_create_another_tenants_record(tenants: _Tenants) -> None:
    tenant_a, tenant_b, event_id = tenants.new(), tenants.new(), uuid.uuid4()
    assert _claim(tenant_b, event_id) is True

    with tenant_session_scope(tenant_a) as session:
        # Naming tenant B's identity from tenant A's scope: RLS hides it.
        assert not event_consumption_recorded(
            session, tenant_id=tenant_b, consumer=_CONSUMER, event_id=event_id
        )
    with pytest.raises(DBAPIError, match="row-level security"):  # noqa: PT012
        with tenant_session_scope(tenant_a) as session:
            claim_event_consumption(
                session, tenant_id=tenant_b, consumer=_CONSUMER, event_id=uuid.uuid4()
            )
    with session_scope() as session:  # no tenant bound at all
        assert not event_consumption_recorded(
            session, tenant_id=tenant_b, consumer=_CONSUMER, event_id=event_id
        )
    assert (
        _admin(
            "SELECT count(*) FROM core.outbox_consumptions WHERE tenant_id = :t",
            {"t": str(tenant_b)},
        )[0][0]
        == 1
    )


def test_tenant_purge_removes_the_records(tenants: _Tenants) -> None:
    tenant_id, other = tenants.new(), tenants.new()
    for t in (tenant_id, other):
        _claim(t, uuid.uuid4())
        _claim(t, uuid.uuid4(), "webhook.delivery")
    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    transition_tenant_status(tenant_id, TenantStatus.PURGING)

    assert purge_tenant_outbox_events(tenant_id) == 2
    count = "SELECT count(*) FROM core.outbox_consumptions WHERE tenant_id = :t"
    assert _admin(count, {"t": str(tenant_id)})[0][0] == 0
    assert _admin(count, {"t": str(other)})[0][0] == 2
