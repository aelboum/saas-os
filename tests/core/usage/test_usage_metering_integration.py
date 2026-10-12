"""Phase 5.2 metering semantics against real PostgreSQL: recording,
validation, idempotency, aggregation windows, tenant isolation and failure.

`core.usage_events` is the one authoritative usage ledger. A usage event
reaches it through the transactional outbox (`ingest_event()` -> dispatcher
-> `_ingest_usage_event_job`, deduplicated per outbox event by RE-5) or
synchronously through `consume_quota()`/`consume_quota_idempotent()`.
Every path validates the same way: an exact, finite, non-negative, bounded
quantity; a non-blank metric; timezone-aware times, recorded in UTC.

Concurrency is real (threads, a start barrier, PostgreSQL's own locks); no
correctness depends on a sleep.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
import saas_os.core.usage.service as usage_service
from saas_os.api.outbox_dispatcher import _run_outbox_event
from saas_os.core.billing.provider import FakeBillingProvider
from saas_os.core.billing.service import create_plan, subscribe
from saas_os.core.outbox import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OutboxEvent,
    append_event,
    claim_due_events,
)
from saas_os.core.tenancy import (
    TenantClosedError,
    TenantStatus,
    create_tenant,
    transition_tenant_status,
)
from saas_os.core.usage import aggregate_usage, check_quota, consume_quota, ingest_event
from saas_os.core.usage.errors import InvalidUsageEventError, QuotaExceededError
from saas_os.core.usage.models import UsageEvent
from saas_os.core.usage.service import USAGE_INGESTION_EVENT_TYPE, consume_quota_idempotent
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload

pytestmark = pytest.mark.integration

_T0 = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
_WINDOW = (_T0 - timedelta(hours=1), _T0 + timedelta(hours=1))


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
        pytest.skip(f"PostgreSQL not reachable/migrated: {exc}")
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


class _World:
    def __init__(self) -> None:
        self.tenants: list[uuid.UUID] = []
        self.plans: list[str] = []

    def tenant(self) -> uuid.UUID:
        tenant_id = create_tenant(f"p52-{uuid.uuid4().hex[:10]}").id
        self.tenants.append(tenant_id)
        return tenant_id

    def limit(self, tenant_id: uuid.UUID, metric: str, limit: int) -> None:
        key = f"p52-plan-{uuid.uuid4().hex[:8]}"
        self.plans.append(key)
        create_plan(key, "P52", entitlements={metric: limit})
        subscribe(tenant_id, key, provider=FakeBillingProvider())

    def cleanup(self) -> None:
        for tenant_id in self.tenants:
            params = {"t": str(tenant_id)}
            for table in (
                "outbox_consumptions",
                "outbox_events",
                "usage_events",
                "idempotency_records",
                "billing_subscriptions",
            ):
                _admin(f"DELETE FROM core.{table} WHERE tenant_id = :t", params)  # noqa: S608
            _admin(
                "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t",
                params,
            )
            _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
            _admin("DELETE FROM core.tenants WHERE id = :t", params)
        for key in self.plans:
            _admin("DELETE FROM core.billing_plans WHERE key = :k", {"k": key})


@pytest.fixture
def world() -> Iterator[_World]:
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


def _events(tenant_id: uuid.UUID) -> list[OutboxEvent]:
    with tenant_session_scope(tenant_id) as session:
        rows = list(session.execute(select(OutboxEvent)).scalars())
        for row in rows:
            session.expunge(row)
        return rows


def _record(event: OutboxEvent, *, event_id: uuid.UUID | None = None) -> None:
    """Run the usage consumer for `event`, as the dispatcher would."""
    asyncio.run(
        usage_service._ingest_usage_event_job(
            TenantJobContext(tenant_id=event.tenant_id, event_id=event_id or event.id),
            TenantJobPayload(tenant_id=str(event.tenant_id), data=dict(event.payload)),
        )
    )


def _ingest(tenant_id: uuid.UUID, metric: str, quantity: Any, **kwargs: Any) -> OutboxEvent:
    with tenant_session_scope(tenant_id) as session:
        event_id = ingest_event(session, tenant_id, metric, quantity, **kwargs)
    (event,) = [e for e in _events(tenant_id) if e.id == event_id]
    return event


def _total(tenant_id: uuid.UUID, metric: str) -> Decimal:
    return aggregate_usage(tenant_id, metric, since=_WINDOW[0], until=_WINDOW[1])


# --- Recording and validation -------------------------------------------------------


def test_a_usage_event_is_recorded_exactly_and_in_utc(world: _World) -> None:
    tenant_id = world.tenant()
    at = datetime(2026, 6, 1, 14, 30, tzinfo=timezone(timedelta(hours=2)))  # 12:30 UTC
    _record(_ingest(tenant_id, "calls", Decimal("2.50"), occurred_at=at))

    with tenant_session_scope(tenant_id) as session:
        (row,) = session.execute(select(UsageEvent)).scalars()
        assert row.quantity == Decimal("2.50")
        assert row.occurred_at == datetime(2026, 6, 1, 12, 30, tzinfo=UTC)
        assert row.created_at is not None  # recording time, set by the database
    assert _total(tenant_id, "calls") == Decimal("2.50")


def test_an_int_quantity_is_exact_and_zero_is_recorded(world: _World) -> None:
    tenant_id = world.tenant()
    _record(_ingest(tenant_id, "calls", 3, occurred_at=_T0))
    _record(_ingest(tenant_id, "calls", Decimal("0"), occurred_at=_T0))
    assert _total(tenant_id, "calls") == Decimal("3")
    assert len(_events(tenant_id)) == 2  # the zero event is a real, recorded event


@pytest.mark.parametrize(
    "quantity",
    [
        Decimal("-1"),
        Decimal("NaN"),
        Decimal("sNaN"),
        Decimal("Infinity"),
        Decimal("-Infinity"),
        1.5,
        True,
        "3",
        None,
        Decimal(10) ** 18,
        Decimal("1E-19"),
    ],
)
def test_an_invalid_quantity_is_refused_and_nothing_is_recorded(
    world: _World, quantity: Any
) -> None:
    tenant_id = world.tenant()
    with pytest.raises(InvalidUsageEventError), tenant_session_scope(tenant_id) as session:
        ingest_event(session, tenant_id, "calls", quantity, occurred_at=_T0)
    with pytest.raises(InvalidUsageEventError):
        consume_quota(tenant_id, "calls", quantity, since=_WINDOW[0], until=_WINDOW[1])
    assert _events(tenant_id) == []
    assert _total(tenant_id, "calls") == Decimal("0")


@pytest.mark.parametrize("metric", ["", "   ", "x" * 101])
def test_an_invalid_metric_is_refused(world: _World, metric: str) -> None:
    tenant_id = world.tenant()
    with pytest.raises(InvalidUsageEventError), tenant_session_scope(tenant_id) as session:
        ingest_event(session, tenant_id, metric, Decimal("1"))
    with pytest.raises(InvalidUsageEventError):
        consume_quota(tenant_id, metric, Decimal("1"))
    assert _events(tenant_id) == []


def test_a_naive_occurrence_time_is_refused(world: _World) -> None:
    tenant_id = world.tenant()
    with pytest.raises(InvalidUsageEventError), tenant_session_scope(tenant_id) as session:
        ingest_event(session, tenant_id, "calls", Decimal("1"), occurred_at=datetime(2026, 6, 1))
    assert _events(tenant_id) == []


def test_a_closed_tenant_records_no_usage(world: _World) -> None:
    tenant_id = world.tenant()
    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    with pytest.raises(TenantClosedError), tenant_session_scope(tenant_id) as session:
        ingest_event(session, tenant_id, "calls", Decimal("1"))
    with pytest.raises(TenantClosedError):
        consume_quota(tenant_id, "calls", Decimal("1"))
    assert _events(tenant_id) == []


def test_a_rolled_back_caller_transaction_records_no_usage(world: _World) -> None:
    tenant_id = world.tenant()

    class _Boom(Exception):
        pass

    with pytest.raises(_Boom), tenant_session_scope(tenant_id) as session:
        ingest_event(session, tenant_id, "calls", Decimal("1"))
        raise _Boom
    assert _events(tenant_id) == []


# --- Idempotency (RE-5 identity, proven on the ledger) ------------------------------


def test_the_same_usage_event_recorded_twice_counts_once(world: _World) -> None:
    tenant_id = world.tenant()
    event = _ingest(tenant_id, "calls", Decimal("5"), occurred_at=_T0)
    _record(event)
    _record(event)  # a repeated delivery of the same outbox event
    assert _total(tenant_id, "calls") == Decimal("5")


def test_different_events_and_tenants_are_independent(world: _World) -> None:
    tenant_a, tenant_b = world.tenant(), world.tenant()
    first = _ingest(tenant_a, "calls", Decimal("1"), occurred_at=_T0)
    second = _ingest(tenant_a, "calls", Decimal("2"), occurred_at=_T0)
    _record(first)
    _record(second)
    # tenant B's consumer running under the same event identity as A's:
    shared = _ingest(tenant_b, "calls", Decimal("7"), occurred_at=_T0)
    _record(shared, event_id=first.id)
    assert _total(tenant_a, "calls") == Decimal("3")
    assert _total(tenant_b, "calls") == Decimal("7")


# --- Aggregation windows -----------------------------------------------------------------


def test_the_window_includes_since_and_excludes_until(world: _World) -> None:
    tenant_id = world.tenant()
    since, until = _T0, _T0 + timedelta(hours=1)
    for at, quantity in (
        (since - timedelta(microseconds=1), "1"),
        (since, "10"),
        (until - timedelta(microseconds=1), "100"),
        (until, "1000"),
    ):
        _record(_ingest(tenant_id, "edge", Decimal(quantity), occurred_at=at))
    assert aggregate_usage(tenant_id, "edge", since=since, until=until) == Decimal("110")


def test_a_window_given_in_another_offset_is_the_same_utc_window(world: _World) -> None:
    tenant_id = world.tenant()
    _record(_ingest(tenant_id, "tz", Decimal("4"), occurred_at=_T0))
    plus_five = timezone(timedelta(hours=5))
    since = (_T0 - timedelta(minutes=1)).astimezone(plus_five)
    until = (_T0 + timedelta(minutes=1)).astimezone(plus_five)
    assert aggregate_usage(tenant_id, "tz", since=since, until=until) == Decimal("4")


@pytest.mark.parametrize(
    ("since", "until"),
    [
        (datetime(2026, 6, 1), datetime(2026, 7, 1)),  # naive
        (_T0, None),  # one bound only
        (None, _T0),
        (_T0 + timedelta(hours=1), _T0),  # inverted
    ],
)
def test_an_invalid_window_is_refused(world: _World, since: Any, until: Any) -> None:
    tenant_id = world.tenant()
    with pytest.raises(InvalidUsageEventError):
        check_quota(tenant_id, "calls", since=since, until=until)
    with pytest.raises(InvalidUsageEventError):
        consume_quota(tenant_id, "calls", Decimal("1"), since=since, until=until)
    if since is not None and until is not None:
        with pytest.raises(InvalidUsageEventError):
            aggregate_usage(tenant_id, "calls", since=since, until=until)


def test_concurrent_consumption_and_aggregation_never_exceed_the_limit(world: _World) -> None:
    """Twenty concurrent `consume_quota()` calls against a limit of 10,
    while another thread aggregates: exactly 10 succeed, every aggregate
    read is a committed total within the limit, the final total is 10."""
    tenant_id = world.tenant()
    world.limit(tenant_id, "seats", 10)
    barrier = threading.Barrier(21)
    outcomes: list[str] = []
    seen: list[Decimal] = []
    lock = threading.Lock()

    def _consume() -> None:
        barrier.wait()
        try:
            consume_quota(tenant_id, "seats", Decimal("1"))
            result = "ok"
        except QuotaExceededError:
            result = "exceeded"
        with lock:
            outcomes.append(result)

    def _aggregate() -> None:
        barrier.wait()
        for _ in range(20):
            seen.append(check_quota(tenant_id, "seats").used)

    threads = [threading.Thread(target=_consume) for _ in range(20)]
    threads.append(threading.Thread(target=_aggregate))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)

    assert outcomes.count("ok") == 10
    assert outcomes.count("exceeded") == 10
    assert all(Decimal("0") <= used <= Decimal("10") for used in seen)
    assert check_quota(tenant_id, "seats").used == Decimal("10")


# --- Tenant isolation ------------------------------------------------------------------


def test_a_forged_tenant_cannot_redirect_usage(world: _World) -> None:
    """Tenant A's session naming tenant B: RLS refuses the write."""
    tenant_a, tenant_b = world.tenant(), world.tenant()
    with pytest.raises(DBAPIError, match="row-level security"):  # noqa: PT012
        with tenant_session_scope(tenant_a) as session:
            ingest_event(session, tenant_b, "calls", Decimal("1"))
    assert _events(tenant_b) == []


def test_usage_rows_are_visible_only_under_their_own_tenant_scope(world: _World) -> None:
    tenant_a, tenant_b = world.tenant(), world.tenant()
    _record(_ingest(tenant_b, "calls", Decimal("9"), occurred_at=_T0))

    with tenant_session_scope(tenant_a) as session:
        assert list(session.execute(select(UsageEvent)).scalars()) == []
    with session_scope() as session:  # no tenant bound at all
        assert list(session.execute(select(UsageEvent)).scalars()) == []
    assert _total(tenant_a, "calls") == Decimal("0")
    assert _total(tenant_b, "calls") == Decimal("9")


# --- Failure --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"quantity": "1", "occurred_at": "2026-06-01T12:00:00+00:00"},
        {"metric": "calls", "quantity": "Infinity", "occurred_at": "2026-06-01T12:00:00+00:00"},
        {"metric": "calls", "quantity": "-3", "occurred_at": "2026-06-01T12:00:00+00:00"},
        {"metric": "calls", "quantity": "abc", "occurred_at": "2026-06-01T12:00:00+00:00"},
        {"metric": "calls", "quantity": "1", "occurred_at": "not-a-time"},
    ],
    ids=["no-metric", "infinite", "negative", "unparseable", "bad-time"],
)
def test_a_malformed_usage_event_is_dead_lettered_and_records_nothing(
    world: _World, monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]
) -> None:
    import saas_os.core.outbox.dispatch as dispatch
    from saas_os.core.tenancy import list_open_tenant_ids

    tenant_id = world.tenant()
    monkeypatch.setattr(
        dispatch,
        "list_open_tenant_ids",
        lambda: [t for t in list_open_tenant_ids() if t == tenant_id],
    )
    with tenant_session_scope(tenant_id) as session:
        event_id = append_event(
            session,
            tenant_id=tenant_id,
            event_type=USAGE_INGESTION_EVENT_TYPE,
            aggregate_type="usage_metric",
            aggregate_id="calls",
            payload=payload,
        )
    (claim,) = claim_due_events()
    asyncio.run(
        _run_outbox_event(
            TenantJobContext(tenant_id=tenant_id),
            TenantJobPayload(
                tenant_id=str(tenant_id),
                data={"outbox_event_id": str(event_id), "claim_token": str(claim.claim_token)},
            ),
        )
    )

    (event,) = _events(tenant_id)
    assert event.status == OUTBOX_STATUS_DEAD_LETTERED
    assert event.attempts == 1
    assert event.last_error is not None and event.last_error.startswith("MalformedUsageEventError")
    assert _total(tenant_id, "calls") == Decimal("0")


def test_a_negative_idempotent_consumption_cannot_lower_measured_usage(world: _World) -> None:
    """Regression: `consume_quota_idempotent()` validated nothing, so a
    negative quantity was recorded as negative usage -- lowering the total
    every quota decision is made against."""
    tenant_id = world.tenant()
    world.limit(tenant_id, "seats", 2)
    consume_quota(tenant_id, "seats", Decimal("2"))

    with pytest.raises(InvalidUsageEventError):
        consume_quota_idempotent(tenant_id, "seats", Decimal("-100"), "refund-attempt")
    with pytest.raises(QuotaExceededError):
        consume_quota(tenant_id, "seats", Decimal("1"))
    assert check_quota(tenant_id, "seats").used == Decimal("2")


def test_a_database_failure_is_raised_never_read_as_zero_usage(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = world.tenant()

    def _down(*_: object, **__: object) -> Any:
        raise OperationalError("SELECT 1", {}, Exception("connection lost"))

    monkeypatch.setattr(usage_service, "tenant_session_scope", _down)
    with pytest.raises(OperationalError):
        aggregate_usage(tenant_id, "calls", since=_WINDOW[0], until=_WINDOW[1])
    with pytest.raises(OperationalError):
        consume_quota(tenant_id, "calls", Decimal("1"), since=_WINDOW[0], until=_WINDOW[1])
