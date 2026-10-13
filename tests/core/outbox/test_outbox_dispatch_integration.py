"""The durable outbox state machine (Foundation Reliability & Events, RE-2)
against real PostgreSQL.

Claims, leases, attempts, retries, dead-lettering, claim ownership, tenant
isolation and lifecycle fencing -- driven through `saas_os.core.outbox.dispatch`
with explicit `now` values, so lease expiry and retry schedules are tested
without waiting. Concurrency is real: two dispatchers on two connections,
coordinated with thread events (never a sleep), against PostgreSQL's own
`FOR UPDATE SKIP LOCKED`.

The dispatcher visits every open tenant; each test scopes that enumeration
to its own tenants (intersected with the real `list_open_tenant_ids()`, so
closed-tenant filtering is still the real one) so rows of unrelated tests
cannot interfere.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING, platform_operator
from saas_os.core.outbox import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    OutboxDispatchConfig,
    OutboxEvent,
    append_event,
    begin_event_execution,
    claim_due_events,
    complete_event,
    fail_event,
    release_claim,
    retry_delay,
)
from saas_os.core.tenancy import (
    TenantStatus,
    create_tenant,
    list_open_tenant_ids,
    transition_tenant_status,
)
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

_CONFIG = OutboxDispatchConfig(
    max_attempts=3,
    retry_base_seconds=60,
    retry_max_seconds=600,
    retry_jitter_ratio=0,
    lease_seconds=300,
    enqueue_retry_seconds=30,
    batch_size=50,
    per_tenant_limit=50,
)
_T0 = datetime(2030, 1, 1, tzinfo=UTC)  # after every row's creation time


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
            conn.execute(text("SELECT claim_token FROM core.outbox_events LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable/migrated to RE-2: {exc}")
    finally:
        probe.dispose()


def _admin(sql: str, params: Mapping[str, object]) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            session.execute(text(sql), params)
    finally:
        engine.dispose()


class _Tenants:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.ids: list[uuid.UUID] = []
        monkeypatch.setattr(
            dispatch,
            "list_open_tenant_ids",
            lambda: [t for t in list_open_tenant_ids() if t in self.ids],
        )

    def new(self) -> uuid.UUID:
        tenant_id = create_tenant(
            f"outbox-dispatch-{uuid.uuid4().hex[:10]}", caller=PROVISIONING
        ).id
        self.ids.append(tenant_id)
        return tenant_id

    def cleanup(self) -> None:
        for tenant_id in self.ids:
            params = {"t": str(tenant_id)}
            _admin("DELETE FROM core.outbox_events WHERE tenant_id = :t", params)
            _admin(
                "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t",
                params,
            )
            _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
            _admin("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t", params)
            _admin("DELETE FROM core.tenants WHERE id = :t", params)


@pytest.fixture
def tenants(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Tenants]:
    registry = _Tenants(monkeypatch)
    try:
        yield registry
    finally:
        registry.cleanup()


def _append(tenant_id: uuid.UUID, event_type: str = "usage.ingestion") -> uuid.UUID:
    with tenant_session_scope(tenant_id) as session:
        return append_event(
            session,
            tenant_id=tenant_id,
            event_type=event_type,
            aggregate_type="probe",
            aggregate_id="1",
            payload={"metric": "m", "quantity": "1", "occurred_at": _T0.isoformat()},
        )


def _row(tenant_id: uuid.UUID, event_id: uuid.UUID) -> OutboxEvent:
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(select(OutboxEvent).where(OutboxEvent.id == event_id)).scalar_one()
        session.expunge(row)
        return row


def _claim(at: datetime, config: OutboxDispatchConfig = _CONFIG) -> list[dispatch.ClaimedEvent]:
    return claim_due_events(config=config, now=at, rng=lambda: 0.0)


# --- Claims and leases -------------------------------------------------------------


def test_a_claim_counts_the_attempt_and_sets_a_lease(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)

    (claim,) = _claim(_T0)

    assert (claim.id, claim.tenant_id, claim.attempts) == (event_id, tenant_id, 1)
    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.claim_token == claim.claim_token
    assert row.attempts == 1
    assert row.next_attempt_at == _T0 + _CONFIG.lease
    assert row.tenant_id == tenant_id  # a claim never changes ownership


def test_an_active_lease_is_not_stolen(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)
    (claim,) = _claim(_T0)

    assert _claim(_T0 + _CONFIG.lease - timedelta(seconds=1)) == []
    assert _row(tenant_id, claim.id).claim_token == claim.claim_token


def test_a_stale_lease_is_reclaimed_and_the_old_owner_loses_the_event(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)
    (first,) = _claim(_T0)

    (second,) = _claim(_T0 + _CONFIG.lease)

    assert second.id == first.id
    assert second.claim_token != first.claim_token
    assert second.attempts == 2
    row = _row(tenant_id, first.id)
    assert row.last_error is not None and row.last_error.startswith("LeaseExpired")
    # The old owner can no longer change the event in any way.
    assert complete_event(tenant_id, first.id, first.claim_token) is False
    assert fail_event(tenant_id, first.id, first.claim_token, "x", config=_CONFIG) is None
    assert release_claim(tenant_id, first.id, first.claim_token, "x", config=_CONFIG) is False
    assert begin_event_execution(tenant_id, first.id, first.claim_token, config=_CONFIG) is None
    assert _row(tenant_id, first.id).claim_token == second.claim_token


def test_two_dispatchers_never_claim_the_same_event(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dispatcher A has locked and claimed the event but not committed;
    dispatcher B, on another connection, skips the locked row (it neither
    claims it nor waits for A). Once A commits, B still finds nothing: the
    lease is A's."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    paused, release = threading.Event(), threading.Event()

    def _hold(session: object) -> None:
        if threading.current_thread().name == "dispatcher-a":
            paused.set()
            assert release.wait(timeout=30), "dispatcher A never released"

    monkeypatch.setattr(dispatch, "_claim_hook", _hold)
    outcome: dict[str, Any] = {}

    def _run_a() -> None:
        outcome["a"] = _claim(_T0)

    thread_a = threading.Thread(target=_run_a, name="dispatcher-a")
    thread_a.start()
    try:
        assert paused.wait(timeout=30), "dispatcher A never reached its claim"
        claims_b = _claim(_T0)  # returns while A still holds the row lock
        assert claims_b == []
        assert thread_a.is_alive()
    finally:
        release.set()
        thread_a.join(timeout=30)

    (claim_a,) = outcome["a"]
    assert claim_a.id == event_id
    assert _claim(_T0) == []
    assert _row(tenant_id, event_id).claim_token == claim_a.claim_token


def test_a_claim_lost_before_hand_off_is_recovered(tenants: _Tenants) -> None:
    """A dispatcher claimed (committed) and died before enqueueing: nothing
    happens until the lease expires, then the event is claimed again."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    _claim(_T0)  # ...and the process dies here

    assert _claim(_T0 + timedelta(seconds=1)) == []
    (recovered,) = _claim(_T0 + _CONFIG.lease)
    assert recovered.id == event_id
    assert _row(tenant_id, event_id).status == OUTBOX_STATUS_PENDING


def test_batches_respect_the_per_tenant_and_total_limits(tenants: _Tenants) -> None:
    tenant_a, tenant_b = tenants.new(), tenants.new()
    for _ in range(3):
        _append(tenant_a)
        _append(tenant_b)
    config = OutboxDispatchConfig(
        retry_jitter_ratio=0, batch_size=3, per_tenant_limit=2, lease_seconds=300
    )

    first = _claim(_T0, config)
    assert len(first) == 3
    assert max(sum(c.tenant_id == t for c in first) for t in (tenant_a, tenant_b)) == 2
    second = _claim(_T0, config)
    third = _claim(_T0, config)
    assert len(first) + len(second) + len(third) == 6
    assert len({c.id for c in first + second + third}) == 6


# --- Outcomes, retries and dead-lettering ---------------------------------------------


def test_success_publishes_the_event_and_it_is_never_claimed_again(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    (claim,) = _claim(_T0)
    execution = begin_event_execution(
        tenant_id, event_id, claim.claim_token, config=_CONFIG, now=_T0
    )
    assert execution is not None and execution.payload["metric"] == "m"

    assert complete_event(tenant_id, event_id, claim.claim_token, now=_T0) is True

    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_PUBLISHED
    assert row.published_at == _T0
    assert row.claim_token is None
    assert _claim(_T0 + timedelta(days=30)) == []


def test_a_failure_schedules_a_retry_that_is_due_only_when_scheduled(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    (claim,) = _claim(_T0)

    status = fail_event(
        tenant_id, event_id, claim.claim_token, RuntimeError("boom"), config=_CONFIG, now=_T0
    )

    assert status == OUTBOX_STATUS_PENDING
    row = _row(tenant_id, event_id)
    assert row.claim_token is None
    assert row.attempts == 1
    assert row.last_error == "RuntimeError: boom"
    due = _T0 + retry_delay(1, _CONFIG, lambda: 0.0)
    assert row.next_attempt_at == due
    assert _claim(due - timedelta(seconds=1)) == []
    (retry,) = _claim(due)
    assert retry.attempts == 2


def test_attempts_are_exhausted_into_a_durable_dead_letter(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    at = _T0
    for attempt in range(1, _CONFIG.max_attempts + 1):
        (claim,) = _claim(at)
        assert claim.attempts == attempt
        status = fail_event(
            tenant_id,
            event_id,
            claim.claim_token,
            ValueError(f"fail {attempt}"),
            config=_CONFIG,
            now=at,
        )
        at = at + timedelta(days=1)

    assert status == OUTBOX_STATUS_DEAD_LETTERED
    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.id == event_id
    assert row.attempts == _CONFIG.max_attempts
    assert row.last_error == f"ValueError: fail {_CONFIG.max_attempts}"
    assert row.claim_token is None
    assert row.payload["metric"] == "m"  # the event itself is preserved
    assert _claim(at + timedelta(days=365)) == []  # never dispatched again


def test_a_lost_final_attempt_is_dead_lettered_not_retried_forever(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    at = _T0
    for _ in range(_CONFIG.max_attempts):
        (claim,) = _claim(at)  # each worker dies; the lease simply expires
        at = at + _CONFIG.lease

    assert _claim(at) == []
    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.attempts == _CONFIG.max_attempts
    assert row.last_error is not None and "final attempt" in row.last_error


def test_a_terminal_failure_dead_letters_immediately(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    (claim,) = _claim(_T0)
    status = fail_event(
        tenant_id,
        event_id,
        claim.claim_token,
        "UnknownEventType: x",
        terminal=True,
        config=_CONFIG,
    )
    assert status == OUTBOX_STATUS_DEAD_LETTERED
    assert _row(tenant_id, event_id).attempts == 1


def test_a_failed_hand_off_refunds_the_attempt_and_keeps_the_event(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    (claim,) = _claim(_T0)

    assert release_claim(
        tenant_id,
        event_id,
        claim.claim_token,
        ConnectionError("redis down"),
        config=_CONFIG,
        now=_T0,
    )

    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.attempts == 0
    assert row.claim_token is None
    assert row.last_error == "ConnectionError: redis down"
    assert row.next_attempt_at == _T0 + _CONFIG.enqueue_retry_delay
    (again,) = _claim(_T0 + _CONFIG.enqueue_retry_delay)
    assert again.attempts == 1


# --- Tenancy and lifecycle -------------------------------------------------------------


def test_a_tenant_scope_cannot_run_another_tenants_event(tenants: _Tenants) -> None:
    tenant_a, tenant_b = tenants.new(), tenants.new()
    event_id = _append(tenant_a)
    (claim,) = _claim(_T0)
    assert claim.tenant_id == tenant_a

    # The right event id and claim token, presented under the wrong tenant:
    assert begin_event_execution(tenant_b, event_id, claim.claim_token, config=_CONFIG) is None
    assert complete_event(tenant_b, event_id, claim.claim_token) is False
    assert fail_event(tenant_b, event_id, claim.claim_token, "x", config=_CONFIG) is None
    assert release_claim(tenant_b, event_id, claim.claim_token, "x", config=_CONFIG) is False
    row = _row(tenant_a, event_id)
    assert (row.status, row.claim_token, row.attempts) == (
        OUTBOX_STATUS_PENDING,
        claim.claim_token,
        1,
    )


def test_a_closed_tenants_events_are_not_claimed(tenants: _Tenants) -> None:
    open_tenant, closed_tenant = tenants.new(), tenants.new()
    _append(open_tenant)
    closed_event = _append(closed_tenant)
    transition_tenant_status(closed_tenant, TenantStatus.DELETED, caller=platform_operator())

    claims = _claim(_T0)

    assert [c.tenant_id for c in claims] == [open_tenant]
    assert _row(closed_tenant, closed_event).attempts == 0


def test_a_tenant_closed_after_the_claim_releases_it_without_running(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    (claim,) = _claim(_T0)
    transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())

    assert begin_event_execution(tenant_id, event_id, claim.claim_token, config=_CONFIG) is None
    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.claim_token is None
    assert _claim(_T0 + timedelta(days=1)) == []  # a closed tenant is never claimed again


def test_a_suspended_tenants_events_are_still_dispatched(tenants: _Tenants) -> None:
    """Existing lifecycle contract: SUSPENDED does not cancel work already in
    motion (docs/MULTI-TENANCY.md); only DELETED/PURGING/PURGED fence it."""
    tenant_id = tenants.new()
    transition_tenant_status(tenant_id, TenantStatus.ACTIVE, caller=platform_operator())
    event_id = _append(tenant_id)
    transition_tenant_status(tenant_id, TenantStatus.SUSPENDED, caller=platform_operator())

    (claim,) = _claim(_T0)
    assert begin_event_execution(tenant_id, event_id, claim.claim_token, config=_CONFIG)
