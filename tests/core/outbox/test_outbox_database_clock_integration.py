"""The outbox runs on one clock: PostgreSQL's (dispatch.py, "One clock").

`append_event()` stamps a new event with the database's `now()`; the
dispatcher must judge it due, schedule its lease and its retries, and see a
lease expire by that same clock -- never by the application host's. These
tests make the two clocks disagree without waiting and without touching any
system clock:

- the host clock is the one the dispatch path would read
  (`saas_os.core.outbox.dispatch.datetime`), replaced by one shifted by a
  chosen offset -- per thread where two dispatchers run on two hosts;
- the database's view of time is set on the rows themselves: an event made
  due (or not yet due) a given number of seconds from the database's
  `now()`, or "aged" by exactly a lease or a backoff, which is what the
  passing of that much database time does to it.

Each test that targets the clock fails against the previous implementation
(host-clock comparisons and writes); see the PR for the negative control.
Real PostgreSQL; the end-to-end tests also use real Redis and a real ARQ
burst worker. Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.api.outbox_dispatcher as outbox_dispatcher
import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.api.outbox_dispatcher import OUTBOX_JOB_FUNCTIONS, dispatch_outbox_once
from saas_os.core.outbox import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    AmbiguousOutcomeError,
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
from saas_os.core.tenancy import create_tenant, list_open_tenant_ids
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload, build_worker
from saas_os.infra.jobs.queue import get_redis_pool

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_EVENT_TYPE = "clock.probe"
_CONFIG = OutboxDispatchConfig(
    max_attempts=5,
    retry_base_seconds=60,
    retry_max_seconds=600,
    retry_jitter_ratio=0,
    lease_seconds=300,
    enqueue_retry_seconds=30,
    batch_size=50,
    per_tenant_limit=50,
)
_HOUR = timedelta(hours=1)
# A schedule written "now + N seconds" by the database is read back a few
# milliseconds later; anything within this margin of N is N.
_MARGIN = 30.0


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


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


@pytest.fixture(autouse=True)
def _dispatch_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dispatch, "get_outbox_dispatch_config", lambda: _CONFIG)


def _admin(sql: str, params: Mapping[str, object], *, fetch: bool = False) -> list[Any]:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            result = session.execute(text(sql), dict(params))
            return list(result.all()) if fetch else []
    finally:
        engine.dispose()


# --- The two clocks -------------------------------------------------------------------


class _HostClock:
    """The application host's clock as the dispatch path reads it, shifted
    by `offset` -- or by a per-thread offset, for two dispatchers on two
    hosts."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.offset = timedelta(0)
        self.per_thread: dict[str, timedelta] = {}
        clock = self
        real = datetime

        class _Shifted(datetime):
            @classmethod
            def now(cls, tz: tzinfo | None = None) -> datetime:  # type: ignore[override]
                name = threading.current_thread().name
                return real.now(tz) + clock.per_thread.get(name, clock.offset)

        monkeypatch.setattr(dispatch, "datetime", _Shifted)


@pytest.fixture
def host_clock(monkeypatch: pytest.MonkeyPatch) -> _HostClock:
    return _HostClock(monkeypatch)


def _seconds_until_due(event_id: uuid.UUID) -> float:
    """`next_attempt_at` measured on the database's own clock."""
    ((seconds,),) = _admin(
        "SELECT EXTRACT(EPOCH FROM next_attempt_at - now()) FROM core.outbox_events WHERE id = :i",
        {"i": event_id},
        fetch=True,
    )
    return float(seconds)


def _due_in(event_id: uuid.UUID, seconds: float) -> None:
    """Make the event due `seconds` from the database's now (negative: overdue)."""
    _admin(
        "UPDATE core.outbox_events SET next_attempt_at = now() + make_interval(secs => :s)"
        " WHERE id = :i",
        {"i": event_id, "s": seconds},
    )


def _age(event_id: uuid.UUID, by: timedelta) -> None:
    """What `by` of database time passing does to the event's schedule."""
    _admin(
        "UPDATE core.outbox_events SET next_attempt_at = next_attempt_at"
        " - make_interval(secs => :s) WHERE id = :i",
        {"i": event_id, "s": by.total_seconds()},
    )


# --- Tenants and events ---------------------------------------------------------------


class _Tenants:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.ids: list[uuid.UUID] = []
        monkeypatch.setattr(
            dispatch,
            "list_open_tenant_ids",
            lambda: [t for t in list_open_tenant_ids() if t in self.ids],
        )

    def new(self) -> uuid.UUID:
        tenant_id = create_tenant(f"outbox-clock-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
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


def _append(tenant_id: uuid.UUID) -> uuid.UUID:
    with tenant_session_scope(tenant_id) as session:
        return append_event(
            session,
            tenant_id=tenant_id,
            event_type=_EVENT_TYPE,
            aggregate_type="probe",
            aggregate_id="1",
            payload={"probe": True},
        )


def _row(tenant_id: uuid.UUID, event_id: uuid.UUID) -> OutboxEvent:
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(select(OutboxEvent).where(OutboxEvent.id == event_id)).scalar_one()
        session.expunge(row)
        return row


def _claim() -> list[dispatch.ClaimedEvent]:
    return claim_due_events(config=_CONFIG, rng=lambda: 0.0)


# --- End to end: real dispatcher, real Redis, real worker -------------------------------


@pytest.fixture
async def sends(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    """Every external send the consumer makes, by event id."""
    try:
        pool = await get_redis_pool()
        await pool.ping()
        await pool.aclose()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable: {exc}")
    sent: list[uuid.UUID] = []

    async def _send(ctx: TenantJobContext, payload: TenantJobPayload) -> None:
        assert ctx.event_id is not None
        sent.append(ctx.event_id)

    monkeypatch.setattr(outbox_dispatcher, "outbox_event_handlers", lambda: {_EVENT_TYPE: _send})
    return sent


async def _cycle() -> int:
    """One dispatch cycle and a burst worker draining what it handed off;
    returns how many events the cycle claimed."""
    queue_name = f"outbox-clock-{uuid.uuid4().hex[:8]}"
    report = await dispatch_outbox_once(config=_CONFIG, queue_name=queue_name)
    worker = build_worker(OUTBOX_JOB_FUNCTIONS, burst=True, queue_name=queue_name)
    try:
        await worker.main()
    finally:
        await worker.close()
    return report.claimed


# --- (1) database ahead of the host ---------------------------------------------------


def test_database_ahead_of_host_a_new_event_is_claimed_at_once(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    """The database stamped the event with its own now; a host an hour
    behind must still find it due."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    host_clock.offset = -_HOUR

    (claim,) = _claim()

    assert (claim.id, claim.attempts) == (event_id, 1)
    assert abs(_seconds_until_due(event_id) - _CONFIG.lease_seconds) < _MARGIN


# --- (2) database behind the host -----------------------------------------------------


def test_database_behind_host_an_event_not_yet_due_is_not_claimed(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    _due_in(event_id, 600)
    host_clock.offset = _HOUR  # past the due time by the host's clock only

    assert _claim() == []
    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_PENDING, 0, None)


# --- (3) host clock corrected mid-dispatch --------------------------------------------


def test_a_host_clock_correction_mid_dispatch_changes_no_schedule(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    """The host clock is an hour fast when the event is claimed, corrected
    before the worker starts it, and an hour slow when the failure is
    recorded: the lease and the retry are still exactly a lease and a
    backoff from the database's now."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)

    host_clock.offset = _HOUR
    (claim,) = _claim()
    assert abs(_seconds_until_due(event_id) - _CONFIG.lease_seconds) < _MARGIN

    host_clock.offset = timedelta(0)
    assert begin_event_execution(tenant_id, event_id, claim.claim_token) is not None
    assert abs(_seconds_until_due(event_id) - _CONFIG.lease_seconds) < _MARGIN

    host_clock.offset = -_HOUR
    status = fail_event(tenant_id, event_id, claim.claim_token, "Boom", rng=lambda: 0.0)

    assert status == OUTBOX_STATUS_PENDING
    backoff = retry_delay(1, _CONFIG, lambda: 0.0).total_seconds()
    assert abs(_seconds_until_due(event_id) - backoff) < _MARGIN
    assert _claim() == []  # not before the backoff, by the database's clock


# --- (4) and (5) due by the database's clock, end to end ------------------------------


async def test_an_event_is_not_dispatched_before_its_database_due_time(
    tenants: _Tenants, host_clock: _HostClock, sends: list[uuid.UUID]
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    _due_in(event_id, 600)
    host_clock.offset = _HOUR

    assert await _cycle() == 0

    assert sends == []
    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_PENDING, 0)


async def test_an_event_is_dispatched_once_it_is_due_by_database_time(
    tenants: _Tenants, host_clock: _HostClock, sends: list[uuid.UUID]
) -> None:
    """Of two events, only the one due by the database's clock is sent --
    with the host an hour behind it -- and it is sent exactly once."""
    tenant_id = tenants.new()
    due, later = _append(tenant_id), _append(tenant_id)
    _due_in(due, -1)
    _due_in(later, 600)
    host_clock.offset = -_HOUR

    assert await _cycle() == 1
    assert await _cycle() == 0

    assert sends == [due]
    assert (_row(tenant_id, due).status, _row(tenant_id, due).attempts) == (
        OUTBOX_STATUS_PUBLISHED,
        1,
    )
    assert _row(tenant_id, later).attempts == 0


# --- (6) pending events during and after a temporary skew -----------------------------


async def test_events_pending_during_a_temporary_skew_are_each_delivered_once(
    tenants: _Tenants, host_clock: _HostClock, sends: list[uuid.UUID]
) -> None:
    tenant_a, tenant_b = tenants.new(), tenants.new()
    events = [_append(tenant_a), _append(tenant_b), _append(tenant_a)]

    host_clock.offset = -_HOUR  # the skew: the host an hour behind the database
    assert await _cycle() == 3
    host_clock.offset = timedelta(0)  # the skew is corrected
    assert await _cycle() == 0

    assert sorted(sends) == sorted(events)
    for tenant_id, event_id in zip((tenant_a, tenant_b, tenant_a), events, strict=True):
        row = _row(tenant_id, event_id)
        assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_PUBLISHED, 1, None)


# --- (7) no duplicate external dispatch -----------------------------------------------


def test_a_running_event_is_not_dispatched_twice_when_hosts_disagree(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    """Dispatcher A, on a host an hour slow, claims and starts the event;
    dispatcher B, on a correct host, runs while A's consumer is still
    sending. A's lease is the database's now plus the lease, so B finds
    nothing to claim and the destination receives the event once."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    _due_in(event_id, -2 * 3600)
    sent: list[uuid.UUID] = []

    host_clock.offset = -_HOUR  # dispatcher A's host
    (claim_a,) = _claim()
    execution = begin_event_execution(tenant_id, event_id, claim_a.claim_token)
    assert execution is not None
    sent.append(execution.id)  # A's consumer is sending...

    host_clock.offset = timedelta(0)  # ...while dispatcher B runs
    claims_b = _claim()
    for claim in claims_b:
        if (
            execution_b := begin_event_execution(tenant_id, claim.id, claim.claim_token)
        ) is not None:
            sent.append(execution_b.id)

    assert claims_b == []
    assert complete_event(tenant_id, event_id, claim_a.claim_token) is True
    assert sent == [event_id]
    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_PUBLISHED, 1)


# --- (8) no lost events ---------------------------------------------------------------


def test_retries_scheduled_while_the_host_was_fast_are_not_lost(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    """Three events fail while the host clock is an hour fast. Once their
    backoff has passed on the database's clock they are all claimed again
    and published -- none is held back by the skew of the host that
    recorded the failure."""
    tenant_id = tenants.new()
    events = {_append(tenant_id) for _ in range(3)}
    claims = _claim()
    assert {c.id for c in claims} == events

    host_clock.offset = _HOUR
    for claim in claims:
        assert fail_event(tenant_id, claim.id, claim.claim_token, "Boom", rng=lambda: 0.0) == (
            OUTBOX_STATUS_PENDING
        )
    host_clock.offset = timedelta(0)
    assert _claim() == []
    for event_id in events:
        _age(event_id, retry_delay(1, _CONFIG, lambda: 0.0))

    retries = _claim()
    assert {c.id for c in retries} == events
    assert {c.attempts for c in retries} == {2}
    for claim in retries:
        assert complete_event(tenant_id, claim.id, claim.claim_token) is True
    assert {_row(tenant_id, e).status for e in events} == {OUTBOX_STATUS_PUBLISHED}


# --- (9) lease expiry between two dispatchers on two connections ------------------------


def test_lease_expiry_between_two_concurrent_dispatchers_follows_the_database_clock(
    tenants: _Tenants, host_clock: _HostClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dispatcher A (its own thread and connection, host an hour slow) holds
    its claim transaction open; dispatcher B (host an hour fast) skips the
    locked row. After A commits, B still finds nothing: A's lease runs on
    the database's clock. Only once a lease of database time has passed is
    the event reclaimed by B -- and A, having lost it, can no longer
    complete it."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    _due_in(event_id, -2 * 3600)
    host_clock.per_thread = {"dispatcher-a": -_HOUR}
    host_clock.offset = _HOUR  # every other thread: dispatcher B
    paused, release = threading.Event(), threading.Event()

    def _hold(session: object) -> None:
        if threading.current_thread().name == "dispatcher-a":
            paused.set()
            assert release.wait(timeout=30), "dispatcher A never released"

    monkeypatch.setattr(dispatch, "_claim_hook", _hold)
    outcome: dict[str, Any] = {}

    def _run_a() -> None:
        outcome["a"] = _claim()

    thread_a = threading.Thread(target=_run_a, name="dispatcher-a")
    thread_a.start()
    try:
        assert paused.wait(timeout=30), "dispatcher A never reached its claim"
        assert _claim() == []  # the row is locked: skipped, never waited for
        assert thread_a.is_alive()
    finally:
        release.set()
        thread_a.join(timeout=30)

    (claim_a,) = outcome["a"]
    assert claim_a.id == event_id
    assert abs(_seconds_until_due(event_id) - _CONFIG.lease_seconds) < _MARGIN
    assert _claim() == []  # A's lease is live by the database's clock

    _age(event_id, _CONFIG.lease)
    (claim_b,) = _claim()

    assert (claim_b.id, claim_b.attempts) == (event_id, 2)
    assert claim_b.claim_token != claim_a.claim_token
    row = _row(tenant_id, event_id)
    assert row.last_error is not None and row.last_error.startswith("LeaseExpired")
    assert complete_event(tenant_id, event_id, claim_a.claim_token) is False
    assert complete_event(tenant_id, event_id, claim_b.claim_token) is True
    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_PUBLISHED, 2)


# --- Explicit `now` keeps working ------------------------------------------------------


def test_an_explicit_now_is_still_used_as_given(tenants: _Tenants) -> None:
    """The `now=` test seam is unchanged: an explicit instant decides
    due-ness and is the base of the lease."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    past = datetime(2000, 1, 1, tzinfo=UTC)
    future = datetime(2100, 1, 1, tzinfo=UTC)

    assert claim_due_events(config=_CONFIG, now=past, rng=lambda: 0.0) == []
    (claim,) = claim_due_events(config=_CONFIG, now=future, rng=lambda: 0.0)

    assert claim.id == event_id
    assert _row(tenant_id, event_id).next_attempt_at == future + _CONFIG.lease


# --- The enqueue retry and the publication time ---------------------------------------


def test_a_failed_hand_off_is_retried_after_the_enqueue_delay_on_the_database_clock(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    """The queue refused the hand-off while the host clock was an hour fast:
    the claim is given back, the attempt refunded, and the event is due
    again `enqueue_retry_seconds` from the database's now -- not an hour
    later."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    (claim,) = _claim()

    host_clock.offset = _HOUR
    assert release_claim(tenant_id, event_id, claim.claim_token, "QueueDown") is True

    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_PENDING, 0, None)
    assert abs(_seconds_until_due(event_id) - _CONFIG.enqueue_retry_seconds) < _MARGIN
    assert _claim() == []
    _age(event_id, _CONFIG.enqueue_retry_delay)
    (again,) = _claim()
    assert (again.id, again.attempts) == (event_id, 1)


def test_published_at_is_the_database_time_whatever_the_host_clock(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    (claim,) = _claim()

    host_clock.offset = -_HOUR
    assert complete_event(tenant_id, event_id, claim.claim_token) is True

    ((age,),) = _admin(
        "SELECT EXTRACT(EPOCH FROM now() - published_at) FROM core.outbox_events WHERE id = :i",
        {"i": event_id},
        fetch=True,
    )
    assert 0 <= float(age) < _MARGIN
    assert _row(tenant_id, event_id).status == OUTBOX_STATUS_PUBLISHED


# --- (8) the ambiguous-outcome idempotency window is judged on the database's clock ------
#
# `begin_event_execution()` and `record_ambiguous_outcome()` compare an
# idempotent-retry deadline in Python, through `_instant()`, which reads the
# database's transaction time when no `now` is passed. The tests below pass
# none. The host clock is shifted by more than the whole window, in the
# direction that would flip the answer if the host clock were consulted.

_WINDOW = timedelta(hours=1)
_SKEW = timedelta(hours=3)


def _set_created_at_ago(event_id: uuid.UUID, ago: timedelta) -> None:
    """Make the event `ago` old by the database's clock."""
    _admin(
        "UPDATE core.outbox_events SET created_at = now() - make_interval(secs => :s)"
        " WHERE id = :i",
        {"i": event_id, "s": ago.total_seconds()},
    )


def _claimed_retry_with_deadline(event_id: uuid.UUID, deadline_from_now: timedelta) -> uuid.UUID:
    """Claim the event, then make it the second attempt of an event whose
    idempotency window ends `deadline_from_now` after the database's now
    (negative: already closed); returns the claim token."""
    (claim,) = _claim()
    assert claim.id == event_id
    ((deadline,),) = _admin(
        "SELECT now() + make_interval(secs => :s)",
        {"s": deadline_from_now.total_seconds()},
        fetch=True,
    )
    _admin(
        "UPDATE core.outbox_events SET attempts = 2, last_error = :e WHERE id = :i",
        {"i": event_id, "e": f"OutcomeUnknown: probe {dispatch._deadline_tag(deadline)}"},
    )
    return claim.claim_token


def test_a_host_clock_ahead_of_the_window_does_not_stop_a_retry_the_database_allows(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    """The database is still inside the window (an hour left); the host is
    three hours ahead of it, so by the host's clock the window closed two
    hours ago. The retry must still run."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    claim_token = _claimed_retry_with_deadline(event_id, _WINDOW)
    host_clock.offset = _SKEW

    execution = begin_event_execution(tenant_id, event_id, claim_token)

    assert execution is not None and execution.id == event_id
    assert _row(tenant_id, event_id).status == OUTBOX_STATUS_PENDING


def test_a_host_clock_behind_the_window_does_not_let_a_retry_the_database_refuses_run(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    """The window closed an hour ago by the database's clock; the host is
    three hours behind it, so by the host's clock two hours remain. The
    retry must be dead-lettered, not run."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    claim_token = _claimed_retry_with_deadline(event_id, -_WINDOW)
    host_clock.offset = -_SKEW

    assert begin_event_execution(tenant_id, event_id, claim_token) is None

    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert (row.last_error or "").startswith("OutcomeUnknown: the idempotency window closed")


def _ambiguous_with_window(tenant_id: uuid.UUID, event_id: uuid.UUID) -> str | None:
    (claim,) = _claim()
    assert claim.id == event_id
    error = AmbiguousOutcomeError("read timeout", phase="read", retry_within=_WINDOW)
    return dispatch.record_ambiguous_outcome(
        tenant_id, event_id, claim.claim_token, error, rng=lambda: 0.0
    )


def test_an_ambiguous_outcome_is_retried_while_the_database_is_inside_its_window(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    """The event was created just now: the database is at the start of its
    window. A host three hours ahead would see the deadline as passed."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    host_clock.offset = _SKEW

    status = _ambiguous_with_window(tenant_id, event_id)

    assert status == OUTBOX_STATUS_PENDING
    row = _row(tenant_id, event_id)
    assert row.claim_token is None and "idempotent-retry-until" in (row.last_error or "")
    backoff = retry_delay(1, _CONFIG, lambda: 0.0).total_seconds()
    assert abs(_seconds_until_due(event_id) - backoff) < _MARGIN


def test_an_ambiguous_outcome_is_dead_lettered_once_the_database_is_past_its_window(
    tenants: _Tenants, host_clock: _HostClock
) -> None:
    """The event is two hours old by the database's clock, so its one-hour
    window closed an hour ago. A host three hours behind would still see
    the window open."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    _set_created_at_ago(event_id, 2 * _WINDOW)
    host_clock.offset = -_SKEW

    status = _ambiguous_with_window(tenant_id, event_id)

    assert status == OUTBOX_STATUS_DEAD_LETTERED
    row = _row(tenant_id, event_id)
    assert "idempotency window closed" in (row.last_error or "")
