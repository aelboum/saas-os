"""Crash recovery D4: the durable started marker on `core.outbox_events`
(migrations `0420025c3b4b`, `f0cc2e656d79`; design pull request #195,
section 4a; `docs/architecture/OUTBOX-STARTED-MARKER.md`) against real
PostgreSQL, as the application role.

- the marker write (`mark_external_effect_started()`): off by default;
  one conditional `UPDATE` by the current claim, live lease, not yet marked
  by this claim; a stale or duplicated claim writes nothing;
- the reclaim: a lost lease whose marker is the expired claim's is
  dead-lettered `CrashAfterStart:`, marker kept; no marker, or an older
  claim's marker, is a plain retry;
- the outcomes: complete, release and a retry clear the marker; every dead
  letter keeps it; `fail_event()` never retries a marked attempt;
- the pair check, tenant isolation (RLS), and the two race orderings of
  #195 4a.7 (scenarios 7 and 8) on separate connections;
- the dispatcher's `_run_outbox_event` with a probe consumer that uses
  `context.external_effect()`.

Times are explicit (`now=`), so leases expire without waiting. Every row a
test creates is removed afterwards. Marked `integration`.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

import saas_os.api.outbox_dispatcher as outbox_dispatcher
import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.api.outbox_dispatcher import _run_outbox_event
from saas_os.core.outbox import (
    CRASH_AFTER_START_ERROR,
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    ExternalEffectAlreadyStartedError,
    ExternalEffectNotStartedError,
    OutboxDispatchConfig,
    OutboxEvent,
    PermanentEventError,
    RetryAfterEventError,
    append_event,
    claim_due_events,
    complete_event,
    fail_event,
    get_outbox_dispatch_config,
    mark_external_effect_started,
    release_claim,
)
from saas_os.core.tenancy import create_tenant, list_open_tenant_ids
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload

pytestmark = pytest.mark.integration

_OFF = OutboxDispatchConfig(
    max_attempts=3, retry_base_seconds=60, retry_jitter_ratio=0, lease_seconds=300
)
_ON = OutboxDispatchConfig(
    max_attempts=3,
    retry_base_seconds=60,
    retry_jitter_ratio=0,
    lease_seconds=300,
    external_effect_markers=True,
)
_T0 = datetime(2030, 1, 1, tzinfo=UTC)  # after every row's creation time
_LEASE = _ON.lease
_PROBE = "probe.external_effect"


@pytest.fixture(autouse=True)
def _require_database() -> Iterator[None]:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    get_outbox_dispatch_config.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT external_started_claim FROM core.outbox_events LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable/migrated to 0420025c3b4b: {exc}")
    finally:
        probe.dispose()
    yield
    get_outbox_dispatch_config.cache_clear()


def _admin(sql: str, params: Mapping[str, object]) -> list[Any]:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            result = session.execute(text(sql), params)
            return list(result) if getattr(result, "returns_rows", False) else []
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
        tenant_id = create_tenant(f"outbox-d4-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
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


def _append(tenant_id: uuid.UUID, event_type: str = _PROBE) -> uuid.UUID:
    with tenant_session_scope(tenant_id) as session:
        return append_event(
            session,
            tenant_id=tenant_id,
            event_type=event_type,
            aggregate_type="probe",
            aggregate_id="1",
            payload={"n": 1},
        )


def _row(tenant_id: uuid.UUID, event_id: uuid.UUID) -> OutboxEvent:
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(select(OutboxEvent).where(OutboxEvent.id == event_id)).scalar_one()
        session.expunge(row)
        return row


def _claim(at: datetime, config: OutboxDispatchConfig = _ON) -> list[dispatch.ClaimedEvent]:
    return claim_due_events(config=config, now=at, rng=lambda: 0.0)


def _mark(claim: dispatch.ClaimedEvent, at: datetime, config: OutboxDispatchConfig = _ON) -> bool:
    return mark_external_effect_started(
        claim.tenant_id, claim.id, claim.claim_token, config=config, now=at
    )


def _marked_claim(tenants: _Tenants) -> tuple[uuid.UUID, dispatch.ClaimedEvent]:
    tenant_id = tenants.new()
    _append(tenant_id)
    (claim,) = _claim(_T0)
    assert _mark(claim, _T0 + timedelta(seconds=10)) is True
    return tenant_id, claim


# --- The marker write -------------------------------------------------------------


def test_markers_are_off_by_default_and_nothing_is_written(tenants: _Tenants) -> None:
    assert get_outbox_dispatch_config().external_effect_markers is False
    tenant_id = tenants.new()
    _append(tenant_id)
    (claim,) = _claim(_T0, _OFF)

    assert _mark(claim, _T0 + timedelta(seconds=10), _OFF) is False
    assert mark_external_effect_started(tenant_id, claim.id, claim.claim_token) is False

    row = _row(tenant_id, claim.id)
    assert (row.external_started_at, row.external_started_claim) == (None, None)
    assert row.next_attempt_at == _T0 + _LEASE  # the lease is not touched either


def test_the_current_claim_commits_its_marker_and_renews_the_lease(tenants: _Tenants) -> None:
    tenant_id, claim = _marked_claim(tenants)

    row = _row(tenant_id, claim.id)
    assert row.external_started_claim == claim.claim_token
    assert row.external_started_at == _T0 + timedelta(seconds=10)
    assert row.next_attempt_at == _T0 + timedelta(seconds=10) + _LEASE
    assert (row.status, row.claim_token, row.attempts) == (
        OUTBOX_STATUS_PENDING,
        claim.claim_token,
        1,
    )


def test_a_duplicated_execution_of_the_same_claim_cannot_mark_twice(tenants: _Tenants) -> None:
    """#195 4a.7 scenario 2: only one request may start per claim."""
    tenant_id, claim = _marked_claim(tenants)
    before = _row(tenant_id, claim.id)

    with pytest.raises(ExternalEffectNotStartedError):
        _mark(claim, _T0 + timedelta(seconds=20))

    after = _row(tenant_id, claim.id)
    assert (after.external_started_at, after.next_attempt_at) == (
        before.external_started_at,
        before.next_attempt_at,
    )


def test_no_marker_once_the_claims_own_lease_has_expired(tenants: _Tenants) -> None:
    """Scenario S9 of #200: `next_attempt_at > :at`."""
    tenant_id = tenants.new()
    _append(tenant_id)
    (claim,) = _claim(_T0)

    with pytest.raises(ExternalEffectNotStartedError):
        _mark(claim, _T0 + _LEASE)

    assert _row(tenant_id, claim.id).external_started_claim is None


def test_a_stale_worker_changes_nothing_after_the_reclaim(tenants: _Tenants) -> None:
    """#195 4a.7 scenario 4: the stale claim's marker write, complete, fail
    and release all match no row; the row stays the new claim's."""
    tenant_id = tenants.new()
    _append(tenant_id)
    (old,) = _claim(_T0)
    (new,) = _claim(_T0 + _LEASE)  # the old claim never marked: a plain retry
    snapshot = _row(tenant_id, new.id)

    with pytest.raises(ExternalEffectNotStartedError):
        _mark(old, _T0 + _LEASE + timedelta(seconds=1))
    assert complete_event(tenant_id, old.id, old.claim_token) is False
    assert fail_event(tenant_id, old.id, old.claim_token, "x", config=_ON) is None
    assert release_claim(tenant_id, old.id, old.claim_token, "x", config=_ON) is False

    row = _row(tenant_id, new.id)
    assert row.claim_token == new.claim_token
    assert (row.external_started_claim, row.external_started_at) == (None, None)
    assert (row.status, row.attempts, row.next_attempt_at) == (
        snapshot.status,
        snapshot.attempts,
        snapshot.next_attempt_at,
    )


def test_another_tenants_scope_can_neither_see_nor_mark_the_event(tenants: _Tenants) -> None:
    """Tenant isolation (#195 4a.8): the marker write runs under the
    caller's tenant scope, and RLS hides the other tenant's row."""
    owner = tenants.new()
    other = tenants.new()
    _append(owner)
    (claim,) = _claim(_T0)

    with pytest.raises(ExternalEffectNotStartedError):
        mark_external_effect_started(
            other, claim.id, claim.claim_token, config=_ON, now=_T0 + timedelta(seconds=10)
        )
    with tenant_session_scope(other) as session:
        assert (
            session.execute(
                select(OutboxEvent.id).where(OutboxEvent.external_started_claim.is_not(None))
            ).all()
            == []
        )
        assert session.execute(select(OutboxEvent).where(OutboxEvent.id == claim.id)).all() == []
    assert _row(owner, claim.id).external_started_claim is None

    _mark(claim, _T0 + timedelta(seconds=10))
    with tenant_session_scope(other) as session:
        cleared = session.execute(
            update(OutboxEvent)
            .where(OutboxEvent.id == claim.id)
            .values(external_started_at=None, external_started_claim=None)
        )
        assert getattr(cleared, "rowcount", None) == 0
    assert _row(owner, claim.id).external_started_claim == claim.claim_token


def test_half_a_marker_is_refused_by_the_pair_check(tenants: _Tenants) -> None:
    tenant_id, claim = _marked_claim(tenants)

    for column in ("external_started_at", "external_started_claim"):
        with pytest.raises(IntegrityError, match="ck_outbox_events_external_started_pair"):
            with tenant_session_scope(tenant_id) as session:
                session.execute(
                    update(OutboxEvent).where(OutboxEvent.id == claim.id).values({column: None})
                )
    assert _row(tenant_id, claim.id).external_started_claim == claim.claim_token


# --- The reclaim ------------------------------------------------------------------


def test_a_crash_after_the_marker_is_dead_lettered_not_retried(tenants: _Tenants) -> None:
    """#195 4a.7 scenarios 3 and 3b: the reclaim finds the expired claim's
    own marker. No consumer holds a safe-retry opt-in, so: dead letter,
    claim cleared, marker kept as evidence."""
    tenant_id, claim = _marked_claim(tenants)

    assert _claim(_T0 + timedelta(seconds=10) + _LEASE) == []

    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error == CRASH_AFTER_START_ERROR
    assert row.claim_token is None
    assert row.external_started_claim == claim.claim_token
    assert row.external_started_at == _T0 + timedelta(seconds=10)
    assert row.attempts == 1


def test_a_crash_after_the_marker_on_the_last_attempt_is_still_crash_after_start(
    tenants: _Tenants,
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)
    config = OutboxDispatchConfig(max_attempts=1, lease_seconds=300, external_effect_markers=True)
    (claim,) = _claim(_T0, config)
    _mark(claim, _T0 + timedelta(seconds=1), config)

    assert _claim(_T0 + timedelta(seconds=1) + _LEASE, config) == []

    row = _row(tenant_id, claim.id)
    assert (row.status, row.last_error) == (OUTBOX_STATUS_DEAD_LETTERED, CRASH_AFTER_START_ERROR)


def test_a_crash_before_the_marker_is_retried(tenants: _Tenants) -> None:
    """#195 4a.7 scenario 6: no marker, so nothing was sent; plain retry."""
    tenant_id = tenants.new()
    _append(tenant_id)
    (first,) = _claim(_T0)

    (second,) = _claim(_T0 + _LEASE)

    assert (second.id, second.attempts) == (first.id, 2)
    row = _row(tenant_id, first.id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.last_error is not None and row.last_error.startswith("LeaseExpired")


def test_an_older_claims_marker_next_to_a_claim_that_never_marked_is_a_plain_retry(
    tenants: _Tenants,
) -> None:
    """Scenario S10 of #200 / the ambiguity rule of #195 4a.7: ambiguous only
    if the marker is the expiring claim's. The old marker is a state the
    schema must allow (D1: no claim-matching check), set up here directly."""
    tenant_id = tenants.new()
    _append(tenant_id)
    (first,) = _claim(_T0)
    (second,) = _claim(_T0 + _LEASE)
    _admin(
        "UPDATE core.outbox_events SET external_started_at = :at, external_started_claim = :c "
        "WHERE id = :i",
        {"at": _T0 + timedelta(seconds=5), "c": first.claim_token, "i": first.id},
    )

    (third,) = _claim(_T0 + 2 * _LEASE)

    assert third.attempts == 3
    row = _row(tenant_id, first.id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.external_started_claim == first.claim_token  # untouched by the reclaim

    # Scenario 5: the current claim writes its own marker over the old one,
    # then completes: both columns cleared.
    assert _mark(third, _T0 + 2 * _LEASE + timedelta(seconds=1)) is True
    assert _row(tenant_id, first.id).external_started_claim == third.claim_token
    assert complete_event(tenant_id, third.id, third.claim_token) is True
    row = _row(tenant_id, first.id)
    assert row.status == OUTBOX_STATUS_PUBLISHED
    assert (row.external_started_at, row.external_started_claim, row.claim_token) == (
        None,
        None,
        None,
    )


# --- Outcomes ---------------------------------------------------------------------


def test_completion_clears_the_marker(tenants: _Tenants) -> None:
    tenant_id, claim = _marked_claim(tenants)

    assert complete_event(tenant_id, claim.id, claim.claim_token) is True

    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_PUBLISHED
    assert (row.external_started_at, row.external_started_claim) == (None, None)


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("HTTP 503 from the destination"),
        TimeoutError("deadline_expired"),
        RetryAfterEventError(60, "Throttled"),
    ],
    ids=["transient", "timeout", "retry_after"],
)
def test_a_marked_attempts_failure_is_dead_lettered_as_outcome_unknown(
    tenants: _Tenants, error: Exception
) -> None:
    """The exception rule (#195 4a.9): after the marker no error proves the
    request was not sent; never a retry, the marker kept."""
    tenant_id, claim = _marked_claim(tenants)
    retry_after = error.retry_after_seconds if isinstance(error, RetryAfterEventError) else None

    status = fail_event(
        tenant_id, claim.id, claim.claim_token, error, retry_after=retry_after, config=_ON
    )

    assert status == OUTBOX_STATUS_DEAD_LETTERED
    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error == f"OutcomeUnknown: {type(error).__name__}: {error}"
    assert row.claim_token is None
    assert row.external_started_claim == claim.claim_token
    assert row.attempts == 1  # attempts were left: the rule, not exhaustion, decided


def test_a_marked_attempts_permanent_failure_is_dead_lettered_with_its_error(
    tenants: _Tenants,
) -> None:
    tenant_id, claim = _marked_claim(tenants)

    status = fail_event(
        tenant_id,
        claim.id,
        claim.claim_token,
        PermanentEventError("HTTP 410"),
        terminal=True,
        config=_ON,
    )

    assert status == OUTBOX_STATUS_DEAD_LETTERED
    row = _row(tenant_id, claim.id)
    assert row.last_error == "PermanentEventError: HTTP 410"
    assert row.external_started_claim == claim.claim_token


def test_an_unmarked_failure_is_retried_as_before_and_clears_an_older_marker(
    tenants: _Tenants,
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)
    (first,) = _claim(_T0)
    (second,) = _claim(_T0 + _LEASE)
    _admin(
        "UPDATE core.outbox_events SET external_started_at = :at, external_started_claim = :c "
        "WHERE id = :i",
        {"at": _T0 + timedelta(seconds=5), "c": first.claim_token, "i": first.id},
    )

    status = fail_event(tenant_id, second.id, second.claim_token, "Boom", config=_ON)

    assert status == OUTBOX_STATUS_PENDING
    row = _row(tenant_id, second.id)
    assert row.claim_token is None and row.last_error == "Boom"
    assert (row.external_started_at, row.external_started_claim) == (None, None)


def test_a_released_claim_clears_the_marker(tenants: _Tenants) -> None:
    """`release_claim()` gives back a claim that never ran; it clears both
    columns like every non-dead-letter outcome (#195 4a.9). Set up with
    the pair written as the marker write writes it."""
    tenant_id, claim = _marked_claim(tenants)

    assert release_claim(tenant_id, claim.id, claim.claim_token, "QueueDown", config=_ON)

    row = _row(tenant_id, claim.id)
    assert (row.external_started_at, row.external_started_claim, row.claim_token) == (
        None,
        None,
        None,
    )


# --- Races on separate connections ------------------------------------------------


def test_a_stale_marker_write_racing_an_uncommitted_reclaim_writes_nothing(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#195 4a.7 scenario 7: the reclaim holds the row lock, uncommitted; the
    stale worker's marker write (its clock still inside its lease, so only
    `claim_token = :claim` can stop it) waits on the row, and once the
    reclaim commits PostgreSQL re-checks the `WHERE`: 0 rows."""
    tenant_id = tenants.new()
    _append(tenant_id)
    (old,) = _claim(_T0)
    paused, release = threading.Event(), threading.Event()

    def _hold(session: object) -> None:
        if threading.current_thread().name == "reclaimer":
            paused.set()
            assert release.wait(timeout=30), "the reclaim was never released"

    monkeypatch.setattr(dispatch, "_claim_hook", _hold)
    outcome: dict[str, Any] = {}

    def _reclaim() -> None:
        outcome["claims"] = _claim(_T0 + _LEASE)

    def _stale_mark() -> None:
        try:
            outcome["marked"] = _mark(old, _T0 + _LEASE - timedelta(seconds=1))
        except ExternalEffectNotStartedError as exc:
            outcome["marked"] = exc

    reclaimer = threading.Thread(target=_reclaim, name="reclaimer")
    reclaimer.start()
    stale = threading.Thread(target=_stale_mark, name="stale")
    try:
        assert paused.wait(timeout=30)
        stale.start()
        _wait_for_lock_wait(tenant_id)
        assert stale.is_alive()  # waiting on the row, not finished
    finally:
        release.set()
        reclaimer.join(timeout=30)
        stale.join(timeout=30)

    (new,) = outcome["claims"]
    assert isinstance(outcome["marked"], ExternalEffectNotStartedError)
    row = _row(tenant_id, old.id)
    assert row.claim_token == new.claim_token
    assert (row.external_started_at, row.external_started_claim) == (None, None)


def test_a_reclaim_racing_an_uncommitted_marker_write_skips_the_row(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#195 4a.7 scenario 8: the marker write holds the row, uncommitted;
    a reclaim at the old lease expiry skips it (SKIP LOCKED, no wait). The
    committed marker renewed the lease, so the event is not due then; after
    the new expiry it is ambiguous and dead-lettered."""
    tenant_id = tenants.new()
    _append(tenant_id)
    (claim,) = _claim(_T0)
    paused, release = threading.Event(), threading.Event()
    real_scope = dispatch.tenant_session_scope

    @contextmanager
    def _paused_scope(scope_tenant: uuid.UUID) -> Iterator[Any]:
        with real_scope(scope_tenant) as session:
            yield session
            if threading.current_thread().name == "marker":
                paused.set()
                assert release.wait(timeout=30), "the marker write was never released"

    monkeypatch.setattr(dispatch, "tenant_session_scope", _paused_scope)
    outcome: dict[str, Any] = {}
    marked_at = _T0 + _LEASE - timedelta(seconds=1)

    def _write() -> None:
        outcome["marked"] = _mark(claim, marked_at)

    marker = threading.Thread(target=_write, name="marker")
    marker.start()
    try:
        assert paused.wait(timeout=30)
        assert _claim(_T0 + _LEASE) == []  # returns while the row is locked
    finally:
        release.set()
        marker.join(timeout=30)

    assert outcome["marked"] is True
    assert _claim(_T0 + _LEASE) == []  # not due: the marker renewed the lease
    assert _claim(marked_at + _LEASE) == []
    row = _row(tenant_id, claim.id)
    assert (row.status, row.last_error) == (OUTBOX_STATUS_DEAD_LETTERED, CRASH_AFTER_START_ERROR)


def _wait_for_lock_wait(tenant_id: uuid.UUID, timeout: float = 10.0) -> None:
    """Until some backend waits on a row lock (`Lock/transactionid` or
    `Lock/tuple`) -- the stale marker write queued behind the reclaim."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waiting = _admin(
            "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
            "AND query LIKE 'UPDATE core.outbox_events SET %external_started_claim%'",
            {},
        )
        if waiting and waiting[0][0] >= 1:
            return
        time.sleep(0.05)
    raise AssertionError(f"the stale marker write of {tenant_id} never waited on the row")


# --- Through the dispatcher -------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def markers_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("OUTBOX_EXTERNAL_EFFECT_MARKERS", "true")
    # The smallest lease the setting accepts (`MIN_LEASE_SECONDS`, #189).
    monkeypatch.setenv("OUTBOX_LEASE_SECONDS", "360")
    get_outbox_dispatch_config.cache_clear()
    yield
    get_outbox_dispatch_config.cache_clear()


def _run_claim(tenant_id: uuid.UUID) -> tuple[dispatch.ClaimedEvent, TenantJobPayload]:
    (claim,) = claim_due_events(now=datetime.now(UTC) + timedelta(seconds=1), rng=lambda: 0.0)
    payload = TenantJobPayload(
        tenant_id=str(tenant_id),
        data={"outbox_event_id": str(claim.id), "claim_token": str(claim.claim_token)},
    )
    return claim, payload


def _probe(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    monkeypatch.setattr(outbox_dispatcher, "outbox_event_handlers", lambda: {_PROBE: handler})


@pytest.mark.anyio
async def test_with_markers_off_a_consumer_failure_is_retried_as_before(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            raise RuntimeError("HTTP 503")

    _probe(monkeypatch, _consumer)
    claim, payload = _run_claim(tenant_id)
    await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), payload)

    row = _row(tenant_id, claim.id)
    assert (row.status, row.claim_token, row.last_error) == (
        OUTBOX_STATUS_PENDING,
        None,
        "RuntimeError: HTTP 503",
    )
    assert row.external_started_claim is None


@pytest.mark.anyio
async def test_with_markers_on_the_marker_is_committed_before_the_send_and_cleared_on_success(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, markers_on: None
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)
    seen: dict[str, Any] = {}

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            # Read from another connection: the marker is already committed.
            (stored,) = _admin(
                "SELECT external_started_claim FROM core.outbox_events WHERE id = :i",
                {"i": context.event_id},
            )
            seen["claim"] = stored[0]

    _probe(monkeypatch, _consumer)
    claim, payload = _run_claim(tenant_id)
    await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), payload)

    assert seen["claim"] == claim.claim_token
    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_PUBLISHED
    assert (row.external_started_at, row.external_started_claim) == (None, None)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (RuntimeError("HTTP 503"), "OutcomeUnknown: RuntimeError: HTTP 503"),
        (RetryAfterEventError(30, "Throttled"), "OutcomeUnknown: RetryAfterEventError: Throttled"),
        (PermanentEventError("HTTP 410"), "PermanentEventError: HTTP 410"),
    ],
    ids=["transient", "retry_after", "permanent"],
)
async def test_with_markers_on_a_failure_after_the_marker_is_dead_lettered(
    tenants: _Tenants,
    monkeypatch: pytest.MonkeyPatch,
    markers_on: None,
    error: Exception,
    expected: str,
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            raise error

    _probe(monkeypatch, _consumer)
    claim, payload = _run_claim(tenant_id)
    await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), payload)

    row = _row(tenant_id, claim.id)
    assert (row.status, row.last_error) == (OUTBOX_STATUS_DEAD_LETTERED, expected)
    assert row.external_started_claim == claim.claim_token


@pytest.mark.anyio
async def test_with_markers_on_a_failure_before_the_marker_keeps_todays_retry(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, markers_on: None
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        raise RuntimeError("subscription lookup failed")

    _probe(monkeypatch, _consumer)
    claim, payload = _run_claim(tenant_id)
    await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), payload)

    row = _row(tenant_id, claim.id)
    assert (row.status, row.claim_token) == (OUTBOX_STATUS_PENDING, None)
    assert row.external_started_claim is None


@pytest.mark.anyio
@pytest.mark.parametrize("swallow", [False, True], ids=["propagated", "swallowed"])
async def test_a_duplicated_execution_of_the_claim_sends_nothing_and_records_nothing(
    tenants: _Tenants,
    monkeypatch: pytest.MonkeyPatch,
    markers_on: None,
    swallow: bool,
) -> None:
    """The same job runs twice with the same claim (a queue redelivery):
    the second execution's marker write is refused, it sends nothing and
    records no outcome -- even when its consumer swallows the refusal --
    and the first execution publishes the event."""
    tenant_id = tenants.new()
    _append(tenant_id)
    sends: list[str] = []
    entered: list[int] = []
    after_duplicate: list[str] = []

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        entered.append(1)
        nested = len(entered) > 1
        try:
            with context.external_effect():
                sends.append("nested" if nested else "first")
                if not nested:
                    await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), job)
                    # Read after the duplicate returned; asserted below, outside
                    # the consumer (an assertion error here would be recorded
                    # as the consumer's failure, not fail the test).
                    after_duplicate.append(_row(tenant_id, claim.id).status)
        except ExternalEffectNotStartedError:
            if not swallow:
                raise

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), job)

    assert sends == ["first"]
    assert after_duplicate == [OUTBOX_STATUS_PENDING]  # the duplicate recorded nothing
    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_PUBLISHED
    assert row.external_started_claim is None


@pytest.mark.anyio
@pytest.mark.parametrize("swallow", [False, True], ids=["propagated", "caught"])
async def test_a_second_external_effect_in_one_execution_sends_nothing_more_and_keeps_the_outcome(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, markers_on: None, swallow: bool
) -> None:
    """A consumer that enters `external_effect()` twice in one execution: the
    second entry raises `ExternalEffectAlreadyStartedError` before its block
    runs (no second send) and is not a refusal, so the execution's outcome
    is recorded: propagated, the marked attempt is dead-lettered
    `OutcomeUnknown:` at once (not left to a later `CrashAfterStart:`);
    caught and returned normally, the event is published."""
    tenant_id = tenants.new()
    _append(tenant_id)
    sends: list[str] = []

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            sends.append("first")
        try:
            with context.external_effect():
                sends.append("second")
        except ExternalEffectAlreadyStartedError:
            if not swallow:
                raise

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), job)

    assert sends == ["first"]
    row = _row(tenant_id, claim.id)
    if swallow:
        assert row.status == OUTBOX_STATUS_PUBLISHED
        assert row.external_started_claim is None
    else:
        assert row.status == OUTBOX_STATUS_DEAD_LETTERED
        assert row.last_error is not None
        assert row.last_error.startswith("OutcomeUnknown: ExternalEffectAlreadyStartedError")
        assert row.external_started_claim == claim.claim_token


@pytest.mark.anyio
async def test_with_markers_off_a_second_external_effect_behaves_as_before(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)
    sends: list[str] = []

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        for name in ("first", "second"):
            with context.external_effect():
                sends.append(name)

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), job)

    assert sends == ["first", "second"]
    assert _row(tenant_id, claim.id).status == OUTBOX_STATUS_PUBLISHED
