"""Retry after a started marker against real PostgreSQL, as the application
role (`docs/architecture/OUTBOX-RETRY-AFTER-MARKER-DESIGN.md`, section 13).

- branch A, `record_confirmed_not_sent()`: an attested `ConfirmedNotSentError`
  retries and clears both marker columns together, the attempt counted; a
  non-qualifying exception (plain, mixed group, not the block's own, none)
  is dead-lettered `OutcomeUnknown:` with the marker kept; `fail_event()`
  still never retries a marked attempt;
- branch B, `record_ambiguous_outcome()`: `at_least_once` after a marker
  retries; `retry_within` and no policy stay dead-lettered;
- the dispatcher end to end: the exception must be the one that left the
  `external_effect()` block, the consumer deadline wins, markers off leaves
  the new branches unreachable;
- the database clock, tenant isolation (RLS), the deadline tag, and races
  between an outcome and a reclaim on separate connections.

Times are explicit (`now=`) except where the database clock is the point.
Every row a test creates is removed afterwards. Marked `integration`.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

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
    AmbiguousOutcomeError,
    ConfirmedNotSentError,
    OutboxConfigurationError,
    OutboxDispatchConfig,
    OutboxEvent,
    PermanentEventError,
    RetryAfterEventError,
    append_event,
    begin_event_execution,
    claim_due_events,
    fail_event,
    get_outbox_dispatch_config,
    mark_external_effect_started,
)
from saas_os.core.outbox.dispatch import record_ambiguous_outcome, record_confirmed_not_sent
from saas_os.core.tenancy import create_tenant, list_open_tenant_ids
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload

pytestmark = pytest.mark.integration

_ON = OutboxDispatchConfig(
    max_attempts=3,
    retry_base_seconds=60,
    retry_jitter_ratio=0,
    lease_seconds=300,
    external_effect_markers=True,
)
_ONE_ATTEMPT = OutboxDispatchConfig(
    max_attempts=1, retry_jitter_ratio=0, lease_seconds=300, external_effect_markers=True
)
_T0 = datetime(2030, 1, 1, tzinfo=UTC)  # after every row's creation time
_LEASE = _ON.lease
_PROBE = "probe.external_effect"
_BACKOFF = timedelta(seconds=60)
_CANARY = "https://canary.example/secret-path"


class _NotSent(ConfirmedNotSentError):
    pass


class _NotSentRetryAfter(ConfirmedNotSentError, RetryAfterEventError):
    def __init__(self) -> None:
        RetryAfterEventError.__init__(self, 120, "Throttled")


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
        tenant_id = create_tenant(f"outbox-rt18-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
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
            event_type=_PROBE,
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


def _marked_claim(
    tenants: _Tenants, config: OutboxDispatchConfig = _ON
) -> tuple[uuid.UUID, dispatch.ClaimedEvent]:
    tenant_id = tenants.new()
    _append(tenant_id)
    (claim,) = _claim(_T0, config)
    assert _mark(claim, _T0 + timedelta(seconds=10), config) is True
    return tenant_id, claim


def _attest(
    claim: dispatch.ClaimedEvent,
    error: BaseException,
    block: BaseException | None,
    at: datetime,
    config: OutboxDispatchConfig = _ON,
    **kwargs: Any,
) -> str | None:
    return record_confirmed_not_sent(
        claim.tenant_id,
        claim.id,
        claim.claim_token,
        error,
        block_exception=block,
        config=config,
        now=at,
        rng=lambda: 0.0,
        **kwargs,
    )


def _ambiguous(
    claim: dispatch.ClaimedEvent,
    error: AmbiguousOutcomeError,
    at: datetime,
    config: OutboxDispatchConfig = _ON,
) -> str | None:
    return record_ambiguous_outcome(
        claim.tenant_id,
        claim.id,
        claim.claim_token,
        error,
        config=config,
        now=at,
        rng=lambda: 0.0,
    )


_AT = _T0 + timedelta(seconds=20)


# --- Branch A: an attested ConfirmedNotSentError -----------------------------------


def test_an_attested_not_sent_retries_and_clears_both_markers_together(
    tenants: _Tenants,
) -> None:
    tenant_id, claim = _marked_claim(tenants)
    error = _NotSent("connect_failed")

    assert _attest(claim, error, error, _AT) == OUTBOX_STATUS_PENDING

    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.claim_token is None
    assert (row.external_started_at, row.external_started_claim) == (None, None)
    assert row.attempts == 1  # counted, no refund (D-2)
    assert row.next_attempt_at == _AT + _BACKOFF
    assert row.last_error == "_NotSent: connect_failed"


def test_the_retry_runs_once_with_a_new_claim_and_a_new_marker(tenants: _Tenants) -> None:
    tenant_id, claim = _marked_claim(tenants)
    error = _NotSent("connect_failed")
    _attest(claim, error, error, _AT)

    assert _claim(_AT + _BACKOFF - timedelta(seconds=1)) == []  # not yet due
    (second,) = _claim(_AT + _BACKOFF)
    assert (second.id, second.attempts) == (claim.id, 2)
    assert second.claim_token != claim.claim_token
    assert _mark(second, _AT + _BACKOFF + timedelta(seconds=1)) is True
    row = _row(tenant_id, claim.id)
    assert row.external_started_claim == second.claim_token
    assert (
        dispatch.complete_event(tenant_id, second.id, second.claim_token, now=_AT + 2 * _BACKOFF)
        is True
    )
    assert _row(tenant_id, claim.id).status == OUTBOX_STATUS_PUBLISHED
    assert _claim(_AT + 10 * _BACKOFF) == []  # nothing is left to run again


def test_an_attested_not_sent_on_the_last_attempt_is_dead_lettered_with_the_marker_kept(
    tenants: _Tenants,
) -> None:
    tenant_id, claim = _marked_claim(tenants, _ONE_ATTEMPT)
    error = _NotSent("connect_failed")

    assert _attest(claim, error, error, _AT, _ONE_ATTEMPT) == OUTBOX_STATUS_DEAD_LETTERED

    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error == "_NotSent: connect_failed"  # the attested error (D-9)
    assert row.claim_token is None
    assert row.external_started_claim == claim.claim_token  # a dead letter keeps it
    assert row.attempts == 1


def test_a_group_of_attested_leaves_retries_with_no_hint(tenants: _Tenants) -> None:
    tenant_id, claim = _marked_claim(tenants)
    group = ExceptionGroup("g", [_NotSentRetryAfter(), _NotSent("b")])

    assert _attest(claim, group, group, _AT) == OUTBOX_STATUS_PENDING

    assert _row(tenant_id, claim.id).next_attempt_at == _AT + _BACKOFF


def test_a_class_that_is_both_attested_and_a_retry_hint_keeps_both_meanings(
    tenants: _Tenants,
) -> None:
    tenant_id, claim = _marked_claim(tenants)
    error = _NotSentRetryAfter()

    assert _attest(claim, error, error, _AT, retry_after=error.retry_after_seconds) == "pending"

    row = _row(tenant_id, claim.id)
    assert row.next_attempt_at == _AT + timedelta(seconds=120)  # max(backoff, hint)
    assert (row.external_started_at, row.external_started_claim) == (None, None)


@pytest.mark.parametrize(
    "case",
    ["plain", "mixed_group", "not_the_blocks", "no_block", "timeout", "ambiguous"],
)
def test_a_non_qualifying_exception_is_dead_lettered_and_keeps_the_marker(
    tenants: _Tenants, case: str
) -> None:
    """The verification is in the locked-row function, not in its caller: a
    caller that hands over anything but an attestation changes nothing but
    the outcome, and the outcome is the ambiguous one."""
    tenant_id, claim = _marked_claim(tenants)
    confirmed = _NotSent("refused")
    error: BaseException
    block: BaseException | None
    if case == "plain":
        error = block = RuntimeError("HTTP 503")
    elif case == "mixed_group":
        error = block = ExceptionGroup("g", [confirmed, RuntimeError("x")])
    elif case == "not_the_blocks":
        error, block = _NotSent("fresh"), RuntimeError("inside")
    elif case == "no_block":
        error, block = confirmed, None
    elif case == "timeout":
        error = block = ExceptionGroup("g", [confirmed, TimeoutError("t")])
    else:
        error = block = ExceptionGroup(
            "g", [confirmed, AmbiguousOutcomeError("read_timeout", phase="read")]
        )

    assert _attest(claim, error, block, _AT) == OUTBOX_STATUS_DEAD_LETTERED

    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error is not None and row.last_error.startswith("OutcomeUnknown: ")
    assert row.external_started_claim == claim.claim_token
    assert row.claim_token is None
    assert row.attempts == 1  # attempts were left: the rule decided


def test_a_permanent_error_is_terminal_and_keeps_the_marker(tenants: _Tenants) -> None:
    tenant_id, claim = _marked_claim(tenants)
    error = PermanentEventError("HTTP 410")

    assert _attest(claim, error, error, _AT) == OUTBOX_STATUS_DEAD_LETTERED

    row = _row(tenant_id, claim.id)
    assert row.last_error == "PermanentEventError: HTTP 410"
    assert row.external_started_claim == claim.claim_token


def test_an_unmarked_attempt_takes_the_ordinary_retry(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)
    (claim,) = _claim(_T0)  # never marked
    error = _NotSent("connect_failed")

    assert _attest(claim, error, None, _AT) == OUTBOX_STATUS_PENDING

    row = _row(tenant_id, claim.id)
    assert (row.status, row.claim_token, row.attempts) == (OUTBOX_STATUS_PENDING, None, 1)
    assert row.next_attempt_at == _AT + _BACKOFF
    assert (row.external_started_at, row.external_started_claim) == (None, None)


def test_fail_event_still_dead_letters_a_marked_attempt_whatever_it_is_given(
    tenants: _Tenants,
) -> None:
    tenant_id, claim = _marked_claim(tenants)
    error = _NotSent("connect_failed")

    status = fail_event(tenant_id, claim.id, claim.claim_token, error, config=_ON, now=_AT)

    assert status == OUTBOX_STATUS_DEAD_LETTERED
    row = _row(tenant_id, claim.id)
    assert row.last_error == "OutcomeUnknown: _NotSent: connect_failed"
    assert row.external_started_claim == claim.claim_token


def test_the_texts_carry_no_url_and_no_message_body(tenants: _Tenants) -> None:
    tenant_id, claim = _marked_claim(tenants)
    error = _NotSent("pool_timeout")

    _attest(claim, error, error, _AT)

    assert _CANARY not in (_row(tenant_id, claim.id).last_error or "")


# --- Branch B: at_least_once after a marker ----------------------------------------


def test_an_at_least_once_outcome_after_a_marker_retries_and_clears_the_marker(
    tenants: _Tenants,
) -> None:
    tenant_id, claim = _marked_claim(tenants)

    status = _ambiguous(
        claim, AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True), _AT
    )

    assert status == OUTBOX_STATUS_PENDING
    row = _row(tenant_id, claim.id)
    assert row.claim_token is None
    assert (row.external_started_at, row.external_started_claim) == (None, None)
    assert row.attempts == 1
    assert row.next_attempt_at == _AT + _BACKOFF
    assert row.last_error == (
        "OutcomeUnknown: read_timeout (read); retried: at-least-once delivery on a stable event id"
    )


def test_an_at_least_once_outcome_on_the_last_attempt_is_dead_lettered_marker_kept(
    tenants: _Tenants,
) -> None:
    tenant_id, claim = _marked_claim(tenants, _ONE_ATTEMPT)

    status = _ambiguous(
        claim,
        AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True),
        _AT,
        _ONE_ATTEMPT,
    )

    assert status == OUTBOX_STATUS_DEAD_LETTERED
    row = _row(tenant_id, claim.id)
    assert row.external_started_claim == claim.claim_token


@pytest.mark.parametrize("policy", ["retry_within", "none"])
def test_retry_within_and_no_policy_stay_dead_lettered_after_a_marker(
    tenants: _Tenants, policy: str
) -> None:
    tenant_id, claim = _marked_claim(tenants)
    error = (
        AmbiguousOutcomeError("read_timeout", phase="read", retry_within=timedelta(days=36500))
        if policy == "retry_within"
        else AmbiguousOutcomeError("read_timeout", phase="read")
    )

    assert _ambiguous(claim, error, _AT) == OUTBOX_STATUS_DEAD_LETTERED

    row = _row(tenant_id, claim.id)
    assert row.last_error is not None
    assert row.last_error.startswith(
        "OutcomeUnknown: read_timeout (read); not retried automatically"
    )
    assert row.external_started_claim == claim.claim_token
    assert row.claim_token is None


# --- Tenant isolation ---------------------------------------------------------------


def test_another_tenants_scope_can_not_change_the_event(tenants: _Tenants) -> None:
    owner_tenant, claim = _marked_claim(tenants)
    other = tenants.new()
    error = _NotSent("connect_failed")
    before = _row(owner_tenant, claim.id)

    status = record_confirmed_not_sent(
        other,
        claim.id,
        claim.claim_token,
        error,
        block_exception=error,
        config=_ON,
        now=_AT,
    )
    ambiguous = record_ambiguous_outcome(
        other,
        claim.id,
        claim.claim_token,
        AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True),
        config=_ON,
        now=_AT,
    )

    assert (status, ambiguous) == (None, None)
    after = _row(owner_tenant, claim.id)
    assert (after.status, after.claim_token, after.external_started_claim) == (
        before.status,
        before.claim_token,
        before.external_started_claim,
    )
    assert after.next_attempt_at == before.next_attempt_at


# --- The deadline tag ---------------------------------------------------------------


def test_a_deadline_tag_survives_an_attested_retry_and_ends_the_next_run(
    tenants: _Tenants,
) -> None:
    tenant_id, claim = _marked_claim(tenants)
    tag = "[idempotent-retry-until 2030-01-01T01:00:00+00:00]"
    _admin(
        "UPDATE core.outbox_events SET last_error = :e WHERE id = :i",
        {"e": f"OutcomeUnknown: earlier {tag}", "i": claim.id},
    )
    error = _NotSent("connect_failed")

    assert _attest(claim, error, error, _AT) == OUTBOX_STATUS_PENDING

    row = _row(tenant_id, claim.id)
    assert row.last_error is not None and row.last_error.endswith(tag)
    # The retry starts after the deadline: begin_event_execution() dead-letters it.
    (second,) = _claim(_T0 + timedelta(hours=2))
    assert second.attempts == 2
    assert (
        begin_event_execution(
            tenant_id, claim.id, second.claim_token, config=_ON, now=_T0 + timedelta(hours=2)
        )
        is None
    )
    after = _row(tenant_id, claim.id)
    assert after.status == OUTBOX_STATUS_DEAD_LETTERED
    assert after.last_error is not None
    assert after.last_error.startswith("OutcomeUnknown: the idempotency window closed")


# --- The database clock --------------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def markers_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("OUTBOX_EXTERNAL_EFFECT_MARKERS", "true")
    monkeypatch.setenv("OUTBOX_LEASE_SECONDS", "360")  # the smallest accepted
    monkeypatch.setenv("OUTBOX_RETRY_JITTER_RATIO", "0")
    monkeypatch.setenv("OUTBOX_RETRY_BASE_SECONDS", "30")
    get_outbox_dispatch_config.cache_clear()
    yield
    get_outbox_dispatch_config.cache_clear()


def _run_claim(
    tenant_id: uuid.UUID, hours_ahead: float = 0
) -> tuple[dispatch.ClaimedEvent, TenantJobPayload]:
    (claim,) = claim_due_events(
        now=datetime.now(UTC) + timedelta(hours=hours_ahead, seconds=1), rng=lambda: 0.0
    )
    payload = TenantJobPayload(
        tenant_id=str(tenant_id),
        data={"outbox_event_id": str(claim.id), "claim_token": str(claim.claim_token)},
    )
    return claim, payload


def _probe(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    monkeypatch.setattr(outbox_dispatcher, "outbox_event_handlers", lambda: {_PROBE: handler})


async def _execute(tenant_id: uuid.UUID, payload: TenantJobPayload) -> None:
    await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), payload)


@pytest.mark.anyio
async def test_the_retry_is_scheduled_on_the_database_clock(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, markers_on: None
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            raise _NotSent("connect_failed")

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    (before,) = _admin("SELECT clock_timestamp()", {})
    await _execute(tenant_id, job)
    (after,) = _admin("SELECT clock_timestamp()", {})

    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_PENDING
    delay = timedelta(seconds=30)
    assert before[0] + delay <= row.next_attempt_at <= after[0] + delay


# --- Through the dispatcher ----------------------------------------------------------


@pytest.mark.anyio
async def test_an_attested_failure_retries_and_the_retry_completes_once(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, markers_on: None
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)
    sends: list[str] = []

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            if not sends:
                sends.append("refused")
                raise _NotSent("connect_failed")
            sends.append("delivered")

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _execute(tenant_id, job)

    row = _row(tenant_id, claim.id)
    assert (row.status, row.claim_token, row.attempts) == (OUTBOX_STATUS_PENDING, None, 1)
    assert (row.external_started_at, row.external_started_claim) == (None, None)

    second, job2 = _run_claim(tenant_id, hours_ahead=1)
    await _execute(tenant_id, job2)

    assert sends == ["refused", "delivered"]
    row = _row(tenant_id, claim.id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_PUBLISHED, 2)
    assert second.claim_token != claim.claim_token
    assert (row.external_started_at, row.external_started_claim) == (None, None)


@pytest.mark.anyio
async def test_a_group_raised_out_of_the_block_by_the_consumer_is_an_attestation(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, markers_on: None
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            raise ExceptionGroup("g", [_NotSent("a"), _NotSent("b")])

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _execute(tenant_id, job)

    row = _row(tenant_id, claim.id)
    assert (row.status, row.claim_token, row.external_started_claim) == (
        OUTBOX_STATUS_PENDING,
        None,
        None,
    )


@pytest.mark.anyio
@pytest.mark.parametrize("shape", ["after_normal_exit", "caught_then_fresh", "wrapped"])
async def test_an_attestation_that_did_not_leave_the_block_is_not_credited(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, markers_on: None, shape: str
) -> None:
    """D-1(b): raised after the block exited normally, raised afresh after
    the consumer caught the block's failure, or a different error wrapped
    around it: the marker bracketed a request these say nothing about."""
    tenant_id = tenants.new()
    _append(tenant_id)

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        if shape == "after_normal_exit":
            with context.external_effect():
                pass
            raise _NotSent("after")
        try:
            with context.external_effect():
                raise RuntimeError("HTTP 503")
        except RuntimeError as inside:
            if shape == "caught_then_fresh":
                raise _NotSent("fresh") from None
            raise _NotSent("wrapped") from inside

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _execute(tenant_id, job)

    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error is not None and row.last_error.startswith("OutcomeUnknown: _NotSent")
    assert row.external_started_claim == claim.claim_token


@pytest.mark.anyio
async def test_a_mixed_group_out_of_the_block_is_dead_lettered(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, markers_on: None
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            raise ExceptionGroup("g", [_NotSent("a"), RuntimeError("b")])

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _execute(tenant_id, job)

    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.external_started_claim == claim.claim_token


@pytest.mark.anyio
async def test_the_consumer_deadline_wins_over_an_attestation(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, markers_on: None
) -> None:
    """D-3: a consumer that ran out of time is dead-lettered
    `ConsumerTimedOut:` whatever it raised, an attestation included."""
    tenant_id = tenants.new()
    _append(tenant_id)
    monkeypatch.setattr(outbox_dispatcher, "OUTBOX_CONSUMER_TIMEOUT_SECONDS", 0.3)

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                raise _NotSent("late attestation") from None

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _execute(tenant_id, job)

    row = _row(tenant_id, claim.id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error is not None and row.last_error.startswith("ConsumerTimedOut:")
    assert row.external_started_claim == claim.claim_token


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("raised", "expected_status"),
    [
        (AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True), "pending"),
        (
            ExceptionGroup(
                "g",
                [
                    AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True),
                    AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True),
                ],
            ),
            "pending",
        ),
        (
            ExceptionGroup(
                "g",
                [
                    AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True),
                    AmbiguousOutcomeError("read_timeout", phase="read"),
                ],
            ),
            "dead_lettered",
        ),
        (
            ExceptionGroup(
                "g",
                [
                    AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True),
                    RuntimeError("other"),
                ],
            ),
            "dead_lettered",
        ),
        (
            AmbiguousOutcomeError("read_timeout", phase="read", retry_within=timedelta(days=9999)),
            "dead_lettered",
        ),
        (AmbiguousOutcomeError("read_timeout", phase="read"), "dead_lettered"),
        (TimeoutError("t"), "dead_lettered"),
        (RetryAfterEventError(30, "Throttled"), "dead_lettered"),
        (RuntimeError("HTTP 503"), "dead_lettered"),
    ],
    ids=[
        "at_least_once",
        "group_of_declarations",
        "group_with_a_non_declaring_member",
        "group_with_a_plain_member",
        "retry_within",
        "no_policy",
        "bare_timeout",
        "retry_after_alone",
        "plain",
    ],
)
async def test_through_the_dispatcher_only_what_the_consumer_declared_is_retried(
    tenants: _Tenants,
    monkeypatch: pytest.MonkeyPatch,
    markers_on: None,
    raised: Exception,
    expected_status: str,
) -> None:
    tenant_id = tenants.new()
    _append(tenant_id)

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            raise raised

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _execute(tenant_id, job)

    row = _row(tenant_id, claim.id)
    assert row.status == expected_status
    if expected_status == "pending":
        assert (row.external_started_at, row.external_started_claim, row.claim_token) == (
            None,
            None,
            None,
        )
    else:
        assert row.last_error is not None and row.last_error.startswith("OutcomeUnknown: ")
        assert row.external_started_claim == claim.claim_token


@pytest.mark.anyio
async def test_attempts_run_out_on_repeated_attestations(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, markers_on: None
) -> None:
    """D-2, D-5: the attempt is never refunded, so a consumer that always
    marks and always attests is dead-lettered at `OUTBOX_MAX_ATTEMPTS`."""
    monkeypatch.setenv("OUTBOX_MAX_ATTEMPTS", "2")
    get_outbox_dispatch_config.cache_clear()
    tenant_id = tenants.new()
    _append(tenant_id)
    runs: list[int] = []

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            runs.append(1)
            raise _NotSent("connect_failed")

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _execute(tenant_id, job)
    assert _row(tenant_id, claim.id).status == OUTBOX_STATUS_PENDING
    _, job2 = _run_claim(tenant_id, hours_ahead=1)
    await _execute(tenant_id, job2)

    row = _row(tenant_id, claim.id)
    assert runs == [1, 1]
    assert (row.status, row.attempts) == (OUTBOX_STATUS_DEAD_LETTERED, 2)
    assert row.external_started_claim is not None  # kept
    assert row.last_error == "_NotSent: connect_failed"


# --- Markers off: the new branches are unreachable ------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["confirmed", "at_least_once"])
async def test_with_markers_off_nothing_changes_and_the_new_branches_are_unreachable(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    assert get_outbox_dispatch_config().external_effect_markers is False
    tenant_id = tenants.new()
    _append(tenant_id)

    def _unreachable(*args: object, **kwargs: object) -> None:
        raise AssertionError("record_confirmed_not_sent() was reached with markers off")

    monkeypatch.setattr(outbox_dispatcher, "record_confirmed_not_sent", _unreachable)

    async def _consumer(context: TenantJobContext, payload: TenantJobPayload) -> None:
        with context.external_effect():
            if kind == "confirmed":
                raise _NotSent("connect_failed")
            raise AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True)

    _probe(monkeypatch, _consumer)
    claim, job = _run_claim(tenant_id)
    await _execute(tenant_id, job)

    row = _row(tenant_id, claim.id)
    assert (row.status, row.claim_token, row.attempts) == (OUTBOX_STATUS_PENDING, None, 1)
    assert (row.external_started_at, row.external_started_claim) == (None, None)
    assert row.last_error is not None
    assert row.last_error.startswith("_NotSent" if kind == "confirmed" else "OutcomeUnknown")


def test_the_lease_floor_is_still_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """The marked attempt's lease must outlast the consumer deadline plus the
    outcome write's retries (design 4.1, lease constraint)."""
    monkeypatch.setenv("OUTBOX_LEASE_SECONDS", "359")
    get_outbox_dispatch_config.cache_clear()
    with pytest.raises(OutboxConfigurationError, match="OUTBOX_LEASE_SECONDS"):
        get_outbox_dispatch_config()


# --- Races on separate connections ---------------------------------------------------


def _wait_for_lock_wait(timeout: float = 10.0) -> None:
    """Until some backend waits on a row lock."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waiting = _admin(
            "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
            "AND query LIKE '%core.outbox_events%'",
            {},
        )
        if waiting and waiting[0][0] >= 1:
            return
        time.sleep(0.05)
    raise AssertionError("no statement ever waited on the outbox row")


def test_an_attestation_holding_the_row_makes_a_reclaim_skip_it_then_retry_cleanly(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The outcome write holds the row lock, uncommitted, past the lease; a
    reclaim skips the row (SKIP LOCKED) and never reads the marker as a
    crash. After the commit the event is pending with no marker and the next
    claim runs it: exactly one of the two decided it."""
    tenant_id, claim = _marked_claim(tenants)
    paused, release = threading.Event(), threading.Event()
    real_scope = dispatch.tenant_session_scope
    error = _NotSent("connect_failed")

    @contextmanager
    def _paused_scope(scope_tenant: uuid.UUID) -> Iterator[Any]:
        with real_scope(scope_tenant) as session:
            yield session
            if threading.current_thread().name == "attester":
                paused.set()
                assert release.wait(timeout=30), "the attestation was never released"

    monkeypatch.setattr(dispatch, "tenant_session_scope", _paused_scope)
    outcome: dict[str, Any] = {}

    def _write() -> None:
        outcome["status"] = _attest(claim, error, error, _AT)

    attester = threading.Thread(target=_write, name="attester")
    attester.start()
    try:
        assert paused.wait(timeout=30)
        assert _claim(_T0 + timedelta(seconds=10) + _LEASE) == []  # skipped, no wait
    finally:
        release.set()
        attester.join(timeout=30)

    assert outcome["status"] == OUTBOX_STATUS_PENDING
    row = _row(tenant_id, claim.id)
    assert (row.status, row.external_started_claim) == (OUTBOX_STATUS_PENDING, None)
    (second,) = _claim(_AT + _BACKOFF)
    assert (second.attempts, second.claim_token != claim.claim_token) == (2, True)
    assert _row(tenant_id, claim.id).last_error == "_NotSent: connect_failed"


def test_a_reclaim_holding_the_row_wins_over_a_waiting_attestation(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reclaim got the row first (the marked lease had expired): it
    dead-letters `CrashAfterStart:`. The waiting attestation then finds the
    event no longer pending and changes nothing: no retry after a crash
    decision."""
    tenant_id, claim = _marked_claim(tenants)
    paused, release = threading.Event(), threading.Event()

    def _hold(session: object) -> None:
        if threading.current_thread().name == "reclaimer":
            paused.set()
            assert release.wait(timeout=30), "the reclaim was never released"

    monkeypatch.setattr(dispatch, "_claim_hook", _hold)
    outcome: dict[str, Any] = {}
    error = _NotSent("connect_failed")
    reclaim_at = _T0 + timedelta(seconds=10) + _LEASE

    reclaimer = threading.Thread(
        target=lambda: outcome.__setitem__("claims", _claim(reclaim_at)), name="reclaimer"
    )
    attester = threading.Thread(
        target=lambda: outcome.__setitem__(
            "status", _attest(claim, error, error, reclaim_at - timedelta(seconds=1))
        ),
        name="attester",
    )
    reclaimer.start()
    try:
        assert paused.wait(timeout=30)
        attester.start()
        _wait_for_lock_wait()
        assert attester.is_alive()  # queued behind the reclaim
    finally:
        release.set()
        reclaimer.join(timeout=30)
        attester.join(timeout=30)

    assert outcome["claims"] == []
    assert outcome["status"] is None
    row = _row(tenant_id, claim.id)
    assert (row.status, row.last_error) == (OUTBOX_STATUS_DEAD_LETTERED, CRASH_AFTER_START_ERROR)
    assert row.external_started_claim == claim.claim_token


def test_two_outcomes_for_one_claim_the_first_wins(tenants: _Tenants) -> None:
    tenant_id, claim = _marked_claim(tenants)
    error = _NotSent("connect_failed")

    assert _attest(claim, error, error, _AT) == OUTBOX_STATUS_PENDING
    snapshot = _row(tenant_id, claim.id)

    assert _attest(claim, error, error, _AT + timedelta(seconds=5)) is None
    assert (
        _ambiguous(
            claim,
            AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True),
            _AT + timedelta(seconds=5),
        )
        is None
    )
    after = _row(tenant_id, claim.id)
    assert (after.next_attempt_at, after.last_error, after.attempts) == (
        snapshot.next_attempt_at,
        snapshot.last_error,
        snapshot.attempts,
    )


def test_a_stale_worker_cannot_touch_a_live_claims_marker(tenants: _Tenants) -> None:
    """The first claim attested and was retried; the second claim marked its
    own request. The first claim's worker, late, finds its claim superseded:
    it can neither clear the second claim's marker nor retry the event."""
    tenant_id, old = _marked_claim(tenants)
    error = _NotSent("connect_failed")
    _attest(old, error, error, _AT)
    (new,) = _claim(_AT + _BACKOFF)
    assert _mark(new, _AT + _BACKOFF + timedelta(seconds=1)) is True
    snapshot = _row(tenant_id, new.id)

    late = _AT + _BACKOFF + timedelta(seconds=30)
    assert _attest(old, error, error, late) is None
    assert (
        _ambiguous(
            old, AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True), late
        )
        is None
    )

    row = _row(tenant_id, new.id)
    assert (row.claim_token, row.external_started_claim, row.status) == (
        new.claim_token,
        new.claim_token,
        OUTBOX_STATUS_PENDING,
    )
    assert (row.next_attempt_at, row.attempts, row.last_error) == (
        snapshot.next_attempt_at,
        snapshot.attempts,
        snapshot.last_error,
    )
