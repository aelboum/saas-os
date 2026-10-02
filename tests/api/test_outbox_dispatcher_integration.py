"""The durable outbox dispatcher end to end (Foundation Reliability & Events,
RE-2): real PostgreSQL, real Redis, a real ARQ burst worker.

A producer's committed event is claimed from PostgreSQL, handed to the queue
as one `_run_outbox_event` tenant job, run through its existing consumer and
recorded as published -- or, when the consumer fails, recorded durably in
the outbox (never in Redis's dead-letter list). A queue that refuses the
hand-off gives the claim back; a worker that dies after running the consumer
leaves the event to run again (at-least-once).

Each test uses its own queue name and scopes the dispatcher's tenant
enumeration to its own tenants. Ordering is structural -- no sleeps.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import api.outbox_dispatcher as outbox_dispatcher
import core.outbox.dispatch as dispatch
import pytest
from api.outbox_dispatcher import (
    OUTBOX_JOB_FUNCTIONS,
    _dispatch_outbox_cycle,
    _run_outbox_event,
    dispatch_outbox_once,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.jobs.errors import JobsConfigurationError
from infra.jobs.queue import get_redis_pool, register_tenant_job, system_cron
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import core.rbac  # noqa: F401 -- registers the mappers core.audit_log references by name
from core.outbox import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    OutboxDispatchConfig,
    OutboxEvent,
    append_event,
    claim_due_events,
)
from core.tenancy import create_tenant, list_open_tenant_ids
from core.usage import aggregate_usage, ingest_event
from infra.jobs import (
    JobKind,
    SystemJobContext,
    TenantJobContext,
    TenantJobPayload,
    build_worker,
    count_dead_letters,
    get_jobs_config,
    registered_job_kind,
)

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_CONFIG = OutboxDispatchConfig(
    max_attempts=3, retry_jitter_ratio=0, lease_seconds=300, retry_base_seconds=60
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
async def _require_database_and_redis() -> None:
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
    try:
        pool = await get_redis_pool()
        await pool.ping()
        await pool.aclose()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable: {exc}")


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
        tenant_id = create_tenant(f"outbox-e2e-{uuid.uuid4().hex[:10]}").id
        self.ids.append(tenant_id)
        return tenant_id

    def cleanup(self) -> None:
        for tenant_id in self.ids:
            params = {"t": str(tenant_id)}
            for table in ("outbox_events", "usage_events"):
                _admin(f"DELETE FROM core.{table} WHERE tenant_id = :t", params)  # noqa: S608
            _admin(
                "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t",
                params,
            )
            _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
            _admin("DELETE FROM core.tenants WHERE id = :t", params)


@pytest.fixture
def tenants(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Tenants]:
    registry = _Tenants(monkeypatch)
    try:
        yield registry
    finally:
        registry.cleanup()


@pytest.fixture
def queue_name() -> str:
    return f"re2-outbox-{uuid.uuid4().hex[:8]}"


def _row(tenant_id: uuid.UUID, event_id: uuid.UUID) -> OutboxEvent:
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(select(OutboxEvent).where(OutboxEvent.id == event_id)).scalar_one()
        session.expunge(row)
        return row


def _usage(tenant_id: uuid.UUID, metric: str) -> Decimal:
    now = datetime.now(UTC)
    return aggregate_usage(
        tenant_id, metric, since=now - timedelta(days=1), until=now + timedelta(days=1)
    )


def _ingest(tenant_id: uuid.UUID, metric: str = "re2_calls") -> uuid.UUID:
    with tenant_session_scope(tenant_id) as session:
        return ingest_event(session, tenant_id, metric, Decimal("1"))


async def _burst(queue_name: str) -> None:
    worker = build_worker(OUTBOX_JOB_FUNCTIONS, burst=True, queue_name=queue_name)
    try:
        await worker.main()
    finally:
        await worker.close()


async def _dead_letters() -> int:
    pool = await get_redis_pool()
    try:
        return await count_dead_letters(pool, get_jobs_config())
    finally:
        await pool.aclose()


class _RecordingPool:
    def __init__(self, *, fail: bool) -> None:
        self.fail = fail
        self.calls: list[tuple[str, TenantJobPayload]] = []

    async def enqueue_job(self, function_name: str, payload: TenantJobPayload, **_: Any) -> Any:
        self.calls.append((function_name, payload))
        if self.fail:
            raise ConnectionError("redis unavailable")
        return type("Job", (), {"job_id": f"job-{len(self.calls)}"})()

    async def aclose(self) -> None:
        return None


# --- The happy path ---------------------------------------------------------------------


async def test_a_committed_event_is_dispatched_executed_and_published(
    tenants: _Tenants, queue_name: str
) -> None:
    tenant_id = tenants.new()
    event_id = _ingest(tenant_id)
    assert _usage(tenant_id, "re2_calls") == Decimal("0")

    report = await dispatch_outbox_once(config=_CONFIG, queue_name=queue_name)
    assert (report.claimed, report.enqueued, report.released) == (1, 1, 0)
    await _burst(queue_name)

    assert _usage(tenant_id, "re2_calls") == Decimal("1")
    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_PUBLISHED
    assert row.attempts == 1
    assert row.claim_token is None
    # Published is terminal: a later cycle hands nothing to the queue.
    assert (await dispatch_outbox_once(config=_CONFIG, queue_name=queue_name)).claimed == 0


async def test_the_hand_off_is_a_tenant_job_carrying_only_the_claim(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    event_id = _ingest(tenant_id)
    pool = _RecordingPool(fail=False)

    await dispatch_outbox_once(pool=pool, config=_CONFIG)

    ((function_name, payload),) = pool.calls
    assert function_name == "_run_outbox_event"
    assert registered_job_kind("_run_outbox_event") is JobKind.TENANT
    assert registered_job_kind("_dispatch_outbox_cycle") is JobKind.SYSTEM
    assert payload.tenant_id == str(tenant_id)  # the event's own tenant, never system
    assert set(payload.data) == {"outbox_event_id", "claim_token"}
    assert payload.data["outbox_event_id"] == str(event_id)
    assert payload.data["claim_token"] == str(_row(tenant_id, event_id).claim_token)


# --- Failures are recorded in PostgreSQL ---------------------------------------------


async def test_a_consumer_failure_is_recorded_durably_not_in_redis(
    tenants: _Tenants, queue_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    event_id = _ingest(tenant_id)

    async def _broken(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        raise RuntimeError("consumer exploded")

    monkeypatch.setattr(
        outbox_dispatcher, "outbox_event_handlers", lambda: {"usage.ingestion": _broken}
    )
    dead_before = await _dead_letters()

    await dispatch_outbox_once(config=_CONFIG, queue_name=queue_name)
    await _burst(queue_name)

    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.attempts == 1
    assert row.claim_token is None
    assert row.last_error == "RuntimeError: consumer exploded"
    assert row.next_attempt_at > datetime.now(UTC)  # a scheduled retry
    assert await _dead_letters() == dead_before  # ARQ never retried or dead-lettered it


async def test_an_event_with_no_consumer_is_dead_lettered(
    tenants: _Tenants, queue_name: str
) -> None:
    tenant_id = tenants.new()
    with tenant_session_scope(tenant_id) as session:
        event_id = append_event(
            session,
            tenant_id=tenant_id,
            event_type="nobody.listens",
            aggregate_type="probe",
            aggregate_id="1",
            payload={},
        )

    await dispatch_outbox_once(config=_CONFIG, queue_name=queue_name)
    await _burst(queue_name)

    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error is not None and row.last_error.startswith("UnknownEventType")


# --- Redis / worker failure boundaries --------------------------------------------------


async def test_an_unreachable_queue_claims_nothing(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    event_id = _ingest(tenant_id)

    async def _no_redis(*_: object, **__: object) -> object:
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr(outbox_dispatcher, "get_redis_pool", _no_redis)
    with pytest.raises(ConnectionError):
        await dispatch_outbox_once(config=_CONFIG)
    # The scheduled cycle swallows it; the next tick tries again.
    await _dispatch_outbox_cycle(SystemJobContext())

    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_PENDING, 0, None)


async def test_a_refused_hand_off_gives_the_claim_back(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    event_id = _ingest(tenant_id)

    report = await dispatch_outbox_once(pool=_RecordingPool(fail=True), config=_CONFIG)

    assert (report.claimed, report.enqueued, report.released) == (1, 0, 1)
    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.attempts == 0  # the queue outage did not consume an attempt
    assert row.claim_token is None
    assert row.last_error == "ConnectionError: redis unavailable"


async def test_a_worker_that_dies_after_the_consumer_ran_lets_the_event_run_again(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At-least-once, never silent loss: the consumer ran but the worker
    died before recording it, so the claim's lease expires and the event is
    executed again. (Deduplicating the consumer is RE-5.)"""
    tenant_id = tenants.new()
    event_id = _ingest(tenant_id, "re2_redo")
    (claim,) = claim_due_events(config=_CONFIG)

    class _WorkerDied(BaseException):
        pass

    def _die(*_: object, **__: object) -> bool:
        raise _WorkerDied

    monkeypatch.setattr(outbox_dispatcher, "complete_event", _die)
    job_payload = TenantJobPayload(
        tenant_id=str(tenant_id),
        data={"outbox_event_id": str(event_id), "claim_token": str(claim.claim_token)},
    )
    with pytest.raises(_WorkerDied):
        await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), job_payload)
    monkeypatch.undo()
    monkeypatch.setattr(
        dispatch,
        "list_open_tenant_ids",
        lambda: [t for t in list_open_tenant_ids() if t in tenants.ids],
    )

    assert _usage(tenant_id, "re2_redo") == Decimal("1")
    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_PENDING and row.claim_token == claim.claim_token

    # The stale job, if ARQ ever ran it again, does nothing once reclaimed.
    # The running job renewed the lease; reclaim once that renewed lease expires.
    later = row.next_attempt_at + timedelta(seconds=1)
    (reclaim,) = claim_due_events(config=_CONFIG, now=later)
    await _run_outbox_event(TenantJobContext(tenant_id=tenant_id), job_payload)
    assert _usage(tenant_id, "re2_redo") == Decimal("1")

    await _run_outbox_event(
        TenantJobContext(tenant_id=tenant_id),
        TenantJobPayload(
            tenant_id=str(tenant_id),
            data={"outbox_event_id": str(event_id), "claim_token": str(reclaim.claim_token)},
        ),
    )
    assert _usage(tenant_id, "re2_redo") == Decimal("2")  # executed twice: at-least-once
    final = _row(tenant_id, event_id)
    assert final.status == OUTBOX_STATUS_PUBLISHED
    assert final.attempts == 2


# --- Tenancy -------------------------------------------------------------------------


async def test_a_job_for_another_tenant_cannot_run_the_event(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_a, tenant_b = tenants.new(), tenants.new()
    event_id = _ingest(tenant_a)
    claims = claim_due_events(config=_CONFIG)
    (claim,) = [c for c in claims if c.id == event_id]
    ran: list[object] = []

    async def _spy(ctx: TenantJobContext, payload: TenantJobPayload) -> None:
        ran.append(ctx)

    monkeypatch.setattr(
        outbox_dispatcher, "outbox_event_handlers", lambda: {"usage.ingestion": _spy}
    )
    await _run_outbox_event(
        TenantJobContext(tenant_id=tenant_b),
        TenantJobPayload(
            tenant_id=str(tenant_b),
            data={"outbox_event_id": str(event_id), "claim_token": str(claim.claim_token)},
        ),
    )

    assert ran == []
    row = _row(tenant_a, event_id)
    assert (row.status, row.claim_token) == (OUTBOX_STATUS_PENDING, claim.claim_token)


async def test_a_schedule_can_only_run_a_system_job() -> None:
    tenant_job = register_tenant_job(_run_outbox_event)
    with pytest.raises(JobsConfigurationError):
        system_cron(tenant_job, every_seconds=10)
