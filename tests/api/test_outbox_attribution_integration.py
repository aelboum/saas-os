"""ADR 0061, owner decision C (2026-11-01) -- attribution through the
durable outbox, against a real PostgreSQL and Redis.

The producer's initiating actor is captured at `append_event()` time,
stored with the event (inside the existing `payload` column, no schema
change), split off again by the dispatcher and handed to the consumer as
`TenantJobContext.initiated_by` -- never as part of the payload, and never
replaced by the job that runs the consumer. The consumer's audit row then
records three distinct roles: the executing actor (the outbox run job),
the initiating actor (as the producer recorded it, or `"unavailable"`), and
the correlation (arq job id, outbox event id, request id). Attribution
grants nothing: the consumer still runs under its event's own tenant.

Marked `integration`.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Iterator, Mapping
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.api.outbox_dispatcher as outbox_dispatcher
import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.api.outbox_dispatcher import OUTBOX_JOB_FUNCTIONS, dispatch_outbox_once
from saas_os.core.audit_log import AuditLogEntry, record_system_action_in_transaction
from saas_os.core.authority import (
    Initiator,
    ServiceAccountCaller,
    SystemActor,
    SystemActorKind,
    SystemAuthority,
    SystemCaller,
    SystemCorrelation,
    UserCaller,
)
from saas_os.core.outbox import (
    OUTBOX_STATUS_PUBLISHED,
    InvalidOutboxEventError,
    OutboxDispatchConfig,
    OutboxEvent,
    append_event,
)
from saas_os.core.tenancy import create_tenant, list_open_tenant_ids
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload, build_worker
from saas_os.infra.jobs.queue import get_redis_pool
from saas_os.infra.observability import bind_correlation_context

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_CONFIG = OutboxDispatchConfig(
    max_attempts=3, retry_jitter_ratio=0, lease_seconds=300, retry_base_seconds=60
)
_EVENT_TYPE = "attribution.test_event"
_ACTION = "test.attribution.consumed"


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
    """Fresh tenants; the dispatcher only sees these, and every row written
    for them is removed afterwards (rows left behind would block later
    migration downgrades in a shared database)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.ids: list[uuid.UUID] = []
        monkeypatch.setattr(
            dispatch,
            "list_open_tenant_ids",
            lambda: [t for t in list_open_tenant_ids() if t in self.ids],
        )

    def new(self) -> uuid.UUID:
        tenant_id = create_tenant(f"attr-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
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
            _admin("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t", params)
            _admin("DELETE FROM core.tenants WHERE id = :t", params)


@pytest.fixture
def tenants(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Tenants]:
    registry = _Tenants(monkeypatch)
    try:
        yield registry
    finally:
        registry.cleanup()


class _Consumer:
    """A consumer that records what it was handed and writes one system
    audit row exactly as ADR 0061 tells a product to: executor, initiator
    and correlation each derived from its job context."""

    def __init__(self) -> None:
        self.contexts: list[TenantJobContext] = []
        self.payloads: list[dict[str, object]] = []

    async def __call__(self, context: TenantJobContext, payload: TenantJobPayload) -> None:
        self.contexts.append(context)
        self.payloads.append(dict(payload.data))
        with tenant_session_scope(context.tenant_id) as session:
            record_system_action_in_transaction(
                session,
                tenant_id=context.tenant_id,
                actor=SystemActor.from_job_actor(context.system_actor),
                action=_ACTION,
                resource_type="attribution_test",
                initiated_by=Initiator.from_job_initiator(context.initiated_by),
                correlation=SystemCorrelation.from_job_context(context),
            )


@pytest.fixture
def consumer(monkeypatch: pytest.MonkeyPatch) -> _Consumer:
    handler = _Consumer()
    monkeypatch.setattr(outbox_dispatcher, "outbox_event_handlers", lambda: {_EVENT_TYPE: handler})
    return handler


def _append(
    tenant_id: uuid.UUID,
    initiated_by: Initiator | None,
    *,
    request_id: str | None = None,
    payload: dict[str, object] | None = None,
) -> uuid.UUID:
    with (
        bind_correlation_context(request_id=request_id),
        tenant_session_scope(tenant_id) as session,
    ):
        return append_event(
            session,
            tenant_id=tenant_id,
            event_type=_EVENT_TYPE,
            aggregate_type="attribution_test",
            aggregate_id="a-1",
            payload=payload if payload is not None else {"n": 1},
            initiated_by=initiated_by,
        )


async def _dispatch_and_run() -> None:
    queue_name = f"attr-outbox-{uuid.uuid4().hex[:8]}"
    report = await dispatch_outbox_once(config=_CONFIG, queue_name=queue_name)
    assert report.enqueued >= 1
    worker = build_worker(OUTBOX_JOB_FUNCTIONS, burst=True, queue_name=queue_name)
    try:
        await worker.main()
    finally:
        await worker.close()


def _audit_rows(tenant_id: uuid.UUID) -> list[AuditLogEntry]:
    with tenant_session_scope(tenant_id) as session:
        rows = (
            session.execute(
                select(AuditLogEntry)
                .where(AuditLogEntry.tenant_id == tenant_id)
                .where(AuditLogEntry.action == _ACTION)
            )
            .scalars()
            .all()
        )
        for row in rows:
            session.expunge(row)
        return list(rows)


def _metadata(entry: AuditLogEntry) -> dict[str, Any]:
    assert entry.entry_metadata is not None
    return entry.entry_metadata


def _stored_payload(tenant_id: uuid.UUID, event_id: uuid.UUID) -> dict[str, object]:
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(select(OutboxEvent).where(OutboxEvent.id == event_id)).scalar_one()
        assert row.status == OUTBOX_STATUS_PUBLISHED
        return dict(row.payload)


# --- The initiating actor travels from producer to consumer --------------------------


async def test_a_user_initiator_is_preserved_from_producer_to_the_consumers_audit_row(
    tenants: _Tenants, consumer: _Consumer
) -> None:
    tenant_id = tenants.new()
    user_id = uuid.uuid4()
    event_id = _append(
        tenant_id, Initiator.from_caller(UserCaller(user_id)), request_id="req-attr-1"
    )

    await _dispatch_and_run()

    (context,) = consumer.contexts
    # The consumer sees the producer's payload only: the stored initiator is
    # split off into the context, never handed over as payload data.
    assert consumer.payloads == [{"n": 1}]
    assert context.tenant_id == tenant_id
    assert context.event_id == event_id
    assert context.job_id  # the run job's arq id: correlation only
    (row,) = _audit_rows(tenant_id)
    assert row.actor_type == "system"
    # The user is recorded only as the initiator, never as the row's actor.
    assert row.actor_user_id is None and row.actor_service_account_id is None
    assert row.entry_metadata == {
        # Executing actor: the outbox run job (the worker job), not the producer.
        "system_actor": {"kind": "worker_job", "name": "_run_outbox_event"},
        # Initiating actor: exactly what the producer recorded.
        "initiated_by": {"type": "user", "user_id": str(user_id)},
        # Correlation: arq job id and outbox event id, distinct, plus the request id.
        "correlation": {
            "arq_job_id": context.job_id,
            "outbox_event_id": str(event_id),
            "request_id": "req-attr-1",
        },
    }
    assert context.job_id != str(event_id)
    # Stored inside the existing payload column (no migration) under the
    # reserved key; the producer's own keys are unchanged.
    assert _stored_payload(tenant_id, event_id) == {
        "n": 1,
        "saas_os.initiated_by": {"type": "user", "user_id": str(user_id)},
    }


async def test_a_system_initiator_never_yields_a_user_id(
    tenants: _Tenants, consumer: _Consumer
) -> None:
    tenant_id = tenants.new()
    initiator = Initiator.system(
        SystemActor(SystemActorKind.PROVIDER_EVENT_PROCESSOR, "billing.provider_events"),
        record_type="provider_event",
        record_id="evt_attr_1",
    )
    event_id = _append(tenant_id, initiator)

    await _dispatch_and_run()

    (row,) = _audit_rows(tenant_id)
    assert row.actor_user_id is None and row.actor_service_account_id is None
    assert _metadata(row)["initiated_by"] == {
        "type": "system",
        "kind": "provider_event_processor",
        "name": "billing.provider_events",
        "record_type": "provider_event",
        "record_id": "evt_attr_1",
    }
    assert _metadata(row)["system_actor"] == {
        "kind": "worker_job",
        "name": "_run_outbox_event",
    }
    assert _metadata(row)["correlation"]["outbox_event_id"] == str(event_id)
    assert "user_id" not in json.dumps(row.entry_metadata)


async def test_a_service_account_and_an_attributed_system_caller_are_preserved(
    tenants: _Tenants, consumer: _Consumer
) -> None:
    tenant_id = tenants.new()
    account_id = uuid.uuid4()
    _append(tenant_id, Initiator.from_caller(ServiceAccountCaller(account_id, tenant_id)))
    schedule = SystemActor(SystemActorKind.SCHEDULED_JOB, "trial_expiry")
    _append(
        tenant_id,
        Initiator.from_caller(SystemCaller(SystemAuthority.BILLING_OPERATIONS, actor=schedule)),
    )

    await _dispatch_and_run()

    initiators = sorted(
        (json.dumps(_metadata(r)["initiated_by"]) for r in _audit_rows(tenant_id)),
    )
    assert initiators == sorted(
        [
            json.dumps({"type": "service_account", "service_account_id": str(account_id)}),
            json.dumps({"type": "system", "kind": "scheduled_job", "name": "trial_expiry"}),
        ]
    )


async def test_without_a_recorded_initiator_the_consumer_records_it_as_unavailable(
    tenants: _Tenants, consumer: _Consumer
) -> None:
    """A producer that recorded none (every producer before decision C, and
    a purpose-only `SystemCaller`): the row says `"unavailable"`; the run
    job is never substituted for the initiator."""
    tenant_id = tenants.new()
    assert Initiator.from_caller(SystemCaller(SystemAuthority.PROVISIONING)) is None
    event_id = _append(tenant_id, None)

    await _dispatch_and_run()

    (context,) = consumer.contexts
    assert context.initiated_by is None
    (row,) = _audit_rows(tenant_id)
    assert _metadata(row)["initiated_by"] == "unavailable"
    assert _metadata(row)["system_actor"] == {
        "kind": "worker_job",
        "name": "_run_outbox_event",
    }
    assert _stored_payload(tenant_id, event_id) == {"n": 1}


async def test_an_unreadable_stored_initiator_is_unavailable_never_guessed(
    tenants: _Tenants, consumer: _Consumer, caplog: pytest.LogCaptureFixture
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id, Initiator.user(uuid.uuid4()))
    forged = {"n": 1, "saas_os.initiated_by": {"type": "root", "user_id": "x"}}
    _admin(
        "UPDATE core.outbox_events SET payload = CAST(:p AS json) WHERE id = :i",
        {"p": json.dumps(forged), "i": str(event_id)},
    )

    with caplog.at_level(logging.WARNING, logger="saas_os.core.outbox.dispatch"):
        await _dispatch_and_run()

    assert consumer.payloads == [{"n": 1}]
    (row,) = _audit_rows(tenant_id)
    assert _metadata(row)["initiated_by"] == "unavailable"
    assert "outbox_event_initiator_unreadable" in caplog.text


# --- Producer-side validation ---------------------------------------------------------


@pytest.mark.parametrize(
    "initiated_by",
    [
        {"type": "user", "user_id": str(uuid.uuid4())},
        "unavailable",
        UserCaller(uuid.uuid4()),
        SystemActor(SystemActorKind.WORKER_JOB, "x"),
    ],
    ids=["dict", "string", "caller", "actor"],
)
async def test_append_event_accepts_only_a_validated_initiator(
    tenants: _Tenants, initiated_by: object
) -> None:
    tenant_id = tenants.new()
    with pytest.raises(InvalidOutboxEventError):
        _append(tenant_id, initiated_by)  # type: ignore[arg-type]


async def test_a_producer_cannot_forge_the_initiator_through_its_payload(
    tenants: _Tenants,
) -> None:
    tenant_id = tenants.new()
    forged: dict[str, object] = {
        "saas_os.initiated_by": {"type": "user", "user_id": str(uuid.uuid4())}
    }
    with pytest.raises(InvalidOutboxEventError):
        _append(tenant_id, None, payload=forged)
    with tenant_session_scope(tenant_id) as session:
        count = session.execute(select(OutboxEvent).where(OutboxEvent.tenant_id == tenant_id)).all()
    assert count == []


# --- Tenant isolation ------------------------------------------------------------------


async def test_attribution_never_moves_a_row_to_another_tenant(
    tenants: _Tenants, consumer: _Consumer
) -> None:
    """Two tenants' events, each initiated by a different user: each
    consumer run is scoped to its event's own tenant, and each tenant's
    audit trail holds only its own row with its own initiator."""
    first, second = tenants.new(), tenants.new()
    first_user, second_user = uuid.uuid4(), uuid.uuid4()
    first_event = _append(first, Initiator.user(first_user))
    second_event = _append(second, Initiator.user(second_user))

    await _dispatch_and_run()

    assert {(c.tenant_id, c.event_id) for c in consumer.contexts} == {
        (first, first_event),
        (second, second_event),
    }
    (first_row,) = _audit_rows(first)
    (second_row,) = _audit_rows(second)
    assert _metadata(first_row)["initiated_by"] == {
        "type": "user",
        "user_id": str(first_user),
    }
    assert _metadata(second_row)["initiated_by"] == {
        "type": "user",
        "user_id": str(second_user),
    }
    assert _metadata(first_row)["correlation"]["outbox_event_id"] == str(first_event)
    assert _metadata(second_row)["correlation"]["outbox_event_id"] == str(second_event)
