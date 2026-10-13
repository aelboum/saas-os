"""Transactional outbox (Foundation Reliability & Events, RE-1) against real
PostgreSQL.

Proves the RE-1 guarantee: an event is appended in the caller's own
transaction -- it commits exactly when the caller's mutation commits, and a
rollback discards both -- without opening a session, committing, or
contacting Redis; tenant RLS isolates every row; the three converted
producers (`saas_os.core.webhooks.trigger_event`, `saas_os.core.usage.ingest_event`,
`saas_os.core.notifications.dispatch_notification`) record their events that way;
and tenant purge / user erasure remove the events they must.

Every ordering here is structural (one transaction, then a second session
reading committed state) -- no sleeps, no timing.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Mapping
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

import saas_os.core.notifications.service as notifications_service
import saas_os.core.outbox.service as outbox_service
import saas_os.infra.db.session as db_session_module
import saas_os.infra.jobs.queue as jobs_queue
from lifecycle_callers import PROVISIONING, TENANT_PURGE, platform_operator
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.notifications import dispatch_notification
from saas_os.core.notifications.service import (
    NOTIFICATION_DISPATCH_EVENT_TYPE,
    _decrypt_recipient_email,
    _dispatch_notification_job,
    purge_user_notification_events_in_tenant,
)
from saas_os.core.outbox import (
    OUTBOX_STATUS_PENDING,
    OutboxEvent,
    append_event,
    purge_tenant_outbox_events,
)
from saas_os.core.rbac.models import Role
from saas_os.core.tenancy import (
    TenantClosedError,
    TenantStatus,
    create_tenant,
    transition_tenant_status,
)
from saas_os.core.usage import ingest_event
from saas_os.core.usage.service import USAGE_INGESTION_EVENT_TYPE
from saas_os.core.webhooks import subscribe, trigger_event
from saas_os.core.webhooks.service import WEBHOOK_DELIVERY_EVENT_TYPE
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload
from saas_os.infra.jobs.config import get_jobs_config

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

pytestmark = pytest.mark.integration


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
            conn.execute(text("SELECT 1 FROM core.outbox_events LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable/migrated to RE-1: {exc}")
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
        tenant_id = create_tenant(f"outbox-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
        self.ids.append(tenant_id)
        return tenant_id

    def cleanup(self) -> None:
        for tenant_id in self.ids:
            params = {"t": str(tenant_id)}
            for table in ("outbox_events", "roles", "webhook_subscriptions"):
                _admin(f"DELETE FROM core.{table} WHERE tenant_id = :t", params)  # noqa: S608
            _admin(
                "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t",
                params,
            )
            _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
            _admin("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t", params)
            _admin("DELETE FROM core.tenants WHERE id = :t", params)


@pytest.fixture
def tenants() -> Iterator[_Tenants]:
    registry = _Tenants()
    try:
        yield registry
    finally:
        registry.cleanup()


def _events(tenant_id: uuid.UUID) -> list[OutboxEvent]:
    """Committed outbox rows, read in a fresh tenant-scoped session."""
    with tenant_session_scope(tenant_id) as session:
        rows = list(
            session.execute(
                select(OutboxEvent)
                .where(OutboxEvent.tenant_id == tenant_id)
                .order_by(OutboxEvent.created_at, OutboxEvent.id)
            ).scalars()
        )
        for row in rows:
            session.expunge(row)
        return rows


def _roles(tenant_id: uuid.UUID) -> list[str]:
    with tenant_session_scope(tenant_id) as session:
        return list(session.execute(select(Role.name).where(Role.tenant_id == tenant_id)).scalars())


def _append(session: Any, tenant_id: uuid.UUID, **overrides: Any) -> uuid.UUID:
    kwargs: dict[str, Any] = {
        "tenant_id": tenant_id,
        "event_type": "outbox_test.happened",
        "aggregate_type": "role",
        "aggregate_id": "r-1",
        "payload": {"n": 1, "nested": {"ok": True}},
    }
    kwargs.update(overrides)
    return append_event(session, **kwargs)


class _Boom(Exception):
    pass


# --- Transaction semantics ------------------------------------------------------


def test_commit_persists_the_mutation_and_exactly_one_event_with_its_id(
    tenants: _Tenants,
) -> None:
    tenant_id = tenants.new()
    with tenant_session_scope(tenant_id) as session:
        session.add(Role(tenant_id=tenant_id, name="outbox-commit"))
        event_id = _append(session, tenant_id)

    assert _roles(tenant_id) == ["outbox-commit"]
    (event,) = _events(tenant_id)
    assert event.id == event_id
    assert event.event_type == "outbox_test.happened"
    assert (event.aggregate_type, event.aggregate_id) == ("role", "r-1")
    assert event.payload == {"n": 1, "nested": {"ok": True}}
    assert event.status == OUTBOX_STATUS_PENDING
    assert event.attempts == 0
    assert event.next_attempt_at is not None
    assert event.last_error is None
    assert event.published_at is None
    # The identity is stable: reading it again changes nothing.
    assert [e.id for e in _events(tenant_id)] == [event_id]


def test_rollback_discards_the_mutation_and_the_event_together(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    with pytest.raises(_Boom), tenant_session_scope(tenant_id) as session:
        session.add(Role(tenant_id=tenant_id, name="outbox-rollback"))
        _append(session, tenant_id)
        raise _Boom

    assert _roles(tenant_id) == []
    assert _events(tenant_id) == []


def test_append_event_neither_commits_nor_opens_a_session(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The caller owns the transaction: until the caller commits, a second
    session cannot see the event; and no session factory may be touched."""
    tenant_id = tenants.new()

    def _no_new_session(*_: object, **__: object) -> object:
        raise AssertionError("append_event opened its own session")

    with tenant_session_scope(tenant_id) as session:
        monkeypatch.setattr(db_session_module, "get_session_factory", _no_new_session)
        monkeypatch.setattr(outbox_service, "tenant_session_scope", _no_new_session)
        event_id = _append(session, tenant_id)
        monkeypatch.undo()
        assert _events(tenant_id) == []  # flushed in the caller's txn, not committed
        assert session.get(OutboxEvent, event_id) is not None  # visible to the caller

    assert [e.id for e in _events(tenant_id)] == [event_id]


def test_producers_open_no_session_of_their_own(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    subscribe(tenant_id, "https://example.com/outbox-hook", caller=_PROVISIONING)

    def _no_new_session(*_: object, **__: object) -> object:
        raise AssertionError("a producer opened its own session")

    with tenant_session_scope(tenant_id) as session:
        monkeypatch.setattr(db_session_module, "get_session_factory", _no_new_session)
        trigger_event(session, tenant_id, "order.created", {"order_id": "o-1"})
        ingest_event(session, tenant_id, "api_calls", Decimal("2"))
        dispatch_notification(session, tenant_id, uuid.uuid4(), "in_app", "hello")
        monkeypatch.undo()

    assert len(_events(tenant_id)) == 3


def test_events_commit_while_redis_is_unreachable(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Redis is not part of the transaction: with every route to it broken,
    the producers' events still commit."""
    tenant_id = tenants.new()
    subscribe(tenant_id, "https://example.com/outbox-redis", caller=_PROVISIONING)

    def _no_redis(*_: object, **__: object) -> object:
        raise ConnectionError("redis unreachable")

    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    get_jobs_config.cache_clear()
    monkeypatch.setattr(jobs_queue, "create_pool", _no_redis)
    monkeypatch.setattr(jobs_queue, "get_redis_pool", _no_redis)
    try:
        with tenant_session_scope(tenant_id) as session:
            session.add(Role(tenant_id=tenant_id, name="outbox-redis-down"))
            trigger_event(session, tenant_id, "order.created", {"order_id": "o-2"})
            ingest_event(session, tenant_id, "api_calls", Decimal("1"))
            dispatch_notification(session, tenant_id, uuid.uuid4(), "in_app", "body")
    finally:
        get_jobs_config.cache_clear()

    assert _roles(tenant_id) == ["outbox-redis-down"]
    assert {e.event_type for e in _events(tenant_id)} == {
        WEBHOOK_DELIVERY_EVENT_TYPE,
        USAGE_INGESTION_EVENT_TYPE,
        NOTIFICATION_DISPATCH_EVENT_TYPE,
    }


# --- Tenant isolation -------------------------------------------------------------


def test_a_tenant_cannot_read_another_tenants_events(tenants: _Tenants) -> None:
    tenant_a, tenant_b = tenants.new(), tenants.new()
    with tenant_session_scope(tenant_b) as session:
        _append(session, tenant_b)

    with tenant_session_scope(tenant_a) as session:
        assert list(session.execute(select(OutboxEvent)).scalars()) == []
    with session_scope() as session:  # no tenant bound at all
        assert list(session.execute(select(OutboxEvent)).scalars()) == []
    assert len(_events(tenant_b)) == 1


def test_a_tenant_cannot_append_an_event_for_another_tenant(tenants: _Tenants) -> None:
    tenant_a, tenant_b = tenants.new(), tenants.new()
    with pytest.raises(DBAPIError, match="row-level security"):  # noqa: PT012
        with tenant_session_scope(tenant_a) as session:
            _append(session, tenant_b)
    assert _events(tenant_b) == []


def test_an_unscoped_session_cannot_append_an_event(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    with pytest.raises(DBAPIError, match="row-level security"):  # noqa: PT012
        with session_scope() as session:
            _append(session, tenant_id)
    assert _events(tenant_id) == []


# --- Producers ---------------------------------------------------------------------


def test_trigger_event_records_one_delivery_event_per_subscription(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    first, _ = subscribe(tenant_id, "https://example.com/a", caller=_PROVISIONING)
    second, _ = subscribe(tenant_id, "https://example.com/b", caller=_PROVISIONING)

    with tenant_session_scope(tenant_id) as session:
        ids = trigger_event(session, tenant_id, "order.created", {"order_id": "o-3"})

    events = {e.id: e for e in _events(tenant_id)}
    assert set(ids) == set(events) and len(ids) == 2
    payloads = [events[i].payload for i in ids]
    assert {p["subscription_id"] for p in payloads} == {str(first.id), str(second.id)}
    # One occurrence: one webhook event_id shared by every subscription.
    assert len({p["event_id"] for p in payloads}) == 1
    for event in events.values():
        assert event.event_type == WEBHOOK_DELIVERY_EVENT_TYPE
        assert event.aggregate_type == "webhook_subscription"
        assert event.aggregate_id == event.payload["subscription_id"]
        assert event.payload["event_type"] == "order.created"
        assert event.payload["event_data"] == {"order_id": "o-3"}
        assert set(event.payload) == {"subscription_id", "event_id", "event_type", "event_data"}


def test_trigger_event_with_no_subscriptions_records_nothing(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    with tenant_session_scope(tenant_id) as session:
        assert trigger_event(session, tenant_id, "order.created", {}) == []
    assert _events(tenant_id) == []


def test_trigger_event_never_puts_the_signing_secret_in_the_event(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    _, raw_secret = subscribe(tenant_id, "https://example.com/secret", caller=_PROVISIONING)
    with tenant_session_scope(tenant_id) as session:
        trigger_event(session, tenant_id, "order.created", {"order_id": "o-4"})
    (raw_payload,) = _admin(
        "SELECT payload::text FROM core.outbox_events WHERE tenant_id = :t", {"t": str(tenant_id)}
    )
    assert raw_secret not in raw_payload[0]


def test_ingest_event_records_a_usage_event(tenants: _Tenants) -> None:
    tenant_id = tenants.new()
    with tenant_session_scope(tenant_id) as session:
        event_id = ingest_event(session, tenant_id, "api_calls", Decimal("2.5"))
    (event,) = _events(tenant_id)
    assert event.id == event_id
    assert event.event_type == USAGE_INGESTION_EVENT_TYPE
    assert (event.aggregate_type, event.aggregate_id) == ("usage_metric", "api_calls")
    assert event.payload["metric"] == "api_calls"
    assert event.payload["quantity"] == "2.5"
    assert "occurred_at" in event.payload


def test_in_app_notification_event_carries_no_recipient_email(tenants: _Tenants) -> None:
    tenant_id, user_id = tenants.new(), uuid.uuid4()
    with tenant_session_scope(tenant_id) as session:
        dispatch_notification(session, tenant_id, user_id, "in_app", "hi", subject="S")
    (event,) = _events(tenant_id)
    assert event.event_type == NOTIFICATION_DISPATCH_EVENT_TYPE
    assert (event.aggregate_type, event.aggregate_id) == ("user", str(user_id))
    assert event.payload == {
        "recipient_user_id": str(user_id),
        "channel": "in_app",
        "subject": "S",
        "body": "hi",
    }


@pytest.mark.anyio
async def test_email_address_is_stored_only_encrypted_and_the_handler_decrypts_it(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id, user_id = tenants.new(), uuid.uuid4()
    address = "customer@example.com"
    with tenant_session_scope(tenant_id) as session:
        dispatch_notification(
            session, tenant_id, user_id, "email", "shipped", recipient_email=address
        )

    (raw_payload,) = _admin(
        "SELECT payload::text FROM core.outbox_events WHERE tenant_id = :t", {"t": str(tenant_id)}
    )
    assert address not in raw_payload[0]
    (event,) = _events(tenant_id)
    stored = event.payload["recipient_email"]
    assert isinstance(stored, str) and stored.startswith("efv1:")
    assert _decrypt_recipient_email(tenant_id, stored) == address
    # Bound to the owning tenant: another tenant's binding cannot open it.
    with pytest.raises(Exception):  # noqa: B017, PT011
        _decrypt_recipient_email(uuid.uuid4(), stored)

    # The registered handler, given the event's payload, sends to the
    # plaintext address (the send is intercepted before any delivery).
    sent: list[str] = []

    class _Sent(Exception):
        pass

    def _capture(_user: uuid.UUID, _subject: object, _body: str, recipient: str) -> None:
        sent.append(recipient)
        raise _Sent

    monkeypatch.setattr(notifications_service, "_send_email_channel", _capture)
    with pytest.raises(_Sent):
        await _dispatch_notification_job(
            TenantJobContext(tenant_id=tenant_id, correlation_id=None),
            TenantJobPayload(tenant_id=str(tenant_id), data=event.payload),
        )
    assert sent == [address]


@pytest.mark.parametrize(
    "produce",
    [
        lambda s, t: trigger_event(s, t, "order.created", {}),
        lambda s, t: ingest_event(s, t, "api_calls", Decimal("1")),
        lambda s, t: dispatch_notification(s, t, uuid.uuid4(), "in_app", "b"),
    ],
    ids=["webhooks", "usage", "notifications"],
)
def test_producers_refuse_a_closed_tenant_and_record_nothing(
    tenants: _Tenants, produce: Any
) -> None:
    tenant_id = tenants.new()
    subscribe(tenant_id, "https://example.com/closed", caller=_PROVISIONING)
    transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
    with pytest.raises(TenantClosedError), tenant_session_scope(tenant_id) as session:
        produce(session, tenant_id)
    assert _events(tenant_id) == []


# --- Purge and erasure ----------------------------------------------------------------


def test_tenant_purge_step_deletes_every_outbox_event(tenants: _Tenants) -> None:
    tenant_id, other = tenants.new(), tenants.new()
    for t in (tenant_id, other):
        with tenant_session_scope(t) as session:
            _append(session, t)
            _append(session, t, aggregate_id="r-2")
    transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
    transition_tenant_status(tenant_id, TenantStatus.PURGING, caller=TENANT_PURGE)

    assert purge_tenant_outbox_events(tenant_id) == 2
    assert purge_tenant_outbox_events(tenant_id) == 0  # idempotent
    assert _events(tenant_id) == []
    assert len(_events(other)) == 2  # never another tenant's rows


def test_user_erasure_helper_deletes_only_that_users_notification_events(
    tenants: _Tenants,
) -> None:
    tenant_id = tenants.new()
    erased, kept = uuid.uuid4(), uuid.uuid4()
    with tenant_session_scope(tenant_id) as session:
        dispatch_notification(session, tenant_id, erased, "in_app", "a")
        dispatch_notification(session, tenant_id, erased, "in_app", "b")
        dispatch_notification(session, tenant_id, kept, "in_app", "c")
        ingest_event(session, tenant_id, "api_calls", Decimal("1"))

    assert purge_user_notification_events_in_tenant(tenant_id, erased) == 2
    remaining = _events(tenant_id)
    assert {(e.event_type, e.aggregate_id) for e in remaining} == {
        (NOTIFICATION_DISPATCH_EVENT_TYPE, str(kept)),
        (USAGE_INGESTION_EVENT_TYPE, "api_calls"),
    }
