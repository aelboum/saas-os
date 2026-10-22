"""RE-5: consumer idempotency in the real outbox consumers -- real
PostgreSQL, real handlers, real Redis/ARQ for the dispatcher path, a real
local HTTP receiver for webhooks.

What is proven, consumer by consumer:

- `usage.ingestion` -- the usage row and the consumption record commit in
  one transaction: a repeated execution (after a worker died, or running
  concurrently) never counts usage twice;
- `notification.dispatch` -- one notification row per event; an e-mail is
  not re-sent once its completion is recorded, and the one window where it
  can be (the worker dies between sending and recording) is demonstrated,
  not hidden;
- `webhook.delivery` -- a delivered event is not POSTed again; each
  subscription's delivery is its own identity;
- a job with no event identity (queued directly, before the outbox) behaves
  exactly as before.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import asyncio
import ipaddress
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.api.outbox_dispatcher as outbox_dispatcher
import saas_os.core.notifications.service as notifications_service
import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
import saas_os.core.usage.service as usage_service
import saas_os.core.webhooks.service as webhooks_service
from lifecycle_callers import PROVISIONING
from saas_os.api.outbox_dispatcher import _run_outbox_event
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.notifications import dispatch_notification, list_notifications
from saas_os.core.outbox import (
    OUTBOX_STATUS_PUBLISHED,
    ClaimedEvent,
    OutboxEvent,
    claim_due_events,
)
from saas_os.core.outbox.models import OUTBOX_STATUS_DEAD_LETTERED, OUTBOX_STATUS_PENDING
from saas_os.core.tenancy import create_tenant, list_open_tenant_ids
from saas_os.core.usage import aggregate_usage, ingest_event
from saas_os.core.webhooks.service import subscribe, trigger_event
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_RECEIVER_HOST = "receiver.invalid"


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


class _World:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tenants: list[uuid.UUID] = []
        self.users: list[uuid.UUID] = []
        monkeypatch.setattr(
            dispatch,
            "list_open_tenant_ids",
            lambda: [t for t in list_open_tenant_ids() if t in self.tenants],
        )

    def tenant(self) -> uuid.UUID:
        tenant_id = create_tenant(f"re5-consumers-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
        self.tenants.append(tenant_id)
        return tenant_id

    def member(self, tenant_id: uuid.UUID) -> uuid.UUID:
        user_id = create_user().id
        self.users.append(user_id)
        add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
        return user_id

    def cleanup(self) -> None:
        for tenant_id in self.tenants:
            params = {"t": str(tenant_id)}
            for table in (
                "outbox_consumptions",
                "outbox_events",
                "usage_events",
                "notifications",
                "webhook_subscriptions",
                "tenant_memberships",
            ):
                _admin(f"DELETE FROM core.{table} WHERE tenant_id = :t", params)  # noqa: S608
            _admin(
                "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t",
                params,
            )
            _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
            _admin("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t", params)
            _admin("DELETE FROM core.tenants WHERE id = :t", params)
        for user_id in self.users:
            _admin("DELETE FROM core.audit_log WHERE actor_user_id = :u", {"u": str(user_id)})
            _admin("DELETE FROM core.users WHERE id = :u", {"u": str(user_id)})


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> Iterator[_World]:
    w = _World(monkeypatch)
    try:
        yield w
    finally:
        w.cleanup()


def _event(tenant_id: uuid.UUID, event_id: uuid.UUID) -> OutboxEvent:
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(select(OutboxEvent).where(OutboxEvent.id == event_id)).scalar_one()
        session.expunge(row)
        return row


def _usage(tenant_id: uuid.UUID, metric: str) -> Decimal:
    now = datetime.now(UTC)
    return aggregate_usage(
        tenant_id, metric, since=now - timedelta(days=1), until=now + timedelta(days=1)
    )


def _context(event: OutboxEvent) -> TenantJobContext:
    return TenantJobContext(tenant_id=event.tenant_id, event_id=event.id)


def _payload(event: OutboxEvent) -> TenantJobPayload:
    return TenantJobPayload(tenant_id=str(event.tenant_id), data=dict(event.payload))


class _WorkerDied(BaseException):
    pass


async def _run_and_die(
    event: OutboxEvent, monkeypatch: pytest.MonkeyPatch, claim: ClaimedEvent | None = None
) -> None:
    """Claim the event (unless already claimed) and run it through the
    dispatcher's own job, but the worker dies before the dispatcher records
    the outcome."""
    if claim is None:
        (claim,) = [c for c in claim_due_events() if c.id == event.id]

    def _die(*_: object, **__: object) -> bool:
        raise _WorkerDied

    with monkeypatch.context() as m:
        m.setattr(outbox_dispatcher, "complete_event", _die)
        with pytest.raises(_WorkerDied):
            await _run_outbox_event(
                TenantJobContext(tenant_id=event.tenant_id),
                TenantJobPayload(
                    tenant_id=str(event.tenant_id),
                    data={"outbox_event_id": str(event.id), "claim_token": str(claim.claim_token)},
                ),
            )


async def _redeliver(event: OutboxEvent) -> None:
    """The lease expires; the event is claimed and run again, to completion."""
    later = _event(event.tenant_id, event.id).next_attempt_at + timedelta(seconds=1)
    (claim,) = [c for c in claim_due_events(now=later) if c.id == event.id]
    await _run_outbox_event(
        TenantJobContext(tenant_id=event.tenant_id),
        TenantJobPayload(
            tenant_id=str(event.tenant_id),
            data={"outbox_event_id": str(event.id), "claim_token": str(claim.claim_token)},
        ),
    )


# --- usage.ingestion -------------------------------------------------------------------


async def test_usage_is_counted_once_when_the_event_runs_again(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = world.tenant()
    with tenant_session_scope(tenant_id) as session:
        event_id = ingest_event(session, tenant_id, "re5_calls", Decimal("3"))
    event = _event(tenant_id, event_id)

    await _run_and_die(event, monkeypatch)
    assert _usage(tenant_id, "re5_calls") == Decimal("3")
    await _redeliver(event)

    assert _usage(tenant_id, "re5_calls") == Decimal("3")  # not 6
    assert _event(tenant_id, event_id).status == OUTBOX_STATUS_PUBLISHED


def test_concurrent_executions_of_one_usage_event_count_it_once(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two workers run the same event at once (a lease expired while the
    first was still running). The first holds its uncommitted claim; the
    second provably waits on it, then sees it committed and skips."""
    tenant_id = world.tenant()
    with tenant_session_scope(tenant_id) as session:
        event_id = ingest_event(session, tenant_id, "re5_race", Decimal("1"))
    event = _event(tenant_id, event_id)
    real_claim = usage_service.claim_event_consumption
    holding, release = threading.Event(), threading.Event()
    pids: dict[str, int] = {}

    def _claim_and_hold(session: Any, **kwargs: Any) -> bool:
        claimed = real_claim(session, **kwargs)
        if threading.current_thread().name == "first":
            pids["first"] = session.execute(text("SELECT pg_backend_pid()")).scalar_one()
            holding.set()
            assert release.wait(30)
        return claimed

    monkeypatch.setattr(usage_service, "claim_event_consumption", _claim_and_hold)

    def _run() -> None:
        asyncio.run(usage_service._ingest_usage_event_job(_context(event), _payload(event)))

    first = threading.Thread(target=_run, name="first")
    second = threading.Thread(target=_run, name="second")
    first.start()
    assert holding.wait(30)
    second.start()
    try:
        engine = build_engine(get_migrations_database_config())
        try:
            deadline = time.monotonic() + 30
            while True:
                with engine.connect() as conn:
                    blocked = conn.execute(
                        text(
                            "SELECT 1 FROM pg_stat_activity WHERE :p = ANY(pg_blocking_pids(pid))"
                        ),
                        {"p": pids["first"]},
                    ).first()
                if blocked:
                    break
                assert time.monotonic() < deadline, "the second execution never waited"
                threading.Event().wait(0.02)
        finally:
            engine.dispose()
    finally:
        release.set()
        first.join(30)
        second.join(30)

    assert _usage(tenant_id, "re5_race") == Decimal("1")


async def test_a_directly_queued_job_without_an_event_identity_is_unchanged(
    world: _World,
) -> None:
    """A job enqueued before the outbox existed carries no event identity:
    it has nothing to deduplicate on, and runs exactly as it always did."""
    tenant_id = world.tenant()
    payload = TenantJobPayload(
        tenant_id=str(tenant_id),
        data={
            "metric": "re5_legacy",
            "quantity": "1",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
    )
    for _ in range(2):
        await usage_service._ingest_usage_event_job(TenantJobContext(tenant_id=tenant_id), payload)
    assert _usage(tenant_id, "re5_legacy") == Decimal("2")


# --- notification.dispatch --------------------------------------------------------------


async def test_an_in_app_notification_is_recorded_once_when_the_event_runs_again(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = world.tenant()
    user_id = world.member(tenant_id)
    with tenant_session_scope(tenant_id) as session:
        event_id = dispatch_notification(session, tenant_id, user_id, "in_app", "hello")
    event = _event(tenant_id, event_id)

    await _run_and_die(event, monkeypatch)
    await _redeliver(event)

    assert len(list_notifications(tenant_id, user_id)) == 1


async def test_an_email_is_not_resent_once_its_completion_is_recorded(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = world.tenant()
    user_id = world.member(tenant_id)
    sent: list[str] = []
    monkeypatch.setattr(
        notifications_service,
        "_send_email_channel",
        lambda _user, _subject, _body, recipient, _event_id=None: sent.append(recipient),
    )
    with tenant_session_scope(tenant_id) as session:
        event_id = dispatch_notification(
            session, tenant_id, user_id, "email", "hi", recipient_email="a@example.com"
        )
    event = _event(tenant_id, event_id)

    await _run_and_die(event, monkeypatch)
    await _redeliver(event)

    assert sent == ["a@example.com"]  # once
    assert len(list_notifications(tenant_id, user_id)) == 1


async def test_an_email_sent_just_before_the_worker_died_is_sent_again(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The documented boundary, demonstrated: an e-mail cannot join the
    database transaction. If the worker dies after sending and before the
    completion commits, the retry sends again -- at-least-once."""
    tenant_id = world.tenant()
    user_id = world.member(tenant_id)
    sent: list[str] = []
    monkeypatch.setattr(
        notifications_service,
        "_send_email_channel",
        lambda _user, _subject, _body, recipient, _event_id=None: sent.append(recipient),
    )
    with tenant_session_scope(tenant_id) as session:
        event_id = dispatch_notification(
            session, tenant_id, user_id, "email", "hi", recipient_email="b@example.com"
        )
    event = _event(tenant_id, event_id)

    def _die_before_recording(*_: object, **__: object) -> bool:
        raise _WorkerDied

    with monkeypatch.context() as m:
        m.setattr(notifications_service, "claim_event_consumption", _die_before_recording)
        (claim,) = [c for c in claim_due_events() if c.id == event.id]
        with pytest.raises(_WorkerDied):
            await _run_outbox_event(
                TenantJobContext(tenant_id=tenant_id),
                TenantJobPayload(
                    tenant_id=str(tenant_id),
                    data={"outbox_event_id": str(event_id), "claim_token": str(claim.claim_token)},
                ),
            )
    await _redeliver(event)

    assert sent == ["b@example.com", "b@example.com"]
    assert len(list_notifications(tenant_id, user_id)) == 1  # the row is still recorded once


def _record_messages(monkeypatch: pytest.MonkeyPatch, sent: list[Any]) -> None:
    """The real `_send_email_channel()`, with only the provider call
    intercepted (ADR-0057 tests below)."""
    from saas_os.core.email.provider import EmailSendResult

    def _send(message: Any, *, provider: Any = None) -> EmailSendResult:
        sent.append(message)
        return EmailSendResult(accepted=True, provider_message_id=message.message_id)

    monkeypatch.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    monkeypatch.setattr("saas_os.core.email.send_email", _send)


async def test_a_resent_email_carries_the_same_message_id(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-0057: the at-least-once resend above carries the same
    `Message-ID` both times, derived from the outbox event id, so a receiver
    that deduplicates on it can drop the second copy. It does not make
    delivery exactly-once: two messages are still sent."""
    tenant_id = world.tenant()
    user_id = world.member(tenant_id)
    sent: list[Any] = []
    _record_messages(monkeypatch, sent)
    with tenant_session_scope(tenant_id) as session:
        event_id = dispatch_notification(
            session, tenant_id, user_id, "email", "hi", recipient_email="c@example.com"
        )
    event = _event(tenant_id, event_id)

    def _die_before_recording(*_: object, **__: object) -> bool:
        raise _WorkerDied

    with monkeypatch.context() as m:
        m.setattr(notifications_service, "claim_event_consumption", _die_before_recording)
        (claim,) = [c for c in claim_due_events() if c.id == event.id]
        with pytest.raises(_WorkerDied):
            await _run_outbox_event(
                TenantJobContext(tenant_id=tenant_id),
                TenantJobPayload(
                    tenant_id=str(tenant_id),
                    data={"outbox_event_id": str(event_id), "claim_token": str(claim.claim_token)},
                ),
            )
    await _redeliver(event)

    assert len(sent) == 2
    assert sent[0].message_id == f"<notification.{event_id}@example.com>"
    assert sent[1].message_id == sent[0].message_id
    assert _event(tenant_id, event_id).status == OUTBOX_STATUS_PUBLISHED


async def _run_once(event: OutboxEvent) -> None:
    (claim,) = [c for c in claim_due_events() if c.id == event.id]
    await _run_outbox_event(
        TenantJobContext(tenant_id=event.tenant_id),
        TenantJobPayload(
            tenant_id=str(event.tenant_id),
            data={"outbox_event_id": str(event.id), "claim_token": str(claim.claim_token)},
        ),
    )


async def test_a_permanent_email_refusal_dead_letters_the_event_at_once(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-0057: a provider failure marked permanent (an SMTP 5xx refusing
    the recipient) is a `PermanentEventError`: the dispatcher dead-letters
    the event after one attempt instead of resending it, and no
    notification row claims it was sent."""
    from saas_os.core.email.errors import EmailProviderError

    tenant_id = world.tenant()
    user_id = world.member(tenant_id)
    attempts: list[Any] = []

    def _refuse(message: Any, *, provider: Any = None) -> None:
        attempts.append(message)
        raise EmailProviderError("send", "SMTPRecipientsRefused", permanent=True, reply_code=550)

    monkeypatch.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    monkeypatch.setattr("saas_os.core.email.send_email", _refuse)
    with tenant_session_scope(tenant_id) as session:
        event_id = dispatch_notification(
            session, tenant_id, user_id, "email", "hi", recipient_email="d@example.com"
        )

    await _run_once(_event(tenant_id, event_id))

    row = _event(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.attempts == 1
    assert len(attempts) == 1
    assert "d@example.com" not in (row.last_error or "")
    assert list_notifications(tenant_id, user_id) == []


async def test_a_transient_email_failure_keeps_the_existing_retry_policy(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The counterpart: an ordinary (transient) provider failure is not
    dead-lettered at once -- the event stays pending for its next attempt,
    exactly as before ADR-0057."""
    from saas_os.core.email.errors import EmailProviderError

    tenant_id = world.tenant()
    user_id = world.member(tenant_id)

    def _fail(message: Any, *, provider: Any = None) -> None:
        raise EmailProviderError("send", "SMTPServerDisconnected")

    monkeypatch.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    monkeypatch.setattr("saas_os.core.email.send_email", _fail)
    with tenant_session_scope(tenant_id) as session:
        event_id = dispatch_notification(
            session, tenant_id, user_id, "email", "hi", recipient_email="e@example.com"
        )

    await _run_once(_event(tenant_id, event_id))

    row = _event(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.attempts == 1
    assert list_notifications(tenant_id, user_id) == []


# --- webhook.delivery ------------------------------------------------------------------


class _Receiver:
    def __init__(self) -> None:
        self.received: list[bytes] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                outer.received.append(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                self.send_response(200)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://{_RECEIVER_HOST}:{self._server.server_address[1]}/hook"

    def __enter__(self) -> _Receiver:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def reach_local_receiver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve only the test-only receiver name to 127.0.0.1 (bypassing the
    destination policy for it); every other name uses the real policy."""
    real = webhooks_service._validate_destination_addresses

    def _validate(url: str, **kwargs: Any) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        if f"//{_RECEIVER_HOST}:" in url:
            return [ipaddress.ip_address("127.0.0.1")]
        return real(url, **kwargs)

    monkeypatch.setattr(webhooks_service, "_validate_destination_addresses", _validate)


async def test_a_delivered_webhook_is_not_posted_again_and_subscriptions_are_independent(
    world: _World, monkeypatch: pytest.MonkeyPatch, reach_local_receiver: None
) -> None:
    tenant_id = world.tenant()
    with _Receiver() as first, _Receiver() as second:
        subscribe(tenant_id, first.url, caller=_PROVISIONING)
        subscribe(tenant_id, second.url, caller=_PROVISIONING)
        with tenant_session_scope(tenant_id) as session:
            event_ids = trigger_event(session, tenant_id, "order.created", {"order_id": "o-5"})
        events = [_event(tenant_id, e) for e in event_ids]

        claims = {c.id: c for c in claim_due_events()}  # one cycle claims both
        for event in events:
            await _run_and_die(event, monkeypatch, claims[event.id])
        later = max(_event(tenant_id, e.id).next_attempt_at for e in events)
        reclaims = {c.id: c for c in claim_due_events(now=later + timedelta(seconds=1))}
        for event in events:
            await _run_outbox_event(
                TenantJobContext(tenant_id=tenant_id),
                TenantJobPayload(
                    tenant_id=str(tenant_id),
                    data={
                        "outbox_event_id": str(event.id),
                        "claim_token": str(reclaims[event.id].claim_token),
                    },
                ),
            )

    # Same webhook occurrence (one shared webhook event_id), two
    # subscriptions: each delivered exactly once despite the re-execution.
    assert len(first.received) == 1
    assert len(second.received) == 1
    assert all(_event(tenant_id, e.id).status == OUTBOX_STATUS_PUBLISHED for e in events)
