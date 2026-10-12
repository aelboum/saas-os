"""RE-4: durable webhook delivery through the outbox dispatcher, with failure
classification -- real PostgreSQL, real Redis, a real ARQ burst worker, a
real local HTTP receiver.

A webhook delivery is a `core.outbox_events` row (`webhook.delivery`), so
its delivery state, attempts and terminal outcome are durable and survive
any worker restart. What RE-4 adds is the classification of a failed
attempt:

- transient (network error, DNS failure, 5xx, 429, ...) -> retried with the
  outbox's bounded backoff, recorded in `last_error`;
- permanent destination refusal (3xx -- never followed -- and 400/410/413/
  422) -> dead-lettered at once;
- security-policy rejection (destination resolves to a non-public address)
  -> dead-lettered at once, with no request sent;
- malformed event -> dead-lettered at once.

The tests that need a reachable receiver bind it to 127.0.0.1 and bypass
only the destination check for that one address (the same, documented
technique as `test_webhooks_delivery_integration.py`); the SSRF and DNS
tests use the real policy with an injected resolver.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import ipaddress
import threading
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
import saas_os.core.webhooks.service as webhooks_service
from saas_os.api.outbox_dispatcher import OUTBOX_JOB_FUNCTIONS, dispatch_outbox_once
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.outbox import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    OutboxDispatchConfig,
    OutboxEvent,
    append_event,
    claim_due_events,
)
from saas_os.core.tenancy import create_tenant, list_open_tenant_ids
from saas_os.core.webhooks.errors import WebhookDestinationUnresolvedError
from saas_os.core.webhooks.service import (
    WEBHOOK_DELIVERY_EVENT_TYPE,
    compute_signed_envelope,
    subscribe,
    trigger_event,
)
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import build_worker
from saas_os.infra.jobs.queue import get_redis_pool

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_CONFIG = OutboxDispatchConfig(
    max_attempts=3, retry_jitter_ratio=0, retry_base_seconds=60, lease_seconds=300
)
_RECEIVER_HOST = "receiver.invalid"


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
        pytest.skip(f"PostgreSQL not reachable/migrated: {exc}")
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


class _Tenant:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.id = create_tenant(f"re4-delivery-{uuid.uuid4().hex[:10]}").id
        monkeypatch.setattr(
            dispatch,
            "list_open_tenant_ids",
            lambda: [t for t in list_open_tenant_ids() if t == self.id],
        )

    def cleanup(self) -> None:
        params = {"t": str(self.id)}
        for table in ("outbox_consumptions", "outbox_events", "webhook_subscriptions"):
            _admin(f"DELETE FROM core.{table} WHERE tenant_id = :t", params)  # noqa: S608
        _admin(
            "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t", params
        )
        _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
        _admin("DELETE FROM core.tenants WHERE id = :t", params)


@pytest.fixture
def tenant(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Tenant]:
    t = _Tenant(monkeypatch)
    try:
        yield t
    finally:
        t.cleanup()


@pytest.fixture(autouse=True)
def _dispatch_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker-side transitions (`fail_event()` etc.) read the policy
    themselves; make the whole dispatch path use this file's policy."""
    monkeypatch.setattr(dispatch, "get_outbox_dispatch_config", lambda: _CONFIG)


@pytest.fixture
def queue_name() -> str:
    return f"re4-webhooks-{uuid.uuid4().hex[:8]}"


class _Receiver:
    """A real local HTTP receiver answering every POST with `status`
    (plus `headers`), recording what it received."""

    def __init__(self, status: int, headers: Mapping[str, str] | None = None) -> None:
        self.status = status
        self.headers = dict(headers or {})
        self.received: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.received.append(
                    {
                        "body": body,
                        "host": self.headers.get("Host"),
                        "signature": self.headers.get("X-Webhook-Signature"),
                        "timestamp": self.headers.get("X-Webhook-Timestamp"),
                    }
                )
                self.send_response(outer.status)
                for name, value in outer.headers.items():
                    self.send_header(name, value)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://{_RECEIVER_HOST}:{self.port}/hook"

    def __enter__(self) -> _Receiver:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def reach_local_receiver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve only `receiver.invalid` to the local receiver's 127.0.0.1,
    bypassing the destination policy for that test-only name. Every other
    name still goes through the real policy."""
    real = webhooks_service._validate_destination

    def _validate(url: str, **kwargs: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        if f"//{_RECEIVER_HOST}:" in url:
            return ipaddress.ip_address("127.0.0.1")
        return real(url, **kwargs)

    monkeypatch.setattr(webhooks_service, "_validate_destination", _validate)


def _row(tenant_id: uuid.UUID, event_id: uuid.UUID) -> OutboxEvent:
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(select(OutboxEvent).where(OutboxEvent.id == event_id)).scalar_one()
        session.expunge(row)
        return row


def _trigger(tenant_id: uuid.UUID) -> uuid.UUID:
    with tenant_session_scope(tenant_id) as session:
        (event_id,) = trigger_event(session, tenant_id, "order.created", {"order_id": "o-1"})
    return event_id


async def _cycle(queue_name: str, *, now: datetime | None = None) -> None:
    await dispatch_outbox_once(config=_CONFIG, queue_name=queue_name, now=now)
    worker = build_worker(OUTBOX_JOB_FUNCTIONS, burst=True, queue_name=queue_name)
    try:
        await worker.main()
    finally:
        await worker.close()


# --- Success and durability ---------------------------------------------------------


async def test_a_delivery_is_signed_sent_and_published(
    tenant: _Tenant, queue_name: str, reach_local_receiver: None
) -> None:
    with _Receiver(200) as receiver:
        _, secret = subscribe(tenant.id, receiver.url, caller=_PROVISIONING)
        event_id = _trigger(tenant.id)
        await _cycle(queue_name)

    (request,) = receiver.received
    assert request["host"] == f"{_RECEIVER_HOST}:{receiver.port}"
    assert request["signature"] == compute_signed_envelope(
        secret, request["body"], int(request["timestamp"])
    )
    row = _row(tenant.id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_PUBLISHED, 1)


async def test_a_delivery_survives_a_worker_that_never_ran(
    tenant: _Tenant, queue_name: str, reach_local_receiver: None
) -> None:
    """The first dispatcher claimed the delivery and handed it to a queue no
    worker ever consumed (the worker process died). Nothing in memory or
    Redis is needed: the row's lease expires and a fresh dispatcher and
    worker deliver it."""
    with _Receiver(200) as receiver:
        subscribe(tenant.id, receiver.url, caller=_PROVISIONING)
        event_id = _trigger(tenant.id)
        await dispatch_outbox_once(config=_CONFIG, queue_name=f"{queue_name}-lost")

        lease_end = _row(tenant.id, event_id).next_attempt_at
        await _cycle(queue_name, now=lease_end + timedelta(seconds=1))

    assert len(receiver.received) == 1
    row = _row(tenant.id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_PUBLISHED, 2)


# --- Transient failures: retried, bounded --------------------------------------------


async def test_a_server_error_is_retried_and_then_dead_lettered_when_exhausted(
    tenant: _Tenant, queue_name: str, reach_local_receiver: None
) -> None:
    with _Receiver(503) as receiver:
        subscribe(tenant.id, receiver.url, caller=_PROVISIONING)
        event_id = _trigger(tenant.id)

        await _cycle(queue_name)
        row = _row(tenant.id, event_id)
        assert (row.status, row.attempts) == (OUTBOX_STATUS_PENDING, 1)
        assert row.last_error is not None and "HTTP 503" in row.last_error
        assert row.next_attempt_at > datetime.now(UTC)  # a scheduled, durable retry

        at = row.next_attempt_at
        for _ in range(_CONFIG.max_attempts - 1):
            await _cycle(queue_name, now=at + timedelta(seconds=1))
            at = _row(tenant.id, event_id).next_attempt_at

    row = _row(tenant.id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_DEAD_LETTERED, _CONFIG.max_attempts)
    assert len(receiver.received) == _CONFIG.max_attempts  # bounded, never more


@pytest.mark.parametrize("status", [429, 500, 401, 404])
async def test_retryable_statuses_are_retried(
    tenant: _Tenant, queue_name: str, reach_local_receiver: None, status: int
) -> None:
    with _Receiver(status) as receiver:
        subscribe(tenant.id, receiver.url, caller=_PROVISIONING)
        event_id = _trigger(tenant.id)
        await _cycle(queue_name)

    row = _row(tenant.id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_PENDING, 1)
    assert row.last_error is not None and f"HTTP {status}" in row.last_error


async def test_a_dns_failure_is_retried(
    tenant: _Tenant, queue_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _unresolvable(hostname: str) -> list[str]:
        raise WebhookDestinationUnresolvedError(hostname)

    monkeypatch.setattr(webhooks_service, "_default_resolve_hostname", _unresolvable)
    subscribe(tenant.id, "https://hooks.example.com/x", caller=_PROVISIONING)
    event_id = _trigger(tenant.id)
    await _cycle(queue_name)

    row = _row(tenant.id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_PENDING, 1)
    assert row.last_error is not None
    assert row.last_error.startswith("WebhookDestinationUnresolvedError")


# --- Permanent failures: dead-lettered at once ----------------------------------------


@pytest.mark.parametrize("status", [400, 410, 413, 422])
async def test_a_permanent_refusal_is_dead_lettered_at_once(
    tenant: _Tenant, queue_name: str, reach_local_receiver: None, status: int
) -> None:
    with _Receiver(status) as receiver:
        subscribe(tenant.id, receiver.url, caller=_PROVISIONING)
        event_id = _trigger(tenant.id)
        await _cycle(queue_name)

    row = _row(tenant.id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_DEAD_LETTERED, 1)
    assert row.last_error is not None
    assert row.last_error.startswith("WebhookPermanentDeliveryError")
    assert f"HTTP {status}" in row.last_error


async def test_a_redirect_is_never_followed_and_is_permanent(
    tenant: _Tenant, queue_name: str, reach_local_receiver: None
) -> None:
    """A redirect would send the event to a destination nobody validated."""
    with _Receiver(200) as target:
        with _Receiver(302, {"Location": f"http://127.0.0.1:{target.port}/hook"}) as receiver:
            subscribe(tenant.id, receiver.url, caller=_PROVISIONING)
            event_id = _trigger(tenant.id)
            await _cycle(queue_name)

    assert len(receiver.received) == 1
    assert target.received == []  # the redirect target was never contacted
    row = _row(tenant.id, event_id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error is not None and "HTTP 302" in row.last_error


@pytest.mark.parametrize("address", ["100.64.0.1", "10.0.0.5", "169.254.169.254", "fd00::1"])
async def test_a_destination_resolving_to_a_non_public_address_is_rejected_at_once(
    tenant: _Tenant, queue_name: str, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    """Security-policy rejection: validated on the resolved address at
    delivery time (so DNS rebinding is caught), never sent, never retried."""
    sent: list[object] = []
    monkeypatch.setattr(webhooks_service, "_default_resolve_hostname", lambda host: [address])
    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", lambda *a, **k: sent.append(a))
    subscribe(tenant.id, "https://hooks.example.com/x", caller=_PROVISIONING)
    event_id = _trigger(tenant.id)
    await _cycle(queue_name)

    assert sent == []
    row = _row(tenant.id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_DEAD_LETTERED, 1)
    assert row.last_error is not None
    assert row.last_error.startswith("WebhookDestinationRejectedError")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"subscription_id": "not-a-uuid", "event_id": str(uuid.uuid4())},
        {"subscription_id": str(uuid.uuid4()), "event_id": str(uuid.uuid4())},
        {
            "subscription_id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "event_type": "order.created",
            "event_data": "not-an-object",
        },
    ],
    ids=["empty", "bad-uuid", "no-event-type", "event-data-not-object"],
)
async def test_a_malformed_delivery_event_is_dead_lettered_at_once(
    tenant: _Tenant, queue_name: str, payload: dict[str, object]
) -> None:
    with tenant_session_scope(tenant.id) as session:
        event_id = append_event(
            session,
            tenant_id=tenant.id,
            event_type=WEBHOOK_DELIVERY_EVENT_TYPE,
            aggregate_type="webhook_subscription",
            aggregate_id="x",
            payload=payload,
        )
    await _cycle(queue_name)

    row = _row(tenant.id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_DEAD_LETTERED, 1)
    assert row.last_error is not None
    assert row.last_error.startswith("MalformedWebhookEventError")


async def test_a_dead_lettered_delivery_is_never_attempted_again(
    tenant: _Tenant, queue_name: str, reach_local_receiver: None
) -> None:
    with _Receiver(410) as receiver:
        subscribe(tenant.id, receiver.url, caller=_PROVISIONING)
        _trigger(tenant.id)
        await _cycle(queue_name)
        assert claim_due_events(config=_CONFIG, now=datetime.now(UTC) + timedelta(days=365)) == []
    assert len(receiver.received) == 1
