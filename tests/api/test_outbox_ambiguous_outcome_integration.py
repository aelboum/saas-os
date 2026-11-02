"""Ambiguous outcomes through the durable outbox dispatcher, against real
PostgreSQL and Redis (owner decision of 2026-11-01, ledger row F5;
`docs/architecture/EXTERNAL-OUTCOME-CLASSIFICATION-DESIGN.md`).

A consumer that raises `AmbiguousOutcomeError` never has its event
published. Without a retry policy (SMTP) the event is dead-lettered at once
and no later polling runs it. With `at_least_once` (webhooks) it is retried
within the attempt budget, on the same `event_id`, and dead-lettered when
the budget runs out. With `retry_within` (Resend with an `Idempotency-Key`)
it is retried with the same key and byte-identical body only while the
retry is due before `created_at + 23 h`; a retry still pending after that
is dead-lettered instead of running. The real notification e-mail step and
the real providers run against scripted local servers
(`tests/support/smtp_fault_server.py`, `tests/support/resend_fault_server.py`).

Owner decision D of 2026-11-01: a bare timeout that escapes a consumer
unclassified (`TimeoutError`, its subclasses, an `httpx` timeout) is
ambiguous with no retry policy -- dead-lettered, never polled again,
replayable -- and a consumer's explicit `ConfirmedNotSentError` keeps the
ordinary retry. SaaS OS's own consumers say "not sent" explicitly where
their transport knows it (a refused connection), so they keep retrying.

Each test uses its own tenants and scopes the dispatcher's tenant
enumeration to them; every row it creates is removed afterwards.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import ssl
import uuid
from collections.abc import Awaitable, Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.api.outbox_dispatcher as outbox_dispatcher
import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from egress_support import PUBLIC_V4, LocalServer, MappingBackend, mapped_transport_factory
from egress_support import read_request as read_http_request
from lifecycle_callers import PROVISIONING
from resend_fault_server import FakeResend
from saas_os.api.outbox_dispatcher import OUTBOX_JOB_FUNCTIONS, _run_outbox_event
from saas_os.core.email import service as email_service
from saas_os.core.email.config import EmailConfig
from saas_os.core.email.provider import EmailProvider
from saas_os.core.email.smtp_provider import SmtpEmailProvider
from saas_os.core.notifications import service as notifications_service
from saas_os.core.outbox import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    AmbiguousOutcomeError,
    ConfirmedNotSentError,
    OutboxDispatchConfig,
    OutboxEvent,
    append_event,
    begin_event_execution,
    claim_due_events,
)
from saas_os.core.outbox.dispatch import record_ambiguous_outcome
from saas_os.core.tenancy import create_tenant, list_open_tenant_ids
from saas_os.core.webhooks import service as webhooks_service
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.egress import Deadline
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload, build_worker
from saas_os.infra.jobs.queue import get_redis_pool
from saas_os.infra.secrets.provider import SecretsProvider
from smtp_fault_server import ScriptedSmtpServer, closed_port

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_EVENT_TYPE = "test.ambiguous"
_SENDER = "no-reply@mail.example.com"
_CONFIG = OutboxDispatchConfig(
    max_attempts=3, retry_jitter_ratio=0, lease_seconds=300, retry_base_seconds=60
)

Handler = Callable[[TenantJobContext, TenantJobPayload], Awaitable[None]]


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
        tenant_id = create_tenant(f"f5-amb-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
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


def _append(tenant_id: uuid.UUID, payload: dict[str, object] | None = None) -> uuid.UUID:
    with tenant_session_scope(tenant_id) as session:
        return append_event(
            session,
            tenant_id=tenant_id,
            event_type=_EVENT_TYPE,
            aggregate_type="test",
            aggregate_id="f5",
            payload=payload or {},
        )


def _row(tenant_id: uuid.UUID, event_id: uuid.UUID) -> OutboxEvent:
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(select(OutboxEvent).where(OutboxEvent.id == event_id)).scalar_one()
        session.expunge(row)
        return row


def _handle_with(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> None:
    monkeypatch.setattr(outbox_dispatcher, "outbox_event_handlers", lambda: {_EVENT_TYPE: handler})


async def _run_once(
    tenant_id: uuid.UUID, event_id: uuid.UUID, *, at: datetime | None = None
) -> None:
    """Claim the event (as a polling cycle at `at` would) and run it."""
    at = at or datetime.now(UTC) + timedelta(seconds=1)
    (claim,) = [c for c in claim_due_events(config=_CONFIG, now=at) if c.id == event_id]
    await _run_outbox_event(
        TenantJobContext(tenant_id=tenant_id),
        TenantJobPayload(
            tenant_id=str(tenant_id),
            data={"outbox_event_id": str(event_id), "claim_token": str(claim.claim_token)},
        ),
    )


def _never_claimed_again(event_id: uuid.UUID) -> None:
    for days in (1, 2, 30):
        later = datetime.now(UTC) + timedelta(days=days)
        assert [c for c in claim_due_events(config=_CONFIG, now=later) if c.id == event_id] == []


@pytest.fixture(autouse=True)
def _dispatch_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dispatch, "get_outbox_dispatch_config", lambda: _CONFIG)


# --- The dispatcher's three policies -------------------------------------------


async def test_without_a_policy_the_event_is_dead_lettered_and_never_polled_again(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    runs: list[int] = []

    async def ambiguous(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        runs.append(1)
        raise AmbiguousOutcomeError("read_timeout", phase="read")

    _handle_with(monkeypatch, ambiguous)
    await _run_once(tenant_id, event_id)

    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.claim_token is None and row.published_at is None
    assert row.attempts == 1
    assert row.last_error == (
        "OutcomeUnknown: read_timeout (read); not retried automatically. "
        "Check the destination, then replay (saas-os-operator replay-outbox-events)."
    )
    _never_claimed_again(event_id)
    queue = f"f5-amb-{uuid.uuid4().hex[:8]}"
    worker = build_worker(OUTBOX_JOB_FUNCTIONS, burst=True, queue_name=queue)
    try:
        await worker.main()
    finally:
        await worker.close()
    assert runs == [1]


async def test_at_least_once_is_retried_and_dead_lettered_when_attempts_run_out(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)

    async def ambiguous(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        raise AmbiguousOutcomeError("ReadTimeout", phase="read", at_least_once=True)

    _handle_with(monkeypatch, ambiguous)
    at = datetime.now(UTC) + timedelta(seconds=1)
    for attempt in (1, 2):
        await _run_once(tenant_id, event_id, at=at)
        row = _row(tenant_id, event_id)
        assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_PENDING, attempt, None)
        assert row.last_error is not None and row.last_error.startswith(
            "OutcomeUnknown: ReadTimeout (read); retried: at-least-once"
        )
        at = row.next_attempt_at + timedelta(seconds=1)
    await _run_once(tenant_id, event_id, at=at)
    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts, row.published_at) == (OUTBOX_STATUS_DEAD_LETTERED, 3, None)
    _never_claimed_again(event_id)


async def test_an_idempotency_window_retries_until_its_deadline_then_dead_letters(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    outcomes: list[BaseException] = [
        AmbiguousOutcomeError("read_timeout", phase="read", retry_within=timedelta(hours=1)),
        RuntimeError("connect_failed"),  # a later, ordinary failure
    ]
    runs: list[int] = []

    async def scripted(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        runs.append(1)
        raise outcomes[len(runs) - 1]

    _handle_with(monkeypatch, scripted)
    await _run_once(tenant_id, event_id)
    row = _row(tenant_id, event_id)
    deadline = row.created_at + timedelta(hours=1)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.last_error is not None
    assert row.last_error.startswith(
        "OutcomeUnknown: read_timeout (read); retried with the same idempotency key"
    )
    recorded = dispatch._retry_deadline(row.last_error)  # pyright: ignore[reportPrivateUsage]
    assert recorded is not None and deadline - timedelta(seconds=1) < recorded <= deadline

    await _run_once(tenant_id, event_id, at=row.next_attempt_at + timedelta(seconds=1))
    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_PENDING
    # The ordinary failure did not erase the deadline.
    assert row.last_error is not None and row.last_error.startswith("RuntimeError: connect_failed")
    assert dispatch._retry_deadline(row.last_error) == recorded  # pyright: ignore[reportPrivateUsage]

    # The third attempt comes due only after the deadline (a dispatcher
    # outage): it is dead-lettered instead of running.
    late = recorded + timedelta(seconds=1)
    (claim,) = [c for c in claim_due_events(config=_CONFIG, now=late) if c.id == event_id]
    assert begin_event_execution(tenant_id, event_id, claim.claim_token, now=late) is None
    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error is not None and row.last_error.startswith(
        "OutcomeUnknown: the idempotency window closed before the retry ran"
    )
    assert runs == [1, 1]
    _never_claimed_again(event_id)


async def test_an_ambiguous_outcome_after_the_window_is_dead_lettered_at_once(
    tenants: _Tenants,
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    created = _row(tenant_id, event_id).created_at
    error = AmbiguousOutcomeError("read_timeout", phase="read", retry_within=timedelta(hours=23))
    # Due now, failing 22 h 59 min 30 s after creation: the 60 s backoff would
    # put the retry past the window, so it is not scheduled.
    at = created + timedelta(hours=23) - timedelta(seconds=30)
    (claim,) = [c for c in claim_due_events(config=_CONFIG, now=at) if c.id == event_id]
    status = record_ambiguous_outcome(tenant_id, event_id, claim.claim_token, error, now=at)
    assert status == OUTBOX_STATUS_DEAD_LETTERED
    row = _row(tenant_id, event_id)
    assert row.last_error is not None and row.last_error.startswith(
        "OutcomeUnknown: read_timeout (read); idempotency window closed; not retried"
    )


async def test_an_idempotency_window_still_respects_the_attempt_budget(
    tenants: _Tenants,
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    error = AmbiguousOutcomeError("read_timeout", phase="read", retry_within=timedelta(hours=23))
    at = datetime.now(UTC) + timedelta(seconds=1)
    for _ in range(3):
        (claim,) = [c for c in claim_due_events(config=_CONFIG, now=at) if c.id == event_id]
        status = record_ambiguous_outcome(tenant_id, event_id, claim.claim_token, error, now=at)
        at = _row(tenant_id, event_id).next_attempt_at + timedelta(seconds=1)
    assert status == OUTBOX_STATUS_DEAD_LETTERED
    row = _row(tenant_id, event_id)
    assert row.attempts == 3
    assert row.last_error is not None and "attempts exhausted" in row.last_error


async def test_an_outcome_is_recorded_only_under_the_events_own_tenant(
    tenants: _Tenants,
) -> None:
    tenant_a, tenant_b = tenants.new(), tenants.new()
    event_a = _append(tenant_a)
    event_b = _append(tenant_b)
    at = datetime.now(UTC) + timedelta(seconds=1)
    claims = {c.id: c for c in claim_due_events(config=_CONFIG, now=at)}
    error = AmbiguousOutcomeError("read_timeout", phase="read")
    # Tenant B's scope cannot see, let alone change, tenant A's event.
    assert (
        record_ambiguous_outcome(tenant_b, event_a, claims[event_a].claim_token, error, now=at)
        is None
    )
    assert _row(tenant_a, event_a).status == OUTBOX_STATUS_PENDING
    assert _row(tenant_a, event_a).claim_token == claims[event_a].claim_token
    assert (
        record_ambiguous_outcome(tenant_a, event_a, claims[event_a].claim_token, error, now=at)
        == OUTBOX_STATUS_DEAD_LETTERED
    )
    row_b = _row(tenant_b, event_b)
    assert (row_b.status, row_b.last_error) == (OUTBOX_STATUS_PENDING, None)


# --- Real consumers against scripted servers ------------------------------------


class _NoSecrets(SecretsProvider):
    def get(self, name: str) -> str | None:
        return None


def _use_provider(monkeypatch: pytest.MonkeyPatch, provider: EmailProvider) -> None:
    monkeypatch.setenv("EMAIL_DEFAULT_SENDER", _SENDER)
    monkeypatch.setattr(email_service, "_default_provider", lambda: provider)


async def _send_email_step(context: TenantJobContext, _payload: TenantJobPayload) -> None:
    """The notification job's real e-mail step (`_send_email_channel`), keyed
    by the outbox event id exactly as `_dispatch_notification_job` calls it."""
    await asyncio.to_thread(
        notifications_service._send_email_channel,  # pyright: ignore[reportPrivateUsage]
        uuid.uuid4(),
        "subject",
        "body-canary-text",
        "recipient-canary@example.com",
        context.event_id,
    )


async def test_an_smtp_disconnect_after_the_data_is_dead_lettered_and_never_resent(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    monkeypatch.setattr("saas_os.core.email.smtp_provider.get_secrets_provider", _NoSecrets)
    with ScriptedSmtpServer("drop_after_data_end") as server:
        _use_provider(
            monkeypatch,
            SmtpEmailProvider(
                config=EmailConfig(smtp_host="127.0.0.1", smtp_port=server.port, tls_mode="none")
            ),
        )
        _handle_with(monkeypatch, _send_email_step)
        await _run_once(tenant_id, event_id)
        row = _row(tenant_id, event_id)
        assert row.status == OUTBOX_STATUS_DEAD_LETTERED
        assert row.last_error is not None
        assert row.last_error.startswith(
            "OutcomeUnknown: SMTPServerDisconnected (data); not retried automatically"
        )
        assert "recipient-canary" not in row.last_error and "body-canary" not in row.last_error
        _never_claimed_again(event_id)
        assert (server.connections, server.messages_received) == (1, 1)


async def test_a_resend_retry_within_the_window_sends_the_same_key_and_bytes(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    monkeypatch.setattr(
        "saas_os.core.email.resend_provider.get_secrets_provider",
        lambda: _Key(),
    )
    async with FakeResend(["drop_after_read", "ok"], tmp_path) as fake:
        _use_provider(monkeypatch, fake.provider())
        _handle_with(monkeypatch, _send_email_step)
        await _run_once(tenant_id, event_id)
        row = _row(tenant_id, event_id)
        assert row.status == OUTBOX_STATUS_PENDING
        assert row.last_error is not None and row.last_error.startswith(
            "OutcomeUnknown: exchange_failed (exchange); retried with the same idempotency key"
        )
        await _run_once(tenant_id, event_id, at=row.next_attempt_at + timedelta(seconds=1))
        row = _row(tenant_id, event_id)
        assert row.status == OUTBOX_STATUS_PUBLISHED
        (key_1, body_1), (key_2, body_2) = fake.requests
        assert key_1 is not None and key_1 == key_2
        assert body_1 == body_2
        assert json.loads(body_1)["headers"]["Message-ID"].startswith(f"<notification.{event_id}@")
        assert fake.deliveries == 1


async def test_a_resend_retry_due_after_the_window_never_reaches_resend(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    monkeypatch.setattr("saas_os.core.email.resend_provider.get_secrets_provider", lambda: _Key())
    async with FakeResend(["drop_after_read", "ok"], tmp_path) as fake:
        _use_provider(monkeypatch, fake.provider())
        _handle_with(monkeypatch, _send_email_step)
        await _run_once(tenant_id, event_id)
        created = _row(tenant_id, event_id).created_at
        late = created + timedelta(hours=23, seconds=1)
        (claim,) = [c for c in claim_due_events(config=_CONFIG, now=late) if c.id == event_id]
        assert begin_event_execution(tenant_id, event_id, claim.claim_token, now=late) is None
        assert _row(tenant_id, event_id).status == OUTBOX_STATUS_DEAD_LETTERED
        assert len(fake.requests) == 1
        _never_claimed_again(event_id)


async def test_a_resend_send_without_a_key_is_dead_lettered(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    monkeypatch.setattr("saas_os.core.email.resend_provider.get_secrets_provider", lambda: _Key())

    async def unkeyed(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        await asyncio.to_thread(
            notifications_service._send_email_channel,  # pyright: ignore[reportPrivateUsage]
            uuid.uuid4(),
            "subject",
            "body",
            "recipient@example.com",
            None,  # no event identity: no Idempotency-Key
        )

    async with FakeResend(["drop_after_read", "ok"], tmp_path) as fake:
        _use_provider(monkeypatch, fake.provider())
        _handle_with(monkeypatch, unkeyed)
        await _run_once(tenant_id, event_id)
        assert fake.requests[0][0] is None
    row = _row(tenant_id, event_id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error is not None and "not retried automatically" in row.last_error
    _never_claimed_again(event_id)


async def test_a_resend_retry_whose_body_changed_is_dead_lettered_not_resent(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    monkeypatch.setattr("saas_os.core.email.resend_provider.get_secrets_provider", lambda: _Key())
    async with FakeResend(["drop_after_read", "ok"], tmp_path) as fake:
        _use_provider(monkeypatch, fake.provider())
        _handle_with(monkeypatch, _send_email_step)
        await _run_once(tenant_id, event_id)
        # The operator changes the sender's local part between the attempts.
        monkeypatch.setenv("EMAIL_DEFAULT_SENDER", "alerts@mail.example.com")
        row = _row(tenant_id, event_id)
        await _run_once(tenant_id, event_id, at=row.next_attempt_at + timedelta(seconds=1))
        row = _row(tenant_id, event_id)
        assert row.status == OUTBOX_STATUS_DEAD_LETTERED
        assert row.last_error is not None and "EmailProviderError" in row.last_error
        (key_1, body_1), (key_2, body_2) = fake.requests
        assert key_1 == key_2 and body_1 != body_2
        assert fake.deliveries == 1


class _Key(SecretsProvider):
    def get(self, name: str) -> str | None:
        fake = "re_fake_integration_key"  # pragma: allowlist secret
        return fake if name == "RESEND_API_KEY" else None


async def test_a_webhook_ambiguous_delivery_is_retried_on_the_same_event_id(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every attempt reaches the receiver with the same `event_id` in the
    signed body (at-least-once); none is recorded as delivered, and the event
    is dead-lettered when the attempts run out."""
    tenant_id = tenants.new()
    webhook_event_id = str(uuid.uuid4())
    event_id = _append(tenant_id, {"event_id": webhook_event_id})
    bodies: list[bytes] = []

    async def read_then_close(reader: asyncio.StreamReader, _w: asyncio.StreamWriter) -> None:
        bodies.append(await read_http_request(server, reader))

    server = LocalServer(read_then_close)
    await server.__aenter__()
    try:
        factory = mapped_transport_factory(MappingBackend(server.port))
        real_client = httpx.AsyncClient

        def client(**options: object) -> httpx.AsyncClient:
            return real_client(transport=factory(ssl.create_default_context()), **options)  # type: ignore[arg-type]

        monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", client)
        monkeypatch.delenv("EGRESS_PROXY_URL", raising=False)

        async def deliver(_ctx: TenantJobContext, payload: TenantJobPayload) -> None:
            body = webhooks_service._encode_event(  # pyright: ignore[reportPrivateUsage]
                uuid.UUID(str(payload.data["event_id"])), "test.happened", {}
            )
            await webhooks_service._post_to_validated_addresses(  # pyright: ignore[reportPrivateUsage]
                uuid.uuid4(),
                "http://hooks.example.test/hook",
                [ipaddress.ip_address(PUBLIC_V4)],
                body,
                {"Content-Type": "application/json"},
                Deadline.after(5),
            )

        _handle_with(monkeypatch, deliver)
        at = datetime.now(UTC) + timedelta(seconds=1)
        for _ in range(3):
            await _run_once(tenant_id, event_id, at=at)
            at = _row(tenant_id, event_id).next_attempt_at + timedelta(seconds=1)
    finally:
        await server.__aexit__()

    assert len(bodies) == 3
    assert {json.loads(b)["event_id"] for b in bodies} == {webhook_event_id}
    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts, row.published_at) == (OUTBOX_STATUS_DEAD_LETTERED, 3, None)
    assert row.last_error is not None and "at-least-once" in row.last_error


# --- Decision D: bare timeouts and explicit "not sent" ----------------------------

_OUTCOME_UNKNOWN_HINT = (
    "not retried automatically. "
    "Check the destination, then replay (saas-os-operator replay-outbox-events)."
)


class _ProductTimeout(asyncio.TimeoutError):  # noqa: UP041 -- the alias is the point
    """A product client's own timeout class, escaping unclassified."""


class _NotSentTimeout(ConfirmedNotSentError, TimeoutError):
    """A product's connect timeout, classified explicitly as not sent."""


def _read_timeout() -> Exception:
    return httpx.ReadTimeout("read", request=httpx.Request("POST", "https://canary.example/x"))


@pytest.mark.parametrize(
    ("make", "name"),
    [
        (lambda: TimeoutError("https://canary.example/x"), "TimeoutError"),
        (lambda: _ProductTimeout("https://canary.example/x"), "_ProductTimeout"),
        (_read_timeout, "ReadTimeout"),
    ],
    ids=["TimeoutError", "asyncio-subclass", "httpx-ReadTimeout"],
)
async def test_a_bare_timeout_is_dead_lettered_as_unknown_and_never_polled_again(
    tenants: _Tenants,
    monkeypatch: pytest.MonkeyPatch,
    make: Callable[[], Exception],
    name: str,
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    runs: list[int] = []

    async def times_out(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        runs.append(1)
        raise make()

    _handle_with(monkeypatch, times_out)
    await _run_once(tenant_id, event_id)

    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_DEAD_LETTERED, 1, None)
    assert row.published_at is None
    assert row.last_error == f"OutcomeUnknown: {name} (unclassified); {_OUTCOME_UNKNOWN_HINT}"
    _never_claimed_again(event_id)
    queue = f"f5-amb-{uuid.uuid4().hex[:8]}"
    worker = build_worker(OUTBOX_JOB_FUNCTIONS, burst=True, queue_name=queue)
    try:
        await worker.main()
    finally:
        await worker.close()
    assert runs == [1]


async def test_an_explicit_not_sent_timeout_keeps_the_ordinary_retry(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    runs: list[int] = []

    async def not_sent(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        runs.append(1)
        raise _NotSentTimeout("connect_timeout")

    _handle_with(monkeypatch, not_sent)
    at = datetime.now(UTC) + timedelta(seconds=1)
    for attempt in (1, 2):
        await _run_once(tenant_id, event_id, at=at)
        row = _row(tenant_id, event_id)
        assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_PENDING, attempt, None)
        assert row.last_error == "_NotSentTimeout: connect_timeout"
        assert row.next_attempt_at > at
        at = row.next_attempt_at + timedelta(seconds=1)
    await _run_once(tenant_id, event_id, at=at)
    row = _row(tenant_id, event_id)
    # The ordinary budget: dead-lettered when the attempts run out, as before.
    assert (row.status, row.attempts) == (OUTBOX_STATUS_DEAD_LETTERED, 3)
    assert row.last_error == "_NotSentTimeout: connect_timeout"
    assert runs == [1, 1, 1]


async def test_an_smtp_refused_connection_keeps_retrying(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    monkeypatch.setattr("saas_os.core.email.smtp_provider.get_secrets_provider", _NoSecrets)
    _use_provider(
        monkeypatch,
        SmtpEmailProvider(
            config=EmailConfig(smtp_host="127.0.0.1", smtp_port=closed_port(), tls_mode="none")
        ),
    )
    _handle_with(monkeypatch, _send_email_step)
    await _run_once(tenant_id, event_id)
    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_PENDING, 1, None)
    assert row.last_error is not None
    assert row.last_error.startswith("NotificationNotSentDispatchError:")


async def test_a_resend_send_refused_before_sending_keeps_retrying(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    monkeypatch.setattr("saas_os.core.email.resend_provider.get_secrets_provider", lambda: _Key())
    async with FakeResend(["ok"], tmp_path) as fake:
        _use_provider(monkeypatch, fake.provider(port=closed_port()))
        _handle_with(monkeypatch, _send_email_step)
        await _run_once(tenant_id, event_id)
        assert fake.requests == []
    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_PENDING, 1, None)
    assert row.last_error is not None
    assert row.last_error.startswith("NotificationNotSentDispatchError:")


async def test_a_webhook_refused_connection_keeps_retrying(
    tenants: _Tenants, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    factory = mapped_transport_factory(MappingBackend(closed_port()))
    real_client = httpx.AsyncClient

    def client(**options: object) -> httpx.AsyncClient:
        return real_client(transport=factory(ssl.create_default_context()), **options)  # type: ignore[arg-type]

    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", client)
    monkeypatch.delenv("EGRESS_PROXY_URL", raising=False)

    async def deliver(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        await webhooks_service._post_to_validated_addresses(  # pyright: ignore[reportPrivateUsage]
            uuid.uuid4(),
            "http://hooks.example.test/hook",
            [ipaddress.ip_address(PUBLIC_V4)],
            b"{}",
            {"Content-Type": "application/json"},
            Deadline.after(5),
        )

    _handle_with(monkeypatch, deliver)
    await _run_once(tenant_id, event_id)
    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_PENDING, 1, None)
    assert row.last_error is not None
    assert row.last_error.startswith("WebhookNotSentError:")
    assert row.last_error.endswith("failed: ConnectError")


# --- Owner decision of 2026-11-02: other exceptions keep the ordinary retry ----


def _serialization_failure(tenant_id: uuid.UUID) -> None:
    """A real SQLSTATE 40001 from PostgreSQL, as SQLAlchemy raises it."""
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DO $$ BEGIN RAISE EXCEPTION 'conflict' USING ERRCODE = '40001'; END $$")
        )


def _statement_timeout(tenant_id: uuid.UUID) -> None:
    """A real `statement_timeout` cancellation (SQLSTATE 57014)."""
    with tenant_session_scope(tenant_id) as session:
        session.execute(text("SET LOCAL statement_timeout = 10"))
        session.execute(text("SELECT pg_sleep(2)"))


@pytest.mark.parametrize(
    ("fail", "driver_error"),
    [(_serialization_failure, "SerializationFailure"), (_statement_timeout, "QueryCanceled")],
    ids=["serialization-failure", "statement-timeout"],
)
async def test_a_transient_database_error_keeps_the_ordinary_retry_and_is_not_unknown(
    tenants: _Tenants,
    monkeypatch: pytest.MonkeyPatch,
    fail: Callable[[uuid.UUID], None],
    driver_error: str,
) -> None:
    """A database error escaping a consumer is not a timeout of an external
    request -- even `statement_timeout`, which SQLAlchemy raises as an
    `OperationalError`, not a `TimeoutError` -- so it is retried with the
    ordinary backoff and dead-lettered only when the attempts run out, never
    as `OutcomeUnknown`."""
    tenant_id = tenants.new()
    event_id = _append(tenant_id)
    seen: list[str] = []

    async def database_fails(ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        try:
            fail(ctx.tenant_id)
        except OperationalError as exc:
            seen.append(type(exc.orig).__name__)
            raise

    _handle_with(monkeypatch, database_fails)
    at = datetime.now(UTC) + timedelta(seconds=1)
    for attempt in (1, 2):
        await _run_once(tenant_id, event_id, at=at)
        row = _row(tenant_id, event_id)
        assert (row.status, row.attempts, row.claim_token) == (OUTBOX_STATUS_PENDING, attempt, None)
        assert row.last_error is not None
        assert row.last_error.startswith("OperationalError:")
        assert row.next_attempt_at > at
        at = row.next_attempt_at + timedelta(seconds=1)
    await _run_once(tenant_id, event_id, at=at)
    row = _row(tenant_id, event_id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_DEAD_LETTERED, 3)
    assert row.last_error is not None
    assert row.last_error.startswith("OperationalError:")
    assert "OutcomeUnknown" not in row.last_error
    assert row.published_at is None
    assert seen == [driver_error] * 3
