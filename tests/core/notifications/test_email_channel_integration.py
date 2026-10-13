"""P1.12 -- `"email"` notification channel integration tests: real
PostgreSQL (the `Notification` row) + real Redis (the `saas_os.infra.jobs`
queue/worker), mirroring `test_notifications_integration.py`'s own
structure exactly. `saas_os.core.email.send_email`/`get_email_config` are
monkeypatched at the module level (never a real SMTP server, never a
production credential) -- proving the job-handler wiring
(`saas_os/core/notifications/service.py::_send_email_channel`), not
`SmtpEmailProvider` itself (already covered by
`tests/core/email/test_smtp_provider_unit.py`).

Tenant isolation for the `"email"` channel needs no new test: it reuses
the same `Notification` table/model and RLS policy `"in_app"` already
uses, already proven by `test_notifications_isolation_integration.py`.

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/core/notifications/test_email_channel_integration.py
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from sqlalchemy import text

from lifecycle_callers import PROVISIONING
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.email.errors import EmailProviderError
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.notifications import service as notifications_service
from saas_os.core.notifications.service import list_notifications
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import TenantJobPayload, enqueue_job
from saas_os.infra.jobs.config import JobsConfig
from saas_os.infra.jobs.dead_letter import count_dead_letters, list_dead_letters
from saas_os.infra.jobs.queue import build_worker, get_redis_pool, register_tenant_job


def _admin_clear_audit_references(params: object, *, table: str) -> None:
    """Test cleanup only. Core writes its audit evidence in the same
    transaction as every authority change (ADR-0031), and `core.audit_log`
    rows reference `core.tenants`/`core.users` while the runtime role can
    never delete them -- so before a test deletes tenants or users, their
    audit rows are cleared with the privileged migrations role."""
    from sqlalchemy import text

    from saas_os.infra.db.config import get_migrations_database_config
    from saas_os.infra.db.engine import build_engine
    from saas_os.infra.db.session import build_session_factory, session_scope

    raw = params.values() if isinstance(params, dict) else [params]
    values: list[str] = []
    for value in raw:
        items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        values.extend(str(item) for item in items)
    if table == "tenants":
        where = "tenant_id::text = ANY(:v) OR acting_as_tenant_id::text = ANY(:v)"
    else:
        where = "actor_user_id::text = ANY(:v)"
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            # Rows another open transaction already holds (e.g. a teardown that
            # deleted them itself, not yet committed) are being removed by it:
            # skip them rather than wait on that transaction.
            session.execute(
                text(
                    "DELETE FROM core.audit_log WHERE id IN (SELECT id FROM core.audit_log "
                    f"WHERE {where} FOR UPDATE SKIP LOCKED)"
                ),
                {"v": values},
            )
            # ADR-0045 Phase C: lifecycle changes also write platform audit
            # rows, which reference the tenant or the acting user and which
            # the runtime role can never delete.
            platform_where = (
                "target_tenant_id::text = ANY(:v)"
                if table == "tenants"
                else "actor_user_id::text = ANY(:v)"
            )
            # A migration test may be cleaning up below the revision that
            # creates the table.
            if session.execute(text("SELECT to_regclass('core.platform_audit_log')")).scalar():
                session.execute(
                    text(f"DELETE FROM core.platform_audit_log WHERE {platform_where}"),  # noqa: S608
                    {"v": values},
                )
    finally:
        engine.dispose()


_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def _enqueue_dispatch(
    tenant_id: uuid.UUID,
    recipient_user_id: uuid.UUID,
    channel: str,
    body: str,
    *,
    subject: str | None = None,
    recipient_email: str | None = None,
    queue_name: str,
) -> str:
    """Queue the dispatch job directly, with the payload shape
    `dispatch_notification()` records in the outbox (RE-1) -- the address
    encrypted exactly as the producer stores it. Publishing outbox events to
    the queue is the dispatcher's job (RE-2); these tests exercise the job
    handler, so they seed the queue themselves."""
    data: dict[str, object] = {
        "recipient_user_id": str(recipient_user_id),
        "channel": channel,
        "subject": subject,
        "body": body,
    }
    if recipient_email is not None:
        data["recipient_email"] = notifications_service._encrypt_recipient_email(
            tenant_id, recipient_email
        )
    return await enqueue_job(
        notifications_service._dispatch_notification_job.__name__,
        TenantJobPayload(tenant_id=str(tenant_id), data=data),
        queue_name=queue_name,
    )


_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")

    probe_engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.notifications LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.notifications not reachable: {exc}. "
            "Run `docker compose up -d db` and `alembic upgrade head` first."
        )
    finally:
        probe_engine.dispose()


@pytest.fixture
def jobs_config() -> JobsConfig:
    return JobsConfig(redis_url=_REDIS_URL, max_tries=2, retry_backoff_base_seconds=0.01)


@pytest.fixture
def queue_name() -> str:
    return f"core-notifications-email-{uuid.uuid4().hex[:8]}"


@pytest.fixture(autouse=True)
async def _require_reachable_redis(jobs_config: JobsConfig) -> None:
    try:
        pool = await create_pool(RedisSettings.from_dsn(jobs_config.redis_url))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    try:
        await pool.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"Redis not reachable at the configured REDIS_URL "
            f"({jobs_config.redis_url.split('@')[-1]}): {exc}. Run "
            "`docker compose up -d redis` first -- see this file's module docstring."
        )
    finally:
        await pool.aclose()


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(
            f"notif-email-tenant-{uuid.uuid4().hex[:8]}", caller=PROVISIONING
        )
        self.user = create_user()
        add_tenant_membership(self.tenant.id, self.user.id, caller=_PROVISIONING)

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.notifications WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
            _admin_clear_audit_references({"id": str(self.user.id)}, table="users")
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(self.user.id)}
            )
            _admin_clear_audit_references({"id": str(self.tenant.id)}, table="tenants")
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


class _StubEmailConfig:
    def __init__(self, default_sender: str | None) -> None:
        self.default_sender = default_sender


async def test_dispatch_email_notification_end_to_end(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from saas_os.core.email.provider import EmailMessage

    sent_messages: list[EmailMessage] = []

    def _fake_send_email(message, *, provider=None):
        from saas_os.core.email.provider import EmailSendResult

        sent_messages.append(message)
        return EmailSendResult(accepted=True, provider_message_id="fake-1")

    monkeypatch.setattr(
        "saas_os.core.email.get_email_config", lambda: _StubEmailConfig("no-reply@example.com")
    )
    monkeypatch.setattr("saas_os.core.email.send_email", _fake_send_email)

    functions = [
        register_tenant_job(notifications_service._dispatch_notification_job, config=jobs_config)
    ]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        job_id = await _enqueue_dispatch(
            fx.tenant.id,
            fx.user.id,
            "email",
            "Your order has shipped.",
            subject="Order update",
            recipient_email="customer@example.com",
            queue_name=queue_name,
        )
        assert job_id
        await worker.main()
    finally:
        await worker.close()

    assert len(sent_messages) == 1
    assert sent_messages[0].to == ("customer@example.com",)

    notifications = list_notifications(fx.tenant.id, fx.user.id)
    assert len(notifications) == 1
    notification = notifications[0]
    assert notification.channel == "email"
    assert notification.subject == "Order update"
    assert notification.body == "Your order has shipped."
    assert notification.status == "sent"


async def test_email_provider_failure_retries_then_dead_letters_without_persisting(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _failing_send_email(message, *, provider=None):
        raise EmailProviderError("send", "SMTPConnectError")

    monkeypatch.setattr(
        "saas_os.core.email.get_email_config", lambda: _StubEmailConfig("no-reply@example.com")
    )
    monkeypatch.setattr("saas_os.core.email.send_email", _failing_send_email)

    functions = [
        register_tenant_job(notifications_service._dispatch_notification_job, config=jobs_config)
    ]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        pool = await get_redis_pool(jobs_config)
        try:
            assert await count_dead_letters(pool, jobs_config) == 0
        finally:
            await pool.aclose()

        await _enqueue_dispatch(
            fx.tenant.id,
            fx.user.id,
            "email",
            "body",
            recipient_email="customer@example.com",
            queue_name=queue_name,
        )
        await worker.main()
        await asyncio.sleep(0.05)
        await worker.main()
    finally:
        await worker.close()

    verify_pool = await get_redis_pool(jobs_config)
    try:
        assert await count_dead_letters(verify_pool, jobs_config) == 1
        entries = await list_dead_letters(verify_pool, jobs_config)
        assert entries[0].function_name == "_dispatch_notification_job"
        assert entries[0].tenant_id == str(fx.tenant.id)
    finally:
        await verify_pool.delete(jobs_config.dead_letter_key)
        await verify_pool.aclose()

    # Never claim "sent" for a delivery that never happened.
    assert list_notifications(fx.tenant.id, fx.user.id) == []


async def test_missing_default_sender_dead_letters_without_persisting(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("saas_os.core.email.get_email_config", lambda: _StubEmailConfig(None))

    functions = [
        register_tenant_job(notifications_service._dispatch_notification_job, config=jobs_config)
    ]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        await _enqueue_dispatch(
            fx.tenant.id,
            fx.user.id,
            "email",
            "body",
            recipient_email="customer@example.com",
            queue_name=queue_name,
        )
        await worker.main()
        await asyncio.sleep(0.05)
        await worker.main()
    finally:
        await worker.close()

    verify_pool = await get_redis_pool(jobs_config)
    try:
        assert await count_dead_letters(verify_pool, jobs_config) == 1
    finally:
        await verify_pool.delete(jobs_config.dead_letter_key)
        await verify_pool.aclose()

    assert list_notifications(fx.tenant.id, fx.user.id) == []


async def test_email_dispatch_never_logs_recipient_or_body(
    fx: _Fixture,
    jobs_config: JobsConfig,
    queue_name: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def _fake_send_email(message, *, provider=None):
        from saas_os.core.email.provider import EmailSendResult

        return EmailSendResult(accepted=True, provider_message_id="fake-1")

    monkeypatch.setattr(
        "saas_os.core.email.get_email_config", lambda: _StubEmailConfig("no-reply@example.com")
    )
    monkeypatch.setattr("saas_os.core.email.send_email", _fake_send_email)

    secret_recipient = "very-secret-recipient@example.com"
    secret_body = "very secret shipment contents"

    functions = [
        register_tenant_job(notifications_service._dispatch_notification_job, config=jobs_config)
    ]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        with caplog.at_level(logging.INFO):
            await _enqueue_dispatch(
                fx.tenant.id,
                fx.user.id,
                "email",
                secret_body,
                recipient_email=secret_recipient,
                queue_name=queue_name,
            )
            await worker.main()
    finally:
        await worker.close()

    for record in caplog.records:
        message = record.getMessage()
        assert secret_recipient not in message
        assert secret_body not in message
