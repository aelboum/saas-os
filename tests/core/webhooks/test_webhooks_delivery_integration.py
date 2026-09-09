"""End-to-end webhook delivery integration tests: real PostgreSQL (the
subscription itself) + real Redis (the `infra.jobs` queue/worker,
docs/IMPLEMENTATION-ROADMAP.md Phase 2.4) + a real local HTTP server
acting as the mock subscriber endpoint (docs/IMPLEMENTATION-ROADMAP.md
Phase 4.3's own Tests requirement: "delivery + retry-on-failure
integration test against a mock endpoint; signature verification test").

Marked `integration` and excluded from the default `pytest` run. Mirrors
`tests/infra/jobs/test_jobs_integration.py`'s structure (uuid-namespaced
queue name, fast retry backoff so this test doesn't spend real wall-clock
time waiting out backoff).

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/core/webhooks/test_webhooks_delivery_integration.py
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import cast

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from core.webhooks.service import compute_signed_envelope, trigger_event
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.jobs.config import JobsConfig
from infra.jobs.dead_letter import count_dead_letters, list_dead_letters
from infra.jobs.queue import build_worker, get_redis_pool, register_job
from sqlalchemy import text

from core.tenancy import create_tenant
from core.webhooks import service as webhooks_service

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

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
            conn.execute(text("SELECT 1 FROM core.webhook_subscriptions LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.webhook_subscriptions not reachable: {exc}. "
            "Run `docker compose up -d db` and `alembic upgrade head` first."
        )
    finally:
        probe_engine.dispose()


@pytest.fixture
def jobs_config() -> JobsConfig:
    return JobsConfig(redis_url=_REDIS_URL, max_tries=2, retry_backoff_base_seconds=0.01)


@pytest.fixture
def queue_name() -> str:
    return f"core-webhooks-phase43-{uuid.uuid4().hex[:8]}"


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


class _MockSubscriberServer:
    """A real local HTTP server standing in for a tenant's webhook
    receiver -- records every request received and returns a
    caller-controlled status code, so tests can assert on exactly what
    was sent (headers, body) and simulate a transient failure.
    """

    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code
        self.received: list[dict[str, object]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler's own naming
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                outer.received.append(
                    {
                        "body": body,
                        "signature": self.headers.get("X-Webhook-Signature"),
                        "timestamp": self.headers.get("X-Webhook-Timestamp"),
                        "content_type": self.headers.get("Content-Type"),
                    }
                )
                self.send_response(outer.status_code)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                pass  # silence stdlib's default request logging in test output

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        # Always a plain (host, port) 2-tuple at runtime -- this server is
        # explicitly bound to an IPv4 address ("127.0.0.1") above, never
        # IPv6, but socketserver's own type stub covers both shapes.
        host, port = self._server.server_address[0], self._server.server_address[1]
        return f"http://{host}:{port}/hook"

    def __enter__(self) -> _MockSubscriberServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    # core.audit_log DELETE is REVOKEd from the restricted runtime role
    # entirely (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4) -- test cleanup
    # must use the privileged migrations role here (subscribe() writes an
    # audit entry, which would otherwise block deleting the tenant via its
    # audit_log.tenant_id foreign key).
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.webhook_subscriptions WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        )
    _admin_delete_audit_log_for_tenant(tenant_id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_id)})


async def test_delivery_sends_a_correctly_signed_event_to_the_mock_endpoint(
    jobs_config: JobsConfig, queue_name: str
) -> None:
    tenant = create_tenant(f"webhooks-delivery-{uuid.uuid4().hex[:8]}")
    try:
        with _MockSubscriberServer(status_code=200) as mock_server:
            _subscription, raw_secret = webhooks_service.subscribe(tenant.id, mock_server.url)

            functions = [register_job(webhooks_service._deliver_webhook, config=jobs_config)]
            worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
            try:
                await trigger_event(
                    tenant.id,
                    "order.created",
                    {"order_id": "abc123"},
                    queue_name=queue_name,
                )
                await worker.main()
            finally:
                await worker.close()

            assert len(mock_server.received) == 1
            received = mock_server.received[0]
            received_body = cast("bytes", received["body"])
            received_timestamp = cast("str | None", received["timestamp"])
            received_signature = cast("str | None", received["signature"])
            decoded_body = json.loads(received_body)
            # P1.10: event_id is generated internally by trigger_event()
            # and not returned to the caller (module docstring) -- a real
            # receiver (and this test) learns it from the signed body
            # itself, never predicts it in advance.
            assert decoded_body["event_type"] == "order.created"
            assert decoded_body["data"] == {"order_id": "abc123"}
            assert uuid.UUID(decoded_body["event_id"])  # a real, well-formed UUID

            assert received_timestamp is not None
            expected_signature = compute_signed_envelope(
                raw_secret, received_body, int(received_timestamp)
            )
            assert received_signature == expected_signature
            assert received["content_type"] == "application/json"
    finally:
        _cleanup_tenant(tenant.id)


async def test_delivery_retries_on_failure_then_dead_letters(
    jobs_config: JobsConfig, queue_name: str
) -> None:
    tenant = create_tenant(f"webhooks-retry-{uuid.uuid4().hex[:8]}")
    try:
        with _MockSubscriberServer(status_code=500) as mock_server:
            webhooks_service.subscribe(tenant.id, mock_server.url)

            functions = [register_job(webhooks_service._deliver_webhook, config=jobs_config)]
            worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
            try:
                pool = await get_redis_pool(jobs_config)
                try:
                    assert await count_dead_letters(pool, jobs_config) == 0
                finally:
                    await pool.aclose()

                await trigger_event(
                    tenant.id,
                    "order.created",
                    {"order_id": "abc123"},
                    queue_name=queue_name,
                )

                # max_tries=2: burst run 1 executes try 1 (mock server
                # returns 500 -> WebhookDeliveryError -> arq.Retry,
                # deferred briefly), burst run 2 executes try 2 (final
                # attempt -> dead-letters).
                await worker.main()
                await asyncio.sleep(0.05)
                await worker.main()
            finally:
                await worker.close()

            assert len(mock_server.received) == 2  # both attempts actually reached the endpoint

            verify_pool = await get_redis_pool(jobs_config)
            try:
                assert await count_dead_letters(verify_pool, jobs_config) == 1
                entries = await list_dead_letters(verify_pool, jobs_config)
                assert entries[0].function_name == "_deliver_webhook"
                assert entries[0].tenant_id == str(tenant.id)
                assert entries[0].attempts == 2
                assert "HTTP 500" in entries[0].error
            finally:
                await verify_pool.delete(jobs_config.dead_letter_key)
                await verify_pool.aclose()
    finally:
        _cleanup_tenant(tenant.id)
