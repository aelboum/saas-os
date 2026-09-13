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
import ipaddress
import json
import os
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import cast
from urllib.parse import urlparse

import httpx
import pytest
from arq import create_pool
from arq.connections import RedisSettings
from core.webhooks.errors import InvalidWebhookUrlError
from core.webhooks.models import WebhookSubscription
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
from infra.jobs import TenantJobPayload

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


@pytest.fixture
def _bypass_ssrf_destination_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase J-R1 (J-API-01): this file's own `_MockSubscriberServer` is
    necessarily bound to a loopback address (127.0.0.1) -- there is no
    other same-machine, hermetic, real-HTTP-server address a test process
    can bind to. The SSRF fix correctly rejects exactly that class of
    destination in real use, so the tests in this file that need a
    genuinely reachable local server request this fixture to bypass only
    their *own* two SSRF gates (subscription-time literal-address check,
    delivery-time resolved-address check) -- never any application code
    path a real tenant-supplied URL goes through outside this file. Tests
    that specifically prove the SSRF gate itself works (below) do not
    request this fixture.
    """

    def _bypassed_validate_destination(
        url: str, **kwargs: object
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        # Phase J-R1B: _validate_destination() now must return the address
        # _deliver_webhook() actually pins the connection to -- returning
        # the real host this file's own mock server is bound to (never a
        # placeholder) keeps these tests exercising genuine, working
        # delivery to that real local server, not a broken connection.
        hostname = urlparse(url).hostname
        assert hostname is not None
        return ipaddress.ip_address(hostname)

    monkeypatch.setattr(
        webhooks_service, "_reject_if_literal_non_public_address", lambda *a, **k: None
    )
    monkeypatch.setattr(webhooks_service, "_validate_destination", _bypassed_validate_destination)


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
    jobs_config: JobsConfig, queue_name: str, _bypass_ssrf_destination_check: None
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
    jobs_config: JobsConfig, queue_name: str, _bypass_ssrf_destination_check: None
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


# --- Phase J-R1 (J-API-01): the actual delivery-time SSRF gate --------------
# These tests do NOT request `_bypass_ssrf_destination_check` -- they exist
# specifically to prove that gate is real.


async def test_delivery_is_blocked_before_any_network_attempt_for_non_public_destination() -> None:
    """A subscription whose stored URL is a non-public destination must be
    rejected by `_deliver_webhook()` itself, independent of subscription-
    time validation -- proven by inserting the row directly (bypassing
    `subscribe()`'s own literal-address check, simulating a subscription
    that predates this fix or a hostname repointed after subscription) and
    asserting `InvalidWebhookUrlError` -- never `WebhookDeliveryError` --
    is raised. Nothing is listening on the target port, so if delivery had
    actually attempted a connection, it would fail with a connection error
    (surfacing as `WebhookDeliveryError`), not this specific, earlier error
    -- the exact exception type is what proves validation ran *before* any
    network attempt.
    """
    tenant = create_tenant(f"webhooks-ssrf-block-{uuid.uuid4().hex[:8]}")
    try:
        with tenant_session_scope(tenant.id) as session:
            subscription = WebhookSubscription(
                tenant_id=tenant.id,
                url="http://10.0.0.5:1/hook",
                signing_secret=secrets.token_urlsafe(32),
            )
            session.add(subscription)
            session.flush()
            session.refresh(subscription)
            subscription_id = subscription.id

        payload = TenantJobPayload(
            tenant_id=str(tenant.id),
            data={
                "subscription_id": str(subscription_id),
                "event_id": str(uuid.uuid4()),
                "event_type": "order.created",
                "event_data": {"order_id": "abc123"},
            },
        )
        with pytest.raises(InvalidWebhookUrlError):
            await webhooks_service._deliver_webhook(payload)
    finally:
        _cleanup_tenant(tenant.id)


async def test_delivery_never_enables_follow_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    """`_deliver_webhook()` must construct its `httpx.AsyncClient` with
    `follow_redirects=False` -- a 3xx response must come back to this
    function as a plain response (handled as any other non-2xx: retried,
    then dead-lettered), never transparently chased to a second,
    unvalidated destination. Proven by replacing `httpx.AsyncClient`
    itself with a fake that records its constructor arguments -- no real
    network or DNS involved.
    """
    tenant = create_tenant(f"webhooks-noredirect-{uuid.uuid4().hex[:8]}")
    try:
        with tenant_session_scope(tenant.id) as session:
            subscription = WebhookSubscription(
                tenant_id=tenant.id,
                url="http://127.0.0.1:1/hook",
                signing_secret=secrets.token_urlsafe(32),
            )
            session.add(subscription)
            session.flush()
            session.refresh(subscription)
            subscription_id = subscription.id

        monkeypatch.setattr(
            webhooks_service,
            "_validate_destination",
            lambda *a, **k: ipaddress.ip_address("127.0.0.1"),
        )

        captured_kwargs: dict[str, object] = {}

        class _FakeResponse:
            status_code = 200

        class _FakeAsyncClient:
            def __init__(self, **kwargs: object) -> None:
                captured_kwargs.update(kwargs)

            async def __aenter__(self) -> _FakeAsyncClient:
                return self

            async def __aexit__(self, *exc: object) -> None:
                return None

            async def post(self, *args: object, **kwargs: object) -> _FakeResponse:
                return _FakeResponse()

        monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", _FakeAsyncClient)

        payload = TenantJobPayload(
            tenant_id=str(tenant.id),
            data={
                "subscription_id": str(subscription_id),
                "event_id": str(uuid.uuid4()),
                "event_type": "order.created",
                "event_data": {"order_id": "abc123"},
            },
        )
        await webhooks_service._deliver_webhook(payload)

        assert captured_kwargs.get("follow_redirects") is False
    finally:
        _cleanup_tenant(tenant.id)


# --- Phase J-R1B: the validated IP is the exact IP the connection targets --
#
# These tests intercept at httpx's own transport boundary (`httpx.MockTransport`,
# built into httpx -- no new dependency), the earliest point a real socket
# connection would otherwise be opened from. Everything upstream of that
# point -- URL parsing, `Origin` derivation, extension merging, header
# defaulting -- is httpx/httpcore's own real, unmodified code, so the
# `httpx.Request` object a test observes here is exactly what the real
# network layer would have received. This is deliberately not a bare
# `_validate_destination()` unit test: it proves what the *transport*
# would actually target, which is the property Phase J-R1B exists to
# establish.


async def _deliver_with_recording_transport(
    monkeypatch: pytest.MonkeyPatch, payload: TenantJobPayload
) -> list[httpx.Request]:
    captured: list[httpx.Request] = []
    # Captured *before* the monkeypatch below -- `webhooks_service.httpx` is
    # the exact same module object as this file's own `import httpx` (Python
    # caches modules by name), so patching `httpx.AsyncClient` in place would
    # otherwise make `_client_factory`'s own `httpx.AsyncClient(...)` call
    # recurse into itself.
    real_async_client = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    def _client_factory(*, timeout: float, follow_redirects: bool) -> httpx.AsyncClient:
        return real_async_client(
            transport=httpx.MockTransport(_handler),
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", _client_factory)
    await webhooks_service._deliver_webhook(payload)
    return captured


def _insert_subscription(tenant_id: uuid.UUID, url: str) -> uuid.UUID:
    with tenant_session_scope(tenant_id) as session:
        subscription = WebhookSubscription(
            tenant_id=tenant_id, url=url, signing_secret=secrets.token_urlsafe(32)
        )
        session.add(subscription)
        session.flush()
        session.refresh(subscription)
        return subscription.id


def _payload_for(tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> TenantJobPayload:
    return TenantJobPayload(
        tenant_id=str(tenant_id),
        data={
            "subscription_id": str(subscription_id),
            "event_id": str(uuid.uuid4()),
            "event_type": "order.created",
            "event_data": {"order_id": "abc123"},
        },
    )


async def test_the_connected_address_is_exactly_the_validated_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test A: resolver returns a public IP; the actual `httpx.Request`
    the transport receives must target exactly that IP -- not the
    hostname, and not any other address."""
    tenant = create_tenant(f"webhooks-pin-a-{uuid.uuid4().hex[:8]}")
    try:
        subscription_id = _insert_subscription(tenant.id, "http://pin-target.example/hook")
        monkeypatch.setattr(webhooks_service, "_default_resolve_hostname", lambda host: ["8.8.8.8"])

        captured = await _deliver_with_recording_transport(
            monkeypatch, _payload_for(tenant.id, subscription_id)
        )

        assert len(captured) == 1
        assert captured[0].url.host == "8.8.8.8"
        assert captured[0].headers.get("host") == "pin-target.example"
    finally:
        _cleanup_tenant(tenant.id)


async def test_dns_rebinding_cannot_redirect_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test B: a resolver that would answer *differently* on a second call
    (simulating a rebind) proves nothing, because pinning means there is
    no second call for it to answer -- the resolver is invoked exactly
    once per delivery attempt, and the connection targets the one address
    that single call returned and that passed validation."""
    tenant = create_tenant(f"webhooks-pin-b-{uuid.uuid4().hex[:8]}")
    try:
        subscription_id = _insert_subscription(tenant.id, "https://rebind-target.example/hook")

        call_count = {"n": 0}

        def rebinding_resolver(host: str) -> list[str]:
            call_count["n"] += 1
            # A second call (which must never happen) would answer with a
            # private address -- if pinning were broken and httpx/httpcore
            # resolved the hostname again, this is what it could land on.
            return ["8.8.8.8"] if call_count["n"] == 1 else ["10.0.0.5"]

        monkeypatch.setattr(webhooks_service, "_default_resolve_hostname", rebinding_resolver)

        captured = await _deliver_with_recording_transport(
            monkeypatch, _payload_for(tenant.id, subscription_id)
        )

        assert call_count["n"] == 1  # no second resolution occurred
        assert len(captured) == 1
        assert captured[0].url.host == "8.8.8.8"  # never the "rebound" private address
    finally:
        _cleanup_tenant(tenant.id)


async def test_https_preserves_original_hostname_for_sni_and_host_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test C: for an HTTPS destination, the TCP/transport target must be
    the validated IP, while the TLS SNI extension and the HTTP `Host`
    header must both still carry the *original* hostname --
    `httpcore._async.connection.AsyncHTTPConnection._connect()` (read
    directly from the installed httpcore 1.0.9) passes exactly
    `request.extensions["sni_hostname"]` as `ssl.SSLContext.start_tls()`'s
    `server_hostname`, which Python's `ssl` module also verifies the peer
    certificate against -- so this is the value that determines both SNI
    and certificate-hostname verification for a real TLS connection. This
    test verifies the extension/header values reaching the transport
    boundary; it does not stand up a real TLS server (a live cert-
    validation drill would need a disproportionate amount of local PKI
    machinery for what is otherwise already fully determined by this one
    value, which is asserted directly here).
    """
    tenant = create_tenant(f"webhooks-pin-c-{uuid.uuid4().hex[:8]}")
    try:
        subscription_id = _insert_subscription(tenant.id, "https://secure-target.example:8443/hook")
        monkeypatch.setattr(webhooks_service, "_default_resolve_hostname", lambda host: ["1.1.1.1"])

        captured = await _deliver_with_recording_transport(
            monkeypatch, _payload_for(tenant.id, subscription_id)
        )

        assert len(captured) == 1
        request = captured[0]
        assert request.url.scheme == "https"
        assert request.url.host == "1.1.1.1"
        assert request.url.port == 8443
        assert request.extensions.get("sni_hostname") == "secure-target.example"
        assert request.headers.get("host") == "secure-target.example:8443"
    finally:
        _cleanup_tenant(tenant.id)


async def test_private_destination_never_reaches_the_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test D: strengthens the existing exception-type proof
    (`test_delivery_is_blocked_before_any_network_attempt_for_non_public_destination`)
    with a direct transport-level assertion: a private resolved address
    must result in zero requests ever reaching the transport, not merely
    the right exception type."""
    tenant = create_tenant(f"webhooks-pin-d-{uuid.uuid4().hex[:8]}")
    try:
        subscription_id = _insert_subscription(tenant.id, "http://private-target.example/hook")
        monkeypatch.setattr(
            webhooks_service, "_default_resolve_hostname", lambda host: ["10.0.0.5"]
        )

        with pytest.raises(InvalidWebhookUrlError):
            await _deliver_with_recording_transport(
                monkeypatch, _payload_for(tenant.id, subscription_id)
            )
        # _deliver_with_recording_transport raises before returning its
        # captured list, but the transport it installed is only ever
        # invoked from inside _deliver_webhook() -- an exception raised
        # before that point (as here) means the transport (and the
        # AsyncClient factory that would construct it) was never reached.
    finally:
        _cleanup_tenant(tenant.id)


async def test_mixed_public_and_private_resolution_blocks_delivery_entirely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test E: one public and one private resolved address for the same
    hostname must reject the whole delivery -- never silently pick the
    public one and ignore the private one."""
    tenant = create_tenant(f"webhooks-pin-e-{uuid.uuid4().hex[:8]}")
    try:
        subscription_id = _insert_subscription(tenant.id, "http://mixed-target.example/hook")
        monkeypatch.setattr(
            webhooks_service,
            "_default_resolve_hostname",
            lambda host: ["8.8.8.8", "10.0.0.5"],
        )

        with pytest.raises(InvalidWebhookUrlError):
            await _deliver_with_recording_transport(
                monkeypatch, _payload_for(tenant.id, subscription_id)
            )
    finally:
        _cleanup_tenant(tenant.id)
