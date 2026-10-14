"""PRIV-03 Phase P7 -- execution-time lifecycle fencing of the Core job
handlers (privacy re-audit finding RA-03), against real PostgreSQL (and
real Redis + arq for the queued path).

The re-audit proved that `_dispatch_notification_job`,
`_ingest_usage_event_job` and `_deliver_webhook` did tenant work after the
tenant had committed DELETED/PURGING (and, for usage, even PURGED): the
only lifecycle check lived at enqueue time. Each handler now re-reads the
lifecycle when it *executes* -- `require_open_tenant()` before any e-mail,
outbound request or tenant-scoped database work, then `lock_open_tenant()`
(`core.tenants` FOR SHARE) inside the transaction that reads the secret or
writes the row -- and treats a closed tenant as an intentionally dropped
job: a normal return, so `saas_os.infra.jobs`' wrapper neither retries nor
dead-letters it (the `TENANT_CLOSED` shape of the AI loop job).

External side effects are faked at the same boundaries the existing suites
use: `saas_os.core.email.send_email`/`get_email_config` and `httpx.AsyncClient`
(an `httpx.MockTransport` records what the transport would have sent).
Every persisted-state assertion goes through the privileged migrations
role so RLS cannot hide anything; every action under test runs as the
ordinary application role.

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/core/test_job_lifecycle_fencing_integration.py
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import threading
import traceback
import uuid
from collections.abc import Callable, Coroutine, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from arq import create_pool
from arq.connections import RedisSettings
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

import saas_os.core.notifications.service as notifications_service
import saas_os.core.rbac  # noqa: F401 -- registers core.delegation_grants/support_access_requests on the shared metadata
import saas_os.core.tenancy.service as tenancy_service
import saas_os.core.usage.service as usage_service
import saas_os.core.webhooks.service as webhooks_service
from lifecycle_callers import PROVISIONING, TENANT_PURGE, platform_operator
from lifecycle_callers import TENANT_PURGE as PURGE_AUTHORITY
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.tenancy import (
    TenantClosedError,
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    tenant_job_session,
    transition_tenant_status,
)
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope
from saas_os.infra.jobs import (
    JobsConfig,
    TenantJobContext,
    TenantJobPayload,
    build_worker,
    enqueue_job,
    register_tenant_job,
)
from saas_os.infra.jobs.dead_letter import count_dead_letters
from saas_os.infra.jobs.queue import get_redis_pool


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


async def _run_tenant_job(handler, payload):  # type: ignore[no-untyped-def]
    """Invoke a tenant job handler directly, with the typed context the worker
    would build from `payload` (Foundation Enforcement FE-5)."""
    return await handler(
        TenantJobContext(tenant_id=uuid.UUID(payload.tenant_id), correlation_id=None), payload
    )


_CLOSED = [TenantStatus.DELETED, TenantStatus.PURGING, TenantStatus.PURGED]
_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
_PUBLIC_ADDRESS = ipaddress.ip_address("93.184.216.34")  # any public literal; never connected to


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
        pytest.skip(f"PostgreSQL/core.notifications not reachable: {exc}")
    finally:
        probe_engine.dispose()


@pytest.fixture
def admin() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def jobs_config() -> JobsConfig:
    return JobsConfig(redis_url=_REDIS_URL, max_tries=2, retry_backoff_base_seconds=0.01)


@pytest.fixture
async def _require_reachable_redis(jobs_config: JobsConfig) -> None:
    try:
        pool = await create_pool(RedisSettings.from_dsn(jobs_config.redis_url))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    try:
        await pool.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at REDIS_URL: {exc}")
    finally:
        await pool.aclose()


# --- side-effect fakes ----------------------------------------------------------


class _StubEmailConfig:
    def __init__(self, default_sender: str | None) -> None:
        self.default_sender = default_sender


@dataclass
class Fakes:
    emails: list[Any] = field(default_factory=list)
    requests: list[httpx.Request] = field(default_factory=list)


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> Fakes:
    """Record, never perform, the two external side effects: e-mail
    (`saas_os.core.email`) and the outbound webhook POST (httpx transport)."""
    recorded = Fakes()

    def _fake_send_email(message: Any, *, provider: Any = None) -> Any:
        from saas_os.core.email.provider import EmailSendResult

        recorded.emails.append(message)
        return EmailSendResult(accepted=True, provider_message_id="fake")

    monkeypatch.setattr(
        "saas_os.core.email.get_email_config", lambda: _StubEmailConfig("no-reply@example.com")
    )
    monkeypatch.setattr("saas_os.core.email.send_email", _fake_send_email)

    real_async_client = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        recorded.requests.append(request)
        return httpx.Response(200)

    def _client_factory(*, timeout: float, follow_redirects: bool) -> httpx.AsyncClient:
        return real_async_client(
            transport=httpx.MockTransport(_handler),
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", _client_factory)
    # No DNS in tests: the delivery-time SSRF gate resolves to a fixed public
    # literal; the MockTransport above means nothing is ever connected to.
    monkeypatch.setattr(
        webhooks_service, "_validate_destination", lambda url, **kw: _PUBLIC_ADDRESS
    )
    return recorded


# --- rig -------------------------------------------------------------------------


@dataclass
class Rig:
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    subscription_id: uuid.UUID


def _build_rig() -> Rig:
    tenant = create_tenant(f"priv03-p7-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE, caller=platform_operator())
    user = create_user()
    add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)
    subscription, _secret = webhooks_service.subscribe(
        tenant.id, "https://example.com/hook", caller=_PROVISIONING
    )
    return Rig(tenant_id=tenant.id, user_id=user.id, subscription_id=subscription.id)


_CLEANUP_ORDER = (
    "core.audit_log",
    "core.notifications",
    "core.usage_events",
    "core.webhook_replay_records",
    "core.webhook_subscriptions",
    "core.tenant_memberships",
    "core.tenant_ancestry",
)


def _teardown(admin: sessionmaker[Session], rigs: list[Rig]) -> None:
    with session_scope(session_factory=admin) as session:
        for rig in rigs:
            for table in _CLEANUP_ORDER:
                session.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
                    {"t": str(rig.tenant_id)},
                )
            _admin_clear_audit_references({"t": str(rig.tenant_id)}, table="tenants")
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(rig.tenant_id)}
            )
            _admin_clear_audit_references({"u": str(rig.user_id)}, table="users")
            session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(rig.user_id)})


@pytest.fixture
def rig(admin: sessionmaker[Session]) -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown(admin, [built])


def _count(admin: sessionmaker[Session], table: str, tenant_id: uuid.UUID) -> int:
    with session_scope(session_factory=admin) as session:
        return session.execute(
            text(f"SELECT count(*) FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
            {"t": str(tenant_id)},
        ).scalar_one()


async def _close(tenant_id: uuid.UUID, status: TenantStatus) -> None:
    transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
    if status is TenantStatus.PURGING:
        transition_tenant_status(tenant_id, TenantStatus.PURGING, caller=TENANT_PURGE)
    elif status is TenantStatus.PURGED:
        # `purge_tenant()` cascades into `purge_tenant_dead_letters_sync()`
        # (`saas_os.infra.jobs.dead_letter`), which opens its own event loop via
        # `asyncio.run()` -- documented as safe only with no already-running
        # loop on the calling thread. This helper runs inside an `async def`
        # test on pytest-asyncio's loop, so the call is offloaded to a
        # worker thread (its own, loop-free thread) rather than made here.
        await asyncio.to_thread(purge_tenant, tenant_id, caller=PURGE_AUTHORITY)


# The exact payloads the producers enqueue (`dispatch_notification`,
# `ingest_event`, `trigger_event`) -- what the worker hands the handler.
def _email_payload(rig: Rig) -> TenantJobPayload:
    return TenantJobPayload(
        tenant_id=str(rig.tenant_id),
        data={
            "recipient_user_id": str(rig.user_id),
            "channel": "email",
            "subject": "Order update",
            "body": "Your order has shipped.",
            "recipient_email": "customer@example.com",
        },
    )


def _in_app_payload(rig: Rig) -> TenantJobPayload:
    return TenantJobPayload(
        tenant_id=str(rig.tenant_id),
        data={
            "recipient_user_id": str(rig.user_id),
            "channel": "in_app",
            "subject": None,
            "body": "hi",
        },
    )


def _usage_payload(rig: Rig) -> TenantJobPayload:
    return TenantJobPayload(
        tenant_id=str(rig.tenant_id),
        data={"metric": "api_calls", "quantity": "1", "occurred_at": datetime.now(UTC).isoformat()},
    )


def _webhook_payload(rig: Rig) -> TenantJobPayload:
    return TenantJobPayload(
        tenant_id=str(rig.tenant_id),
        data={
            "subscription_id": str(rig.subscription_id),
            "event_id": str(uuid.uuid4()),
            "event_type": "order.created",
            "event_data": {"order_id": "abc123"},
        },
    )


async def _enqueue_rig_jobs(rig: Rig, queue_name: str) -> None:
    """Queue one e-mail notification, one usage event and one webhook
    delivery job for `rig`, directly. RE-1: the producers now record outbox
    events and publishing them is the dispatcher's job (RE-2); these tests
    are about the job handlers' execution-time fence, so they seed the queue
    with the producers' payload shapes themselves."""
    for handler, payload in (
        (notifications_service._dispatch_notification_job, _email_payload(rig)),
        (usage_service._ingest_usage_event_job, _usage_payload(rig)),
        (webhooks_service._deliver_webhook, _webhook_payload(rig)),
    ):
        await enqueue_job(handler.__name__, payload, queue_name=queue_name)


async def _run_all_handlers(rig: Rig) -> None:
    await _run_tenant_job(notifications_service._dispatch_notification_job, _email_payload(rig))
    await _run_tenant_job(notifications_service._dispatch_notification_job, _in_app_payload(rig))
    await _run_tenant_job(usage_service._ingest_usage_event_job, _usage_payload(rig))
    await _run_tenant_job(webhooks_service._deliver_webhook, _webhook_payload(rig))


def _snapshot(admin: sessionmaker[Session], rig: Rig, fakes: Fakes) -> dict[str, int]:
    return {
        "notifications": _count(admin, "core.notifications", rig.tenant_id),
        "usage_events": _count(admin, "core.usage_events", rig.tenant_id),
        "emails": len(fakes.emails),
        "requests": len(fakes.requests),
    }


# --- 1. ACTIVE tenants keep working exactly as before ---------------------------


async def test_active_tenant_handlers_still_do_their_work(
    rig: Rig, admin: sessionmaker[Session], fakes: Fakes
) -> None:
    await _run_all_handlers(rig)
    assert _snapshot(admin, rig, fakes) == {
        "notifications": 2,
        "usage_events": 1,
        "emails": 1,
        "requests": 1,
    }
    assert fakes.emails[0].to == ("customer@example.com",)
    assert fakes.requests[0].method == "POST"


# --- 2. Closure committed before execution: every handler is a clean drop --------


@pytest.mark.parametrize("status", _CLOSED)
async def test_closed_tenant_drops_every_handler_without_side_effects(
    status: TenantStatus, rig: Rig, admin: sessionmaker[Session], fakes: Fakes
) -> None:
    """Scenario C of the audit: the closure has committed when the worker
    hands the (validly enqueued) payload to the handler. No e-mail, no
    outbound request, no row -- and no exception, so nothing is retried
    or dead-lettered. After PURGED the membership and subscription are
    gone too; the fence must still be what stops the job, not an FK."""
    await _close(rig.tenant_id, status)
    assert get_tenant(rig.tenant_id).status == status.value
    before = _snapshot(admin, rig, fakes)
    await _run_all_handlers(rig)  # returns normally: dropped, not failed
    assert _snapshot(admin, rig, fakes) == before
    assert before["emails"] == 0 and before["requests"] == 0


# --- 3. Enqueue/execution separation through the real queue and worker ---------


@pytest.mark.parametrize("status", _CLOSED)
async def test_queued_jobs_are_dropped_when_the_tenant_closes_before_the_worker_runs(
    status: TenantStatus,
    rig: Rig,
    admin: sessionmaker[Session],
    fakes: Fakes,
    jobs_config: JobsConfig,
    _require_reachable_redis: None,
) -> None:
    """Scenario A of the audit: enqueue while ACTIVE, close the tenant, then let a real arq
    burst worker execute the queued jobs. Nothing happens, and the shared
    dead-letter list does not grow -- a dropped job is a successful job to
    the retry wrapper."""
    queue_name = f"priv03-p7-{uuid.uuid4().hex[:8]}"
    await _enqueue_rig_jobs(rig, queue_name)
    await _close(rig.tenant_id, status)

    pool = await get_redis_pool(jobs_config)
    try:
        dead_before = await count_dead_letters(pool, jobs_config)
    finally:
        await pool.aclose()
    functions = [
        register_tenant_job(notifications_service._dispatch_notification_job, config=jobs_config),
        register_tenant_job(usage_service._ingest_usage_event_job, config=jobs_config),
        register_tenant_job(webhooks_service._deliver_webhook, config=jobs_config),
    ]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        await worker.main()
        await worker.main()  # a second burst would run any retry -- there must be none
    finally:
        await worker.close()

    pool = await get_redis_pool(jobs_config)
    try:
        dead_after = await count_dead_letters(pool, jobs_config)
    finally:
        await pool.aclose()
    assert dead_after == dead_before
    assert _snapshot(admin, rig, fakes) == {
        "notifications": 0,
        "usage_events": 0,
        "emails": 0,
        "requests": 0,
    }


# --- 3b. RA-12-8: SUSPENDED is intentionally different from CLOSED for already- ---
#         queued work (RA-03's own reviewed decision, unchanged by RA-12-8)


async def test_queued_jobs_still_execute_when_the_tenant_is_suspended_before_the_worker_runs(
    rig: Rig,
    admin: sessionmaker[Session],
    fakes: Fakes,
    jobs_config: JobsConfig,
    _require_reachable_redis: None,
) -> None:
    """RA-12-8's own audit finding, locked in as an explicit, intentional
    regression test rather than an implicit gap: `SUSPENDED` denies every
    *new*, principal-initiated authorization
    (`test_tenant_lifecycle_authorization_integration.py`'s own
    `_INACCESSIBLE` suite), but it does **not** cancel work already
    queued while the tenant was ACTIVE. Each handler's execution-time
    fence is `require_open_tenant()`/`lock_open_tenant()`
    (`saas_os.core.tenancy.lifecycle.CLOSED_STATUSES` -- DELETED/PURGING/PURGED
    only), never the wider `PRINCIPAL_INACCESSIBLE_STATUSES` a *new*
    authorization decision uses -- this is RA-03's own reviewed design
    (module docstring), and RA-12-8 deliberately leaves it unchanged
    (`docs/MULTI-TENANCY.md` section 6's own RA-12-8 addendum). Same
    real-queue, real-burst-worker shape as
    `test_queued_jobs_are_dropped_when_the_tenant_closes_before_the_worker_runs`
    immediately above, with the opposite, equally intentional outcome: the
    e-mail is sent, the webhook POST goes out, both rows are written."""
    queue_name = f"ra12-p8-{uuid.uuid4().hex[:8]}"
    await _enqueue_rig_jobs(rig, queue_name)
    transition_tenant_status(rig.tenant_id, TenantStatus.SUSPENDED, caller=platform_operator())
    assert get_tenant(rig.tenant_id).status == TenantStatus.SUSPENDED.value

    functions = [
        register_tenant_job(notifications_service._dispatch_notification_job, config=jobs_config),
        register_tenant_job(usage_service._ingest_usage_event_job, config=jobs_config),
        register_tenant_job(webhooks_service._deliver_webhook, config=jobs_config),
    ]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        await worker.main()
    finally:
        await worker.close()

    assert _snapshot(admin, rig, fakes) == {
        "notifications": 1,
        "usage_events": 1,
        "emails": 1,
        "requests": 1,
    }
    assert get_tenant(rig.tenant_id).status == TenantStatus.SUSPENDED.value  # still suspended


# --- 4. Concurrency: closure vs. a worker that has not crossed its fence -------


def _in_frame(name: str) -> bool:
    return any(frame.name == name for frame in traceback.extract_stack())


def _pause_first_call(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    attr: str,
    *,
    frame: str,
    paused: threading.Event,
    release: threading.Event,
    after: bool,
) -> None:
    """Patch `module.attr` (a lifecycle primitive the handler calls) so its
    first call from `frame` pauses -- `after=False`: before the real call
    (the closure races the check); `after=True`: after the real call has
    returned (the handler holds whatever the primitive acquired)."""
    real = getattr(module, attr)
    fired = {"done": False}

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if fired["done"] or not _in_frame(frame):
            return real(*args, **kwargs)
        fired["done"] = True
        if not after:
            paused.set()
            assert release.wait(timeout=30)
        result = real(*args, **kwargs)
        if after:
            paused.set()
            assert release.wait(timeout=30)
        return result

    monkeypatch.setattr(module, attr, wrapper)


# `handler_module` is where `fn_name` itself lives (always); `lifecycle_module`
# is where `require_open_tenant`/`lock_open_tenant` must be patched to affect
# that handler's own call to them. For notification/usage these are the same
# module -- each still imports and calls the two primitives directly. For
# webhook they differ since F-09: `_deliver_webhook()` no longer calls either
# primitive itself, it goes through `saas_os.core.tenancy.service.tenant_job_session()`
# (F-09's shared fence), which is where those names now actually resolve from
# at call time -- `webhooks_service` doesn't even import `lock_open_tenant`
# anymore. `_in_frame(fn_name)` below still finds `_deliver_webhook` on the
# call stack either way (it is still the caller, just one frame further up,
# through `tenant_job_session`'s own generator frame), so the pause/release
# race-timing mechanism is unaffected by this indirection.
_HANDLERS: dict[str, tuple[Any, Any, str, Callable[[Rig], TenantJobPayload], str]] = {
    "notification": (
        notifications_service,
        notifications_service,
        "_dispatch_notification_job",
        _in_app_payload,
        "notifications",
    ),
    "usage": (
        usage_service,
        usage_service,
        "_ingest_usage_event_job",
        _usage_payload,
        "usage_events",
    ),
    "webhook": (
        webhooks_service,
        tenancy_service,
        "_deliver_webhook",
        _webhook_payload,
        "requests",
    ),
}


def _run_in_thread(
    coro_factory: Callable[[], Coroutine[Any, Any, None]],
) -> tuple[threading.Thread, dict]:
    import asyncio

    outcome: dict[str, object] = {}

    def _run() -> None:
        try:
            asyncio.run(coro_factory())
            outcome["done"] = True
        except BaseException as exc:  # noqa: BLE001 -- surfaced by the assertions
            outcome["error"] = exc

    thread = threading.Thread(target=_run)
    thread.start()
    return thread, outcome


@pytest.mark.parametrize("handler", list(_HANDLERS))
def test_closure_that_commits_before_the_fence_drops_the_job(
    handler: str,
    rig: Rig,
    admin: sessionmaker[Session],
    fakes: Fakes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Closure wins: the handler is paused just before its execution-time
    check, DELETED commits, the handler resumes -- and is dropped: no
    row, no request, no exception."""
    module, lifecycle_module, fn_name, make_payload, counter = _HANDLERS[handler]
    paused, release = threading.Event(), threading.Event()
    _pause_first_call(
        monkeypatch,
        lifecycle_module,
        "require_open_tenant",
        frame=fn_name,
        paused=paused,
        release=release,
        after=False,
    )
    payload = make_payload(rig)
    thread, outcome = _run_in_thread(lambda: _run_tenant_job(getattr(module, fn_name), payload))
    assert paused.wait(timeout=30), "the handler never reached its lifecycle fence"
    transition_tenant_status(
        rig.tenant_id, TenantStatus.DELETED, caller=platform_operator()
    )  # commits during the pause
    release.set()
    thread.join(timeout=30)
    assert "error" not in outcome, outcome
    assert _snapshot(admin, rig, fakes)[counter] == 0


@pytest.mark.parametrize("handler", list(_HANDLERS))
def test_worker_holding_the_lifecycle_lock_completes_and_later_execution_is_dropped(
    handler: str,
    rig: Rig,
    admin: sessionmaker[Session],
    fakes: Fakes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Worker wins for the protected transaction: the handler has taken
    `lock_open_tenant()`'s FOR SHARE lock inside its transaction; the
    closure's FOR UPDATE must wait; the transaction completes (row written
    / secret read and request sent); the closure then commits; and the
    next execution of the same job is dropped. Exactly the semantics the
    existing primitive already establishes -- no new rule."""
    module, lifecycle_module, fn_name, make_payload, counter = _HANDLERS[handler]
    paused, release = threading.Event(), threading.Event()
    _pause_first_call(
        monkeypatch,
        lifecycle_module,
        "lock_open_tenant",
        frame=fn_name,
        paused=paused,
        release=release,
        after=True,
    )
    payload = make_payload(rig)
    worker_thread, outcome = _run_in_thread(
        lambda: _run_tenant_job(getattr(module, fn_name), payload)
    )
    assert paused.wait(timeout=30), "the handler never acquired the lifecycle lock"

    closer = threading.Thread(
        target=transition_tenant_status,
        args=(rig.tenant_id, TenantStatus.DELETED),
        kwargs={"caller": platform_operator()},
    )
    closer.start()
    closer.join(timeout=2)
    assert closer.is_alive(), "the closure must block on the handler's share lock"
    assert get_tenant(rig.tenant_id).status == TenantStatus.ACTIVE.value

    release.set()
    worker_thread.join(timeout=30)
    closer.join(timeout=30)
    assert "error" not in outcome, outcome
    assert _snapshot(admin, rig, fakes)[counter] == 1  # completed under the lock it held
    assert get_tenant(rig.tenant_id).status == TenantStatus.DELETED.value

    import asyncio

    asyncio.run(
        _run_tenant_job(getattr(module, fn_name), make_payload(rig))
    )  # after the closure: dropped
    assert _snapshot(admin, rig, fakes)[counter] == 1


# --- 5. Retry semantics for genuine failures are untouched -----------------------


async def test_a_genuine_failure_still_raises_for_the_retry_wrapper(
    rig: Rig, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The drop path is specific to `TenantClosedError`: an unrelated
    failure inside the protected transaction still surfaces as the
    handler's own error type, exactly as before, so `saas_os.infra.jobs` retries
    and dead-letters it."""
    from saas_os.core.usage.errors import UsageIngestionError

    def _boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("simulated database failure")

    monkeypatch.setattr(usage_service, "lock_open_tenant", _boom)
    with pytest.raises(UsageIngestionError):
        await _run_tenant_job(usage_service._ingest_usage_event_job, _usage_payload(rig))


# --- 6. tenant_job_session() itself, directly (F-09) ------------------------
#
# Everything above already proves F-09's shared primitive correct through
# its one real consumer (`_deliver_webhook`), including the two hardest
# properties -- a genuine race and a genuine lock hand-off, against real
# PostgreSQL. These are additionally small, direct tests of the primitive
# in isolation, independent of any job handler, so it carries its own
# regression coverage rather than only being proven transitively.


def test_tenant_job_session_permits_execution_for_an_open_tenant(rig: Rig) -> None:
    entered = False
    with tenant_job_session(rig.tenant_id) as session:
        # A real, usable, already-tenant-scoped Session -- the fence's own
        # transaction, not a second one the caller must open itself.
        row = session.execute(text("SELECT 1")).scalar_one()
        assert row == 1
        entered = True
    assert entered is True


@pytest.mark.parametrize("status", _CLOSED)
def test_tenant_job_session_denies_execution_for_a_closed_tenant(
    status: TenantStatus, rig: Rig
) -> None:
    """DELETED/PURGING/PURGED all deny -- and, critically, the body never
    runs at all (a `with` block whose setup raises never reaches its own
    statements), so nothing the caller would have done inside it -- write
    a row, send a request -- can happen after the fence denies."""
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED, caller=platform_operator())
    if status is TenantStatus.PURGING:
        transition_tenant_status(rig.tenant_id, TenantStatus.PURGING, caller=TENANT_PURGE)
    elif status is TenantStatus.PURGED:
        purge_tenant(rig.tenant_id, caller=PURGE_AUTHORITY)

    entered = False
    with pytest.raises(TenantClosedError):
        with tenant_job_session(rig.tenant_id) as _session:
            entered = True  # pragma: no cover -- must never execute
    assert entered is False


def test_tenant_job_session_permits_execution_for_a_suspended_tenant(rig: Rig) -> None:
    """RA-12-8's own distinction (module docstring, test 3b above), proven
    directly against the primitive itself: `SUSPENDED` is not one of
    `saas_os.core.tenancy.lifecycle.CLOSED_STATUSES` -- `tenant_job_session()` must
    permit execution exactly like an ACTIVE tenant, never conflate this
    with the wider `PRINCIPAL_INACCESSIBLE_STATUSES` a *new* authorization
    decision uses."""
    transition_tenant_status(rig.tenant_id, TenantStatus.SUSPENDED, caller=platform_operator())

    entered = False
    with tenant_job_session(rig.tenant_id) as _session:
        entered = True
    assert entered is True
