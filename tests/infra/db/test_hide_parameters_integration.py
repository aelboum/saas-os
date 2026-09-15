"""PRIV-03 Phase P14 -- bound parameters never enter database exception
text (privacy re-audit finding RA-10-F1), against a real PostgreSQL.

The audit reproduced the mechanism: a tenant-scoped insert failing at the
database produced a SQLAlchemy error whose text carried the statement's
bound values (`[SQL: ...] [parameters: {...}]`) -- a notification's subject
and body, a webhook subscription's plaintext signing secret and its URL
query secret. Every module wraps such failures in a typed error with only
identifiers and a type name, but the traceback a chained
`logger.exception()` prints (the API middleware's unhandled-error path,
the arq worker's job-failure line) and the stack trace
`span.record_exception()` records both walk `__cause__` and reproduced the
SQLAlchemy text verbatim. `infra.db.build_engine()` now creates every
engine with `hide_parameters=True`.

These tests exercise exactly that path -- a real database failure with
bound marker values, wrapped the way the shipped handlers wrap it -- and
assert the markers are absent from `str(exc)`, from the JSON log line the
repository's own `JsonFormatter` emits for a chained `logger.exception()`,
and from the OpenTelemetry exception event recorded on a span (captured
with the SDK's in-memory exporter, the same helper
`tests/infra/observability/test_end_to_end.py` uses). The outer wrapped
message is deliberately not the thing under test; the chained cause is.

Marked `integration`. How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_hide_parameters_integration.py
"""

from __future__ import annotations

import io
import json
import logging
import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from core.identity.service import add_tenant_membership, create_user
from core.notifications.errors import NotificationDispatchError
from core.notifications.models import Notification
from core.webhooks.models import WebhookSubscription
from infra.db.config import DatabaseConfig, get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.observability.config import get_observability_config
from infra.observability.logging import CorrelationFilter, JsonFormatter
from infra.observability.otel import InMemorySpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, StatementError

import core.rbac  # noqa: F401 -- registers the mappers core.audit_log references by name
from core.tenancy import TenantStatus, create_tenant, transition_tenant_status

pytestmark = pytest.mark.integration

# Unmistakable values that must never appear in any exception, log line
# or span produced by a failing statement that binds them.
_BODY = "customer-content-body-MARKER-ra10f1"
_SUBJECT = "customer-content-subject-MARKER-ra10f1"
_SECRET = "plaintext-signing-secret-MARKER-ra10f1"  # noqa: S105 -- a marker, asserted absent
_URL_SECRET = "url-query-secret-MARKER-ra10f1"
_MARKERS = (_BODY, _SUBJECT, _SECRET, _URL_SECRET)


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


@dataclass
class Rig:
    tenant_id: uuid.UUID
    user_id: uuid.UUID


@pytest.fixture
def rig() -> Iterator[Rig]:
    tenant = create_tenant(f"priv03-p14-{uuid.uuid4().hex[:8]}")
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    user = create_user()
    add_tenant_membership(tenant.id, user.id)
    built = Rig(tenant_id=tenant.id, user_id=user.id)
    try:
        yield built
    finally:
        engine = build_engine(get_migrations_database_config())
        try:
            with session_scope(session_factory=build_session_factory(engine)) as session:
                for table in (
                    "core.audit_log",
                    "core.webhook_subscriptions",
                    "core.notifications",
                    "core.tenant_memberships",
                    "core.tenant_ancestry",
                ):
                    session.execute(
                        text(f"DELETE FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
                        {"t": str(built.tenant_id)},
                    )
                session.execute(
                    text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(built.tenant_id)}
                )
                session.execute(
                    text("DELETE FROM core.users WHERE id = :u"), {"u": str(built.user_id)}
                )
        finally:
            engine.dispose()


def _failing_notification_insert(rig: Rig) -> NotificationDispatchError:
    """A notification whose recipient is not a member: the composite FK
    rejects the insert -- exactly what the worker sees when a member is
    removed between enqueue and execution -- wrapped the way
    `core/notifications/service.py::_dispatch_notification_job` wraps it."""
    try:
        try:
            with tenant_session_scope(rig.tenant_id) as session:
                session.add(
                    Notification(
                        tenant_id=rig.tenant_id,
                        recipient_user_id=uuid.uuid4(),
                        channel="in_app",
                        subject=_SUBJECT,
                        body=_BODY,
                        status="sent",
                    )
                )
                session.flush()
        except Exception as exc:  # noqa: BLE001 -- the handler's own wrapping shape
            raise NotificationDispatchError(rig.user_id, type(exc).__name__) from exc
    except NotificationDispatchError as wrapped:
        return wrapped
    raise AssertionError("the insert must fail at the database")


def _failing_subscription_insert(rig: Rig) -> IntegrityError:
    """A duplicate primary key on a webhook subscription that binds a
    plaintext signing secret and a URL carrying a query secret."""
    subscription_id = uuid.uuid4()
    url = f"https://hooks.example.com/x?token={_URL_SECRET}"
    with tenant_session_scope(rig.tenant_id) as session:
        session.add(
            WebhookSubscription(
                id=subscription_id, tenant_id=rig.tenant_id, url=url, signing_secret=_SECRET
            )
        )
        session.flush()
    with pytest.raises(IntegrityError) as excinfo:
        with tenant_session_scope(rig.tenant_id) as session:
            session.add(
                WebhookSubscription(
                    id=subscription_id, tenant_id=rig.tenant_id, url=url, signing_secret=_SECRET
                )
            )
            session.flush()
    return excinfo.value


def _chained_json_log_line(exc: BaseException) -> str:
    """What the API middleware / arq worker path emits: `logger.exception()`
    through the repository's own `JsonFormatter` + `CorrelationFilter`."""
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(CorrelationFilter(get_observability_config()))
    logger = logging.getLogger(f"priv03.p14.{uuid.uuid4().hex[:6]}")
    logger.propagate = False
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        raise exc
    except BaseException:
        logger.exception("unhandled_request_error %s: %s", type(exc).__name__, exc)
    finally:
        logger.removeHandler(handler)
    line = buffer.getvalue()
    assert "Traceback" in json.loads(line)["exception"]  # the chain was really printed
    return line


def _span_exception_event(exc: BaseException) -> dict[str, object]:
    """What `api/middleware.py` records with `span.record_exception(exc)`,
    captured by the SDK's in-memory exporter on a local provider (no
    global tracer-provider mutation)."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    with provider.get_tracer("priv03.p14").start_as_current_span("GET /probe") as span:
        span.record_exception(exc)
    (finished,) = exporter.get_finished_spans()
    (event,) = finished.events
    assert event.name == "exception"
    return dict(event.attributes or {})


def _assert_markers_absent(where: str, *texts: str) -> None:
    for marker in _MARKERS:
        for candidate in texts:
            assert marker not in candidate, f"{marker!r} leaked into {where}"


# --- 1. the SQLAlchemy exception text itself ---------------------------------------


def test_database_error_text_hides_bound_customer_content(rig: Rig) -> None:
    wrapped = _failing_notification_insert(rig)
    cause = wrapped.__cause__
    assert isinstance(cause, StatementError)  # the real SQLAlchemy error, with its statement
    rendered = str(cause)
    assert "[SQL:" in rendered  # the statement is still there for diagnosis...
    assert "hide_parameters=True" in rendered  # ...the values are not
    assert "[parameters:" not in rendered
    # `str()` and `repr()` are what tracebacks, `logger.exception()` and
    # `span.record_exception()` render. (The structured `.params` attribute
    # still exists for programmatic access; nothing in this repository logs
    # it -- the leak was the rendered text, which is what is asserted here.)
    _assert_markers_absent("str(cause)", rendered, repr(cause))
    # The outer wrapped message was always clean; the point is the cause.
    _assert_markers_absent("str(wrapped)", str(wrapped))


def test_database_error_text_hides_bound_secrets(rig: Rig) -> None:
    error = _failing_subscription_insert(rig)
    rendered = str(error)
    assert "[SQL:" in rendered
    assert "[parameters:" not in rendered
    _assert_markers_absent("str(IntegrityError)", rendered, repr(error))


# --- 2. the chained logger.exception() line ------------------------------------------


def test_chained_exception_log_line_hides_customer_content_and_secrets(rig: Rig) -> None:
    notification_line = _chained_json_log_line(_failing_notification_insert(rig))
    subscription_line = _chained_json_log_line(_failing_subscription_insert(rig))
    for line in (notification_line, subscription_line):
        exception_text = json.loads(line)["exception"]
        assert "The above exception was the direct cause" in exception_text or (
            "During handling of the above exception" in exception_text
            or "IntegrityError" in exception_text
        )  # the SQLAlchemy cause is genuinely in the printed chain
        assert "[parameters:" not in line
    _assert_markers_absent("chained JSON log line", notification_line, subscription_line)


# --- 3. the OpenTelemetry exception event ---------------------------------------------


def test_span_exception_event_hides_customer_content_and_secrets(rig: Rig) -> None:
    for exc in (_failing_notification_insert(rig), _failing_subscription_insert(rig)):
        attributes = _span_exception_event(exc)
        stacktrace = str(attributes.get("exception.stacktrace", ""))
        assert "IntegrityError" in stacktrace  # the chained cause is recorded...
        assert "[parameters:" not in stacktrace  # ...without its bound values
        _assert_markers_absent(
            "span exception event",
            stacktrace,
            str(attributes.get("exception.message", "")),
            str(attributes.get("exception.type", "")),
        )


# --- the setting itself, on every engine this repository builds ----------------------


def test_every_engine_built_here_hides_parameters() -> None:
    assert get_engine().hide_parameters is True
    detached = build_engine(
        DatabaseConfig(url="postgresql+psycopg://user:pw@127.0.0.1:1/never-connected")
    )
    try:
        assert detached.hide_parameters is True
    finally:
        detached.dispose()
