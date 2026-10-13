"""Webhook subscription lifecycle integration tests against a real
PostgreSQL instance with the Phase 4.3 table actually migrated
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.3).

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/webhooks/test_webhooks_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from lifecycle_callers import PROVISIONING
from saas_os.core.audit_log.service import list as list_audit_entries
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.identity.service import create_user
from saas_os.core.tenancy import create_tenant
from saas_os.core.webhooks.errors import InvalidWebhookUrlError, WebhookSubscriptionNotFoundError
from saas_os.core.webhooks.service import (
    get_subscription,
    list_subscriptions,
    subscribe,
    unsubscribe,
)
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)


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


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_webhooks_table() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.webhook_subscriptions LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.webhook_subscriptions does not exist yet -- "
            f"run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    # saas_os.core.audit_log DELETE is REVOKEd from the restricted runtime role
    # entirely (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4) -- test cleanup
    # must use the privileged migrations role here.
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
        self.tenant = create_tenant(f"webhooks-tenant-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        self.user = create_user()

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.webhook_subscriptions WHERE tenant_id = :t"),
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


# --- Subscription management -------------------------------------------


def test_subscribe_creates_a_subscription_and_returns_the_raw_secret(fx: _Fixture) -> None:
    subscription, raw_secret = subscribe(
        fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING
    )
    assert subscription.tenant_id == fx.tenant.id
    assert subscription.url == "https://example.com/hook"
    assert len(raw_secret) >= 32
    # F-02: the persisted/returned record never carries the raw secret --
    # `signing_secret` is an encrypted envelope, not `raw_secret` itself.
    # See tests/core/webhooks/test_webhooks_encryption_integration.py for
    # the full at-rest-encryption contract this property is part of.
    assert subscription.signing_secret != raw_secret


def test_subscribe_rejects_invalid_url(fx: _Fixture) -> None:
    with pytest.raises(InvalidWebhookUrlError):
        subscribe(fx.tenant.id, "not-a-url", caller=_PROVISIONING)


def test_get_subscription_returns_the_created_subscription(fx: _Fixture) -> None:
    subscription, _ = subscribe(fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING)
    fetched = get_subscription(fx.tenant.id, subscription.id)
    assert fetched.id == subscription.id
    assert fetched.url == subscription.url


def test_get_unknown_subscription_raises(fx: _Fixture) -> None:
    with pytest.raises(WebhookSubscriptionNotFoundError):
        get_subscription(fx.tenant.id, uuid.uuid4())


def test_list_subscriptions_includes_created_subscription(fx: _Fixture) -> None:
    subscription, _ = subscribe(fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING)
    ids = {s.id for s in list_subscriptions(fx.tenant.id)}
    assert subscription.id in ids


def test_unsubscribe_removes_the_subscription(fx: _Fixture) -> None:
    subscription, _ = subscribe(fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING)
    unsubscribe(fx.tenant.id, subscription.id, caller=_PROVISIONING)
    with pytest.raises(WebhookSubscriptionNotFoundError):
        get_subscription(fx.tenant.id, subscription.id)


def test_unsubscribe_is_idempotent(fx: _Fixture) -> None:
    unsubscribe(fx.tenant.id, uuid.uuid4(), caller=_PROVISIONING)  # no-op, no error
    subscription, _ = subscribe(fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING)
    unsubscribe(fx.tenant.id, subscription.id, caller=_PROVISIONING)
    unsubscribe(fx.tenant.id, subscription.id, caller=_PROVISIONING)  # still no-op


# --- Audit logging -------------------------------------------------------


def test_subscribe_writes_an_audit_entry(fx: _Fixture) -> None:
    subscription, _ = subscribe(fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING)

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "webhook.subscription_created"]
    assert len(matching) == 1
    entry = matching[0]
    assert entry.tenant_id == fx.tenant.id
    # RE-4: the explicit caller is what is recorded -- here provisioning
    # (user-attributed entries: test_webhook_subscription_authority_integration.py).
    assert entry.actor_type == "system"
    assert (entry.entry_metadata or {}).get("system_authority") == "provisioning"
    assert entry.resource_type == "webhook_subscription"
    assert entry.resource_id == str(subscription.id)
    assert entry.outcome == "success"


def test_subscribe_audit_entry_never_contains_the_signing_secret(fx: _Fixture) -> None:
    subscription, raw_secret = subscribe(
        fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING
    )

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "webhook.subscription_created"]
    entry = matching[0]
    assert entry.entry_metadata is None or raw_secret not in str(entry.entry_metadata)
    assert entry.resource_id is not None
    assert raw_secret not in entry.resource_id
    assert subscription.url not in (entry.entry_metadata or {})


def test_unsubscribe_writes_an_audit_entry(fx: _Fixture) -> None:
    subscription, _ = subscribe(fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING)
    unsubscribe(fx.tenant.id, subscription.id, caller=_PROVISIONING)

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "webhook.subscription_deleted"]
    assert len(matching) == 1
    assert matching[0].resource_id == str(subscription.id)


def test_unsubscribe_no_op_does_not_write_an_audit_entry(fx: _Fixture) -> None:
    unsubscribe(fx.tenant.id, uuid.uuid4(), caller=_PROVISIONING)

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "webhook.subscription_deleted"]
    assert matching == []
