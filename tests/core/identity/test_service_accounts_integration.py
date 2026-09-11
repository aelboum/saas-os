"""`ServiceAccount` lifecycle and tenant-isolation integration tests
against a real PostgreSQL instance (architecture research: universal
multi-tenant tenancy, Phase E -- "Principal + Service Accounts + API Key
Hardening").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/identity/test_identity_isolation_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/identity/test_service_accounts_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.errors import DuplicateServiceAccountNameError, ServiceAccountNotFoundError
from core.identity.models import ServiceAccountStatus
from core.identity.service import (
    create_service_account,
    disable_service_account,
    enable_service_account,
    get_service_account,
    list_service_accounts,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_service_accounts_table() -> None:
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
            conn.execute(text("SELECT 1 FROM core.service_accounts LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.service_accounts does not exist yet -- run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _new_tenant() -> uuid.UUID:
    return create_tenant(_unique_name("tenant")).id


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.service_accounts WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
    with session_scope() as session:
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


# --- Creation / basic CRUD -------------------------------------------------


def test_create_service_account_returns_active_by_default() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"))
        assert account.tenant_id == tenant_id
        assert account.status == ServiceAccountStatus.ACTIVE.value
    finally:
        _cleanup_tenant(tenant_id)


def test_create_service_account_rejects_duplicate_name_within_tenant() -> None:
    tenant_id = _new_tenant()
    try:
        name = _unique_name("svc")
        create_service_account(tenant_id, name)
        with pytest.raises(DuplicateServiceAccountNameError):
            create_service_account(tenant_id, name)
    finally:
        _cleanup_tenant(tenant_id)


def test_same_name_allowed_across_different_tenants() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        name = _unique_name("svc")
        create_service_account(tenant_a, name)
        # Must not raise -- uniqueness is per-tenant, not global.
        create_service_account(tenant_b, name)
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)


def test_get_service_account_resolves_within_correct_tenant() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"))
        fetched = get_service_account(tenant_id, account.id)
        assert fetched is not None
        assert fetched.id == account.id
    finally:
        _cleanup_tenant(tenant_id)


def test_get_service_account_returns_none_for_wrong_tenant() -> None:
    """architecture research Phase E: "no implicit hierarchy access" --
    resolving a service account under a tenant it does not belong to
    must fail closed (`None`), not raise, and never fall back to some
    other tenant's row."""
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        account = create_service_account(tenant_a, _unique_name("svc"))
        assert get_service_account(tenant_b, account.id) is None
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)


def test_list_service_accounts_returns_only_this_tenants_accounts() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        account_a = create_service_account(tenant_a, _unique_name("svc"))
        create_service_account(tenant_b, _unique_name("svc"))
        accounts = list_service_accounts(tenant_a)
        assert {a.id for a in accounts} == {account_a.id}
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)


# --- Lifecycle: ACTIVE / DISABLED -------------------------------------------


def test_disable_service_account_sets_status_disabled() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"))
        disabled = disable_service_account(tenant_id, account.id)
        assert disabled.status == ServiceAccountStatus.DISABLED.value
        refetched = get_service_account(tenant_id, account.id)
        assert refetched is not None
        assert refetched.status == ServiceAccountStatus.DISABLED.value
    finally:
        _cleanup_tenant(tenant_id)


def test_disable_service_account_is_idempotent() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"))
        disable_service_account(tenant_id, account.id)
        # Must not raise.
        disable_service_account(tenant_id, account.id)
    finally:
        _cleanup_tenant(tenant_id)


def test_enable_service_account_restores_active_status() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"))
        disable_service_account(tenant_id, account.id)
        enabled = enable_service_account(tenant_id, account.id)
        assert enabled.status == ServiceAccountStatus.ACTIVE.value
    finally:
        _cleanup_tenant(tenant_id)


def test_enable_service_account_is_idempotent() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"))
        # Already active -- must not raise.
        enable_service_account(tenant_id, account.id)
    finally:
        _cleanup_tenant(tenant_id)


def test_disable_unknown_service_account_raises() -> None:
    tenant_id = _new_tenant()
    try:
        with pytest.raises(ServiceAccountNotFoundError):
            disable_service_account(tenant_id, uuid.uuid4())
    finally:
        _cleanup_tenant(tenant_id)


def test_disable_service_account_from_wrong_tenant_raises_not_found() -> None:
    """Cannot disable another tenant's service account merely by knowing
    its id -- the tenant scope is load-bearing, not just a filter."""
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        account = create_service_account(tenant_a, _unique_name("svc"))
        with pytest.raises(ServiceAccountNotFoundError):
            disable_service_account(tenant_b, account.id)
        # And the account itself is untouched.
        refetched = get_service_account(tenant_a, account.id)
        assert refetched is not None
        assert refetched.status == ServiceAccountStatus.ACTIVE.value
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)


# --- RLS (real PostgreSQL, real catalog) ------------------------------------


def test_force_row_level_security_is_actually_enabled_on_service_accounts() -> None:
    with _admin_session() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'service_accounts'"
            )
        ).one()
    assert row[0] is True
    assert row[1] is True


def test_cross_tenant_read_of_service_accounts_is_denied_by_rls() -> None:
    """Direct proof of RLS, bypassing the published `get_service_account()`
    lookup: querying `core.service_accounts` under tenant B's session
    context must return zero rows for a service account that belongs to
    tenant A, even via raw SQL."""
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        account = create_service_account(tenant_a, _unique_name("svc"))
        with tenant_session_scope(tenant_b) as session:
            rows = session.execute(
                text("SELECT id FROM core.service_accounts WHERE id = :id"), {"id": str(account.id)}
            ).all()
        assert rows == []
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)


def test_untenanted_read_of_service_accounts_returns_nothing() -> None:
    """An untenanted `session_scope()` query against an RLS-protected,
    FORCE-enabled table always returns zero rows, regardless of which
    row's `tenant_id` would have matched -- the same deny-by-default
    guarantee every other tenant-owned table has."""
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"))
        with session_scope() as session:
            rows = session.execute(
                text("SELECT id FROM core.service_accounts WHERE id = :id"), {"id": str(account.id)}
            ).all()
        assert rows == []
    finally:
        _cleanup_tenant(tenant_id)
