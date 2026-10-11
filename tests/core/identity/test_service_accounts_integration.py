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
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity.errors import (
    DuplicateServiceAccountNameError,
    ServiceAccountNotFoundError,
)
from saas_os.core.identity.models import ServiceAccountStatus
from saas_os.core.identity.service import (
    create_service_account,
    disable_service_account,
    enable_service_account,
    get_service_account,
    list_service_accounts,
)
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope


def _authority_admin(tenant_id: uuid.UUID, *capabilities: tuple[str, str]) -> UserCaller:
    """An active user holding exactly `capabilities` in `tenant_id` -- the
    explicit, authorized typed caller an authority-changing Core operation
    requires (ADR-0031). Provisioned with explicit provisioning authority."""
    from saas_os.core.authority import SystemAuthority, SystemCaller
    from saas_os.core.identity import add_tenant_membership, create_user
    from saas_os.core.rbac import (
        assign_first_role_for_new_tenant,
        create_role,
        grant_permission,
        register_permission,
    )

    provisioning = SystemCaller(SystemAuthority.PROVISIONING)
    user = create_user()
    membership = add_tenant_membership(tenant_id, user.id, caller=provisioning)
    role = create_role(tenant_id, f"authority-admin-{uuid.uuid4().hex[:8]}", caller=provisioning)
    for resource, action in capabilities:
        permission = register_permission(resource, action)
        grant_permission(tenant_id, role.id, permission.id, caller=provisioning)
    assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=provisioning)
    return UserCaller(user.id)


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
    finally:
        engine.dispose()


_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

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
        for table in (
            "membership_roles",
            "role_permissions",
            "roles",
            "tenant_memberships",
            "service_accounts",
        ):
            session.execute(
                text(f"DELETE FROM core.{table} WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    with session_scope() as session:
        _admin_clear_audit_references({"t": str(tenant_id)}, table="tenants")
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


# --- Creation / basic CRUD -------------------------------------------------


def test_create_service_account_returns_active_by_default() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"), caller=_PROVISIONING)
        assert account.tenant_id == tenant_id
        assert account.status == ServiceAccountStatus.ACTIVE.value
    finally:
        _cleanup_tenant(tenant_id)


def test_create_service_account_rejects_duplicate_name_within_tenant() -> None:
    tenant_id = _new_tenant()
    try:
        name = _unique_name("svc")
        create_service_account(tenant_id, name, caller=_PROVISIONING)
        with pytest.raises(DuplicateServiceAccountNameError):
            create_service_account(tenant_id, name, caller=_PROVISIONING)
    finally:
        _cleanup_tenant(tenant_id)


def test_same_name_allowed_across_different_tenants() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        name = _unique_name("svc")
        create_service_account(tenant_a, name, caller=_PROVISIONING)
        # Must not raise -- uniqueness is per-tenant, not global.
        create_service_account(tenant_b, name, caller=_PROVISIONING)
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)


def test_get_service_account_resolves_within_correct_tenant() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"), caller=_PROVISIONING)
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
        account = create_service_account(tenant_a, _unique_name("svc"), caller=_PROVISIONING)
        assert get_service_account(tenant_b, account.id) is None
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)


def test_list_service_accounts_returns_only_this_tenants_accounts() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        account_a = create_service_account(tenant_a, _unique_name("svc"), caller=_PROVISIONING)
        create_service_account(tenant_b, _unique_name("svc"), caller=_PROVISIONING)
        accounts = list_service_accounts(tenant_a)
        assert {a.id for a in accounts} == {account_a.id}
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)


# --- Lifecycle: ACTIVE / DISABLED -------------------------------------------


def test_disable_service_account_sets_status_disabled() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"), caller=_PROVISIONING)
        disabled = disable_service_account(
            tenant_id,
            account.id,
            caller=_authority_admin(
                tenant_id, ("service_account", "disable"), ("service_account", "enable")
            ),
        )
        assert disabled.status == ServiceAccountStatus.DISABLED.value
        refetched = get_service_account(tenant_id, account.id)
        assert refetched is not None
        assert refetched.status == ServiceAccountStatus.DISABLED.value
    finally:
        _cleanup_tenant(tenant_id)


def test_disable_service_account_is_idempotent() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"), caller=_PROVISIONING)
        disable_service_account(
            tenant_id,
            account.id,
            caller=_authority_admin(
                tenant_id, ("service_account", "disable"), ("service_account", "enable")
            ),
        )
        # Must not raise.
        disable_service_account(
            tenant_id,
            account.id,
            caller=_authority_admin(
                tenant_id, ("service_account", "disable"), ("service_account", "enable")
            ),
        )
    finally:
        _cleanup_tenant(tenant_id)


def test_enable_service_account_restores_active_status() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"), caller=_PROVISIONING)
        disable_service_account(
            tenant_id,
            account.id,
            caller=_authority_admin(
                tenant_id, ("service_account", "disable"), ("service_account", "enable")
            ),
        )
        enabled = enable_service_account(
            tenant_id,
            account.id,
            caller=_authority_admin(
                tenant_id, ("service_account", "disable"), ("service_account", "enable")
            ),
        )
        assert enabled.status == ServiceAccountStatus.ACTIVE.value
    finally:
        _cleanup_tenant(tenant_id)


def test_enable_service_account_is_idempotent() -> None:
    tenant_id = _new_tenant()
    try:
        account = create_service_account(tenant_id, _unique_name("svc"), caller=_PROVISIONING)
        # Already active -- must not raise.
        enable_service_account(
            tenant_id,
            account.id,
            caller=_authority_admin(
                tenant_id, ("service_account", "disable"), ("service_account", "enable")
            ),
        )
    finally:
        _cleanup_tenant(tenant_id)


def test_disable_unknown_service_account_raises() -> None:
    tenant_id = _new_tenant()
    try:
        with pytest.raises(ServiceAccountNotFoundError):
            disable_service_account(
                tenant_id,
                uuid.uuid4(),
                caller=_authority_admin(
                    tenant_id, ("service_account", "disable"), ("service_account", "enable")
                ),
            )
    finally:
        _cleanup_tenant(tenant_id)


def test_disable_service_account_from_wrong_tenant_raises_not_found() -> None:
    """Cannot disable another tenant's service account merely by knowing
    its id -- the tenant scope is load-bearing, not just a filter."""
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        account = create_service_account(tenant_a, _unique_name("svc"), caller=_PROVISIONING)
        with pytest.raises(ServiceAccountNotFoundError):
            disable_service_account(
                tenant_b,
                account.id,
                caller=_authority_admin(
                    tenant_b, ("service_account", "disable"), ("service_account", "enable")
                ),
            )
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
        account = create_service_account(tenant_a, _unique_name("svc"), caller=_PROVISIONING)
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
        account = create_service_account(tenant_id, _unique_name("svc"), caller=_PROVISIONING)
        with session_scope() as session:
            rows = session.execute(
                text("SELECT id FROM core.service_accounts WHERE id = :id"), {"id": str(account.id)}
            ).all()
        assert rows == []
    finally:
        _cleanup_tenant(tenant_id)
