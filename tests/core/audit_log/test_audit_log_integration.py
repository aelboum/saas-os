"""`core/audit_log` record/get/list and immutability integration tests
against a real PostgreSQL instance with the Phase 3.4 table actually
migrated (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 15).

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/rbac/test_rbac_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/audit_log/test_audit_log_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.audit_log.errors import AuditLogEntryNotFoundError, InvalidActorError
from core.audit_log.models import ActorType, AuditOutcome
from core.audit_log.service import get, list, record
from core.identity.service import add_tenant_membership, create_user
from core.rbac.scope import RoleScope
from core.rbac.service import (
    assign_role,
    create_delegation,
    create_role,
    grant_permission,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant
from infra.observability import bind_correlation_context

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_audit_log_table() -> None:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.audit_log LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(f"core.audit_log does not exist yet -- run `alembic upgrade head` first: {exc}")
    finally:
        probe_engine.dispose()


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    # core.audit_log rows are genuinely undeletable by the restricted
    # runtime role (the migration REVOKEs DELETE from it -- that is the
    # whole point being tested in this file), so test cleanup must use the
    # privileged migrations role here, exactly like the scratch-table
    # setup/teardown pattern used elsewhere for anything the runtime role
    # structurally cannot do (tests/core/tenancy/test_tenant_isolation_integration.py's
    # `admin_session_factory`). This is test hygiene, not a code path any
    # real application code ever exercises.
    admin_engine = build_engine(get_migrations_database_config())
    try:
        admin_factory = build_session_factory(admin_engine)
        with session_scope(session_factory=admin_factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        admin_engine.dispose()
    with session_scope() as session:
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _cleanup_user(user_id: uuid.UUID) -> None:
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


# --- record() / get() -------------------------------------------------


def test_record_then_get_a_user_actor_entry() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    user = create_user()
    try:
        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.USER,
            actor_user_id=user.id,
            action="role.create",
            resource_type="role",
            resource_id="editor",
            outcome=AuditOutcome.SUCCESS,
            metadata={"name": "editor"},
        )
        assert entry.tenant_id == tenant.id
        assert entry.actor_user_id == user.id
        assert entry.outcome == "success"

        fetched = get(tenant.id, entry.id)
        assert fetched.id == entry.id
        assert fetched.action == "role.create"
        assert fetched.entry_metadata == {"name": "editor"}
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


def test_record_a_system_actor_entry() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            action="migration.applied",
            resource_type="schema",
            outcome=AuditOutcome.SUCCESS,
        )
        assert entry.actor_type == "system"
        assert entry.actor_user_id is None
    finally:
        _cleanup_tenant(tenant.id)


def test_record_a_denied_outcome() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    user = create_user()
    try:
        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.USER,
            actor_user_id=user.id,
            action="role.delete",
            resource_type="role",
            resource_id="admin",
            outcome=AuditOutcome.DENIED,
        )
        assert entry.outcome == "denied"
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


# --- privileged cross-tenant linkage (architecture research Phase F) -----


def test_record_with_acting_as_tenant_id_round_trips() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    user = create_user()
    try:
        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.USER,
            actor_user_id=user.id,
            action="support_access.request",
            resource_type="support_access_request",
            outcome=AuditOutcome.SUCCESS,
            acting_as_tenant_id=tenant.id,
        )
        assert entry.acting_as_tenant_id == tenant.id
        assert entry.delegation_grant_id is None
        assert entry.support_access_id is None

        fetched = get(tenant.id, entry.id)
        assert fetched.acting_as_tenant_id == tenant.id
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


def test_record_with_a_real_delegation_grant_id_round_trips() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    delegator = create_user()
    delegate = create_user()
    permission = register_permission(_unique_name("resource"), "read")
    try:
        membership = add_tenant_membership(tenant.id, delegator.id)
        role = create_role(tenant.id, _unique_name("role"))
        grant_permission(tenant.id, role.id, permission.id)
        dg_permission = register_permission("delegation_grant", "create")
        grant_permission(tenant.id, role.id, dg_permission.id)
        assign_role(tenant.id, membership.id, role.id, scope=RoleScope.SELF)

        grant = create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=tenant.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.USER,
            actor_user_id=delegate.id,
            action="delegated.action",
            resource_type=permission.resource,
            outcome=AuditOutcome.SUCCESS,
            acting_as_tenant_id=tenant.id,
            delegation_grant_id=grant.id,
        )
        assert entry.delegation_grant_id == grant.id
        assert entry.support_access_id is None
    finally:
        # `core.audit_log` DELETE is REVOKEd from the runtime role -- must
        # use the privileged migrations role, and must run BEFORE
        # `core.delegation_grants` is deleted below, since this test's own
        # audit entry references it via `delegation_grant_id`.
        admin_engine = build_engine(get_migrations_database_config())
        try:
            admin_factory = build_session_factory(admin_engine)
            with session_scope(session_factory=admin_factory) as session:
                session.execute(
                    text("DELETE FROM core.audit_log WHERE tenant_id = :t"),
                    {"t": str(tenant.id)},
                )
        finally:
            admin_engine.dispose()
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.delegation_grants WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.membership_roles WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.role_permissions WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(tenant.id)}
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant.id)})
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
                {"r": permission.resource, "a": permission.action},
            )
            session.execute(
                text(
                    "DELETE FROM core.permissions WHERE resource = 'delegation_grant' "
                    "AND action = 'create'"
                )
            )


def test_record_rejects_both_delegation_and_support_linkage_at_once() -> None:
    """architecture research Phase F: at most one authorization story per
    action -- enforced first as a typed, fail-closed error, mirroring the
    actor-pairing check's own discipline."""
    tenant = create_tenant(_unique_name("tenant"))
    user = create_user()
    try:
        with pytest.raises(InvalidActorError):
            record(
                tenant_id=tenant.id,
                actor_type=ActorType.USER,
                actor_user_id=user.id,
                action="x",
                resource_type="y",
                outcome=AuditOutcome.SUCCESS,
                delegation_grant_id=uuid.uuid4(),
                support_access_id=uuid.uuid4(),
            )
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


def test_record_without_linkage_leaves_all_three_columns_null() -> None:
    """Every pre-Phase-F call site is unaffected: omitting the new kwargs
    leaves `acting_as_tenant_id`/`delegation_grant_id`/`support_access_id`
    all `NULL`, exactly like every historical audit record."""
    tenant = create_tenant(_unique_name("tenant"))
    user = create_user()
    try:
        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.USER,
            actor_user_id=user.id,
            action="role.create",
            resource_type="role",
            outcome=AuditOutcome.SUCCESS,
        )
        assert entry.acting_as_tenant_id is None
        assert entry.delegation_grant_id is None
        assert entry.support_access_id is None
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


def test_get_unknown_entry_raises() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        with pytest.raises(AuditLogEntryNotFoundError):
            get(tenant.id, uuid.uuid4())
    finally:
        _cleanup_tenant(tenant.id)


def test_created_at_is_set_automatically() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            action="test.action",
            resource_type="test",
            outcome=AuditOutcome.SUCCESS,
        )
        assert entry.created_at is not None
    finally:
        _cleanup_tenant(tenant.id)


# --- list() --------------------------------------------------------------


def test_list_returns_entries_most_recent_first() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        first = record(
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            action="a",
            resource_type="t",
            outcome=AuditOutcome.SUCCESS,
        )
        second = record(
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            action="b",
            resource_type="t",
            outcome=AuditOutcome.SUCCESS,
        )
        entries = list(tenant.id)
        ids_in_order = [e.id for e in entries]
        assert ids_in_order.index(second.id) < ids_in_order.index(first.id)
    finally:
        _cleanup_tenant(tenant.id)


def test_list_filters_by_actor() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    user_a = create_user()
    user_b = create_user()
    try:
        entry_a = record(
            tenant_id=tenant.id,
            actor_type=ActorType.USER,
            actor_user_id=user_a.id,
            action="x",
            resource_type="t",
            outcome=AuditOutcome.SUCCESS,
        )
        record(
            tenant_id=tenant.id,
            actor_type=ActorType.USER,
            actor_user_id=user_b.id,
            action="y",
            resource_type="t",
            outcome=AuditOutcome.SUCCESS,
        )
        entries = list(tenant.id, actor_user_id=user_a.id)
        assert [e.id for e in entries] == [entry_a.id]
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user_a.id)
        _cleanup_user(user_b.id)


def test_list_filters_by_resource() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            action="update",
            resource_type="widget",
            resource_id="w-1",
            outcome=AuditOutcome.SUCCESS,
        )
        record(
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            action="update",
            resource_type="widget",
            resource_id="w-2",
            outcome=AuditOutcome.SUCCESS,
        )
        entries = list(tenant.id, resource_type="widget", resource_id="w-1")
        assert [e.id for e in entries] == [entry.id]
    finally:
        _cleanup_tenant(tenant.id)


def test_list_rejects_out_of_range_limit() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        with pytest.raises(Exception):  # noqa: PT011, B017
            list(tenant.id, limit=0)
        with pytest.raises(Exception):  # noqa: PT011, B017
            list(tenant.id, limit=1001)
    finally:
        _cleanup_tenant(tenant.id)


# --- Immutability (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 7/19) --


def test_service_module_exposes_no_update_or_delete() -> None:
    import core.audit_log.service as service_module

    assert not hasattr(service_module, "update")
    assert not hasattr(service_module, "delete")
    assert not hasattr(service_module, "purge")
    assert not hasattr(service_module, "edit")


def test_direct_sql_update_is_rejected_by_the_database() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 3.4's Security Requirement:
    "verify no code path can mutate ... an existing entry, including via
    direct database access." Uses the real restricted runtime role
    (whatever `tenant_session_scope()` actually connects as), not the
    privileged migrations role -- proves the REVOKE the migration applied
    is real, not merely that this module's Python API lacks an update().
    """
    tenant = create_tenant(_unique_name("tenant"))
    try:
        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            action="immutable.test",
            resource_type="t",
            outcome=AuditOutcome.SUCCESS,
        )
        with pytest.raises(Exception) as excinfo:  # noqa: PT011
            with tenant_session_scope(tenant.id) as session:
                session.execute(
                    text("UPDATE core.audit_log SET action = 'tampered' WHERE id = :id"),
                    {"id": str(entry.id)},
                )
        assert "permission denied" in str(excinfo.value).lower()

        unchanged = get(tenant.id, entry.id)
        assert unchanged.action == "immutable.test"
    finally:
        _cleanup_tenant(tenant.id)


def test_direct_sql_delete_is_rejected_by_the_database() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            action="immutable.delete.test",
            resource_type="t",
            outcome=AuditOutcome.SUCCESS,
        )
        with pytest.raises(Exception) as excinfo:  # noqa: PT011
            with tenant_session_scope(tenant.id) as session:
                session.execute(
                    text("DELETE FROM core.audit_log WHERE id = :id"), {"id": str(entry.id)}
                )
        assert "permission denied" in str(excinfo.value).lower()

        still_there = get(tenant.id, entry.id)
        assert still_there.id == entry.id
    finally:
        _cleanup_tenant(tenant.id)


# --- Correlation context (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 9) --


def test_record_picks_up_ambient_correlation_context() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        with bind_correlation_context(request_id="req-abc-123"):
            entry = record(
                tenant_id=tenant.id,
                actor_type=ActorType.SYSTEM,
                action="correlated.action",
                resource_type="t",
                outcome=AuditOutcome.SUCCESS,
            )
        assert entry.correlation_id == "req-abc-123"
    finally:
        _cleanup_tenant(tenant.id)


def test_record_with_no_correlation_context_has_none() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        entry = record(
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            action="uncorrelated.action",
            resource_type="t",
            outcome=AuditOutcome.SUCCESS,
        )
        assert entry.correlation_id is None
    finally:
        _cleanup_tenant(tenant.id)


def test_explicit_correlation_id_overrides_ambient_context() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        with bind_correlation_context(request_id="ambient-id"):
            entry = record(
                tenant_id=tenant.id,
                actor_type=ActorType.SYSTEM,
                action="explicit.correlation",
                resource_type="t",
                outcome=AuditOutcome.SUCCESS,
                correlation_id="explicit-id",
            )
        assert entry.correlation_id == "explicit-id"
    finally:
        _cleanup_tenant(tenant.id)
