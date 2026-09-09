"""Integration tests for `api.tenant_bootstrap` (post-audit F-02) against
a real PostgreSQL, running as the restricted application role -- exactly
the way an operator runs `python -m api.tenant_bootstrap`.

Proves: a fresh bootstrap creates tenant/activation/owner user/role/
grants/membership/assignment and audits each; an identical second run is
a no-op (no duplicate tenant, membership, role, grant, or assignment); a
forced failure between membership and role assignment leaves *no*
privilege and a re-run completes; the owner holds exactly the intended
permissions through the real `core.rbac.can()` chokepoint; two
bootstrapped tenants are isolated from each other (RBAC, RLS, and the
real HTTP route); RLS/FORCE RLS and the NOSUPERUSER/NOBYPASSRLS runtime
role are intact; audit metadata carries no secret; name conflicts and
suspended tenants are refused; `find_tenants_by_name()` behaves.

Marked `integration`, skipped cleanly without a reachable database (same
convention as `tests/api/v1/test_tenant_status_integration.py`). Every
tenant name is unique per test run and every row this file creates is
removed afterwards.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import api.tenant_bootstrap as bootstrap_module
import pytest
from api.tenant_bootstrap import (
    FIRST_TENANT_OWNER_PERMISSIONS,
    FIRST_TENANT_OWNER_ROLE_NAME,
    BootstrapConflictError,
    BootstrapRequest,
    assess_bootstrap,
    bootstrap_first_tenant,
    validate_request,
)
from core.audit_log.metadata import _FORBIDDEN_KEYS
from core.audit_log.service import list as list_audit_entries
from core.rbac.models import Permission, Role, RolePermission
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.role_guard import validate_application_role
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.ratelimit.config import get_ratelimit_config
from sqlalchemy import select, text

from core.identity import (
    add_tenant_membership,
    create_user,
    find_external_identity,
    get_membership,
    issue_session,
    list_tenant_members,
)
from core.rbac import can, get_role_permission, list_membership_roles, list_roles
from core.tenancy import TenantStatus, find_tenants_by_name, get_tenant, transition_tenant_status

pytestmark = pytest.mark.integration

_ISSUER = "https://issuer.example.test"


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
    probe = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.membership_roles LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.membership_roles not reachable: {exc}")
    finally:
        probe.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _request(name: str, subject: str) -> BootstrapRequest:
    return validate_request(name, _ISSUER, subject)


class _Cleanup:
    """Removes every row a test's bootstraps created, as the restricted
    role where RLS allows it and as the admin role only for the
    append-only audit log (which the runtime role cannot delete from --
    the same cleanup shape `tests/api/v1/test_tenant_status_integration.py`
    uses)."""

    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    def track_request(self, request: BootstrapRequest) -> None:
        for tenant in find_tenants_by_name(request.tenant_name):
            if tenant.id not in self.tenant_ids:
                self.tenant_ids.append(tenant.id)
        identity = find_external_identity(request.owner_issuer, request.owner_subject)
        if identity is not None and identity.user_id not in self.user_ids:
            self.user_ids.append(identity.user_id)

    def run(self) -> None:
        for tenant_id in self.tenant_ids:
            with tenant_session_scope(tenant_id) as session:
                for table in (
                    "core.membership_roles",
                    "core.role_permissions",
                    "core.roles",
                    "core.tenant_memberships",
                ):
                    session.execute(
                        text(f"DELETE FROM {table} WHERE tenant_id = :t"), {"t": str(tenant_id)}
                    )
            admin = build_engine(get_migrations_database_config())
            try:
                with session_scope(session_factory=build_session_factory(admin)) as session:
                    session.execute(
                        text("DELETE FROM core.audit_log WHERE tenant_id = :t"),
                        {"t": str(tenant_id)},
                    )
            finally:
                admin.dispose()
        with session_scope() as session:
            for user_id in self.user_ids:
                session.execute(
                    text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": str(user_id)}
                )
                session.execute(
                    text("DELETE FROM core.external_identities WHERE user_id = :u"),
                    {"u": str(user_id)},
                )
                session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(user_id)})
            for tenant_id in self.tenant_ids:
                session.execute(
                    text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)}
                )


@pytest.fixture
def cleanup() -> Iterator[_Cleanup]:
    tracker = _Cleanup()
    yield tracker
    tracker.run()


def _owner_role(tenant_id: uuid.UUID) -> Role:
    roles = [r for r in list_roles(tenant_id) if r.name == FIRST_TENANT_OWNER_ROLE_NAME]
    assert len(roles) == 1
    return roles[0]


def _granted_permissions(tenant_id: uuid.UUID, role_id: uuid.UUID) -> set[tuple[str, str]]:
    with tenant_session_scope(tenant_id) as session:
        rows = session.execute(
            select(Permission.resource, Permission.action)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id)
        ).all()
    return {(r[0], r[1]) for r in rows}


# --- Test 1: first tenant ------------------------------------------------------------


def test_first_tenant_bootstrap_provisions_everything_and_audits_each_step(
    cleanup: _Cleanup,
) -> None:
    request = _request(_unique("f02-first"), _unique("sub"))
    try:
        result = bootstrap_first_tenant(request)
    finally:
        cleanup.track_request(request)

    tenant = get_tenant(result.tenant_id)
    assert tenant.name == request.tenant_name
    assert tenant.status == TenantStatus.ACTIVE.value == result.tenant_status

    identity = find_external_identity(request.owner_issuer, request.owner_subject)
    assert identity is not None and identity.user_id == result.owner_user_id

    membership = get_membership(tenant.id, result.owner_user_id)
    assert membership is not None and membership.id == result.membership_id

    role = _owner_role(tenant.id)
    assert role.id == result.role_id
    assert _granted_permissions(tenant.id, role.id) == set(FIRST_TENANT_OWNER_PERMISSIONS)
    assert [a.role_id for a in list_membership_roles(tenant.id, membership.id)] == [role.id]

    assert result.created == (
        "tenant",
        "activation",
        "owner_user",
        "owner_role",
        "grant:tenant:read_status",
        "owner_membership",
        "role_assignment",
    )
    for resource, action in FIRST_TENANT_OWNER_PERMISSIONS:
        assert can(
            actor_id=result.owner_user_id, tenant_id=tenant.id, action=action, resource=resource
        )

    actions = [e.action for e in list_audit_entries(tenant.id)]
    assert sorted(actions) == sorted(
        [
            "tenant.bootstrap_created",
            "tenant.activated",
            "rbac.role_created",
            "rbac.permission_granted",
            "tenant.owner_membership_created",
            "rbac.role_assigned",
        ]
    )


# --- Test 2: repeat bootstrap ---------------------------------------------------------


def test_identical_second_run_is_a_deterministic_noop(cleanup: _Cleanup) -> None:
    request = _request(_unique("f02-repeat"), _unique("sub"))
    try:
        first = bootstrap_first_tenant(request)
        second = bootstrap_first_tenant(request)
        third = bootstrap_first_tenant(request)
    finally:
        cleanup.track_request(request)

    assert second.was_noop and third.was_noop
    for later in (second, third):
        assert (later.tenant_id, later.owner_user_id, later.membership_id, later.role_id) == (
            first.tenant_id,
            first.owner_user_id,
            first.membership_id,
            first.role_id,
        )
    assert len(find_tenants_by_name(request.tenant_name)) == 1
    assert len(list_tenant_members(first.tenant_id)) == 1
    assert len([r for r in list_roles(first.tenant_id)]) == 1
    assert len(_granted_permissions(first.tenant_id, first.role_id)) == len(
        FIRST_TENANT_OWNER_PERMISSIONS
    )
    assert len(list_membership_roles(first.tenant_id, first.membership_id)) == 1
    # No extra audit entries on a no-op run: six for the first run, none after.
    assert len(list_audit_entries(first.tenant_id)) == 6


# --- Test 4: partial failure ----------------------------------------------------------


def test_failure_before_role_assignment_leaves_no_privilege_and_rerun_completes(
    cleanup: _Cleanup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The last mutation is the only one that confers authority: fail
    right there, prove the owner can do nothing, then re-run and prove
    the bootstrap resumes without duplicating anything."""
    request = _request(_unique("f02-partial"), _unique("sub"))
    real_assign_role = bootstrap_module.assign_role

    def failing_assign_role(*args: object, **kwargs: object) -> object:
        raise RuntimeError("simulated crash between membership and assignment")

    monkeypatch.setattr(bootstrap_module, "assign_role", failing_assign_role)
    try:
        with pytest.raises(RuntimeError):
            bootstrap_first_tenant(request)
    finally:
        cleanup.track_request(request)

    tenants = find_tenants_by_name(request.tenant_name)
    assert len(tenants) == 1
    tenant = tenants[0]
    identity = find_external_identity(request.owner_issuer, request.owner_subject)
    assert identity is not None
    membership = get_membership(tenant.id, identity.user_id)
    assert membership is not None, "membership exists, but..."
    assert list_membership_roles(tenant.id, membership.id) == [], "...carries no role"
    for resource, action in FIRST_TENANT_OWNER_PERMISSIONS:
        assert not can(
            actor_id=identity.user_id, tenant_id=tenant.id, action=action, resource=resource
        )

    monkeypatch.setattr(bootstrap_module, "assign_role", real_assign_role)
    resumed = bootstrap_first_tenant(request)
    assert resumed.tenant_id == tenant.id
    assert resumed.membership_id == membership.id
    assert resumed.created == ("role_assignment",)
    for resource, action in FIRST_TENANT_OWNER_PERMISSIONS:
        assert can(actor_id=identity.user_id, tenant_id=tenant.id, action=action, resource=resource)
    assert len(find_tenants_by_name(request.tenant_name)) == 1
    assert len(list_tenant_members(tenant.id)) == 1


def test_failure_before_membership_leaves_only_inert_state(
    cleanup: _Cleanup, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(_unique("f02-inert"), _unique("sub"))

    def failing_add_membership(*args: object, **kwargs: object) -> object:
        raise RuntimeError("simulated crash before membership")

    monkeypatch.setattr(bootstrap_module, "add_tenant_membership", failing_add_membership)
    try:
        with pytest.raises(RuntimeError):
            bootstrap_first_tenant(request)
    finally:
        cleanup.track_request(request)

    tenant = find_tenants_by_name(request.tenant_name)[0]
    assert tenant.status == TenantStatus.ACTIVE.value
    assert list_tenant_members(tenant.id) == []
    identity = find_external_identity(request.owner_issuer, request.owner_subject)
    assert identity is not None
    assert not can(
        actor_id=identity.user_id, tenant_id=tenant.id, action="read_status", resource="tenant"
    )


# --- Test 5: least privilege -----------------------------------------------------------


def test_owner_receives_exactly_the_intended_permissions(cleanup: _Cleanup) -> None:
    request = _request(_unique("f02-least"), _unique("sub"))
    try:
        result = bootstrap_first_tenant(request)
    finally:
        cleanup.track_request(request)

    assert _granted_permissions(result.tenant_id, result.role_id) == set(
        FIRST_TENANT_OWNER_PERMISSIONS
    )
    assert can(
        actor_id=result.owner_user_id,
        tenant_id=result.tenant_id,
        action="read_status",
        resource="tenant",
    )
    for resource, action in (
        ("tenant", "delete"),
        ("tenant", "update"),
        ("role", "create"),
        ("api_key", "create"),
        ("control_plane.self_learning.adaptation", "activate"),
        ("control_plane.self_learning.adaptation", "rollback"),
        ("secrets", "read"),
    ):
        assert not can(
            actor_id=result.owner_user_id,
            tenant_id=result.tenant_id,
            action=action,
            resource=resource,
        ), f"owner must not hold {resource}:{action}"


# --- Test 6 + 7: tenant isolation, RLS, restricted role --------------------------------


def test_two_bootstrapped_tenants_are_isolated_from_each_other(cleanup: _Cleanup) -> None:
    request_a = _request(_unique("f02-iso-a"), _unique("sub-a"))
    request_b = _request(_unique("f02-iso-b"), _unique("sub-b"))
    try:
        a = bootstrap_first_tenant(request_a)
        b = bootstrap_first_tenant(request_b)
    finally:
        cleanup.track_request(request_a)
        cleanup.track_request(request_b)

    assert a.tenant_id != b.tenant_id and a.owner_user_id != b.owner_user_id

    # RBAC chokepoint: each owner is authorized only in their own tenant.
    for resource, action in FIRST_TENANT_OWNER_PERMISSIONS:
        assert can(
            actor_id=a.owner_user_id, tenant_id=a.tenant_id, action=action, resource=resource
        )
        assert can(
            actor_id=b.owner_user_id, tenant_id=b.tenant_id, action=action, resource=resource
        )
        assert not can(
            actor_id=a.owner_user_id, tenant_id=b.tenant_id, action=action, resource=resource
        )
        assert not can(
            actor_id=b.owner_user_id, tenant_id=a.tenant_id, action=action, resource=resource
        )
    assert get_membership(b.tenant_id, a.owner_user_id) is None
    assert get_membership(a.tenant_id, b.owner_user_id) is None

    # RLS alone (no application filter): tenant A's context cannot see B's
    # roles/memberships/assignments even when asking for them explicitly.
    with tenant_session_scope(a.tenant_id) as session:
        for table in ("core.roles", "core.tenant_memberships", "core.membership_roles"):
            visible = session.execute(
                text(f"SELECT count(*) FROM {table} WHERE tenant_id = :b"), {"b": str(b.tenant_id)}
            ).scalar_one()
            assert visible == 0, f"{table}: tenant A must not see tenant B rows"
        assert (
            session.execute(
                text("SELECT count(*) FROM core.roles WHERE tenant_id = :a"),
                {"a": str(a.tenant_id)},
            ).scalar_one()
            == 1
        )


def test_owner_session_reaches_only_its_own_tenant_over_http(cleanup: _Cleanup) -> None:
    try:
        redis_url = get_ratelimit_config().redis_url
        import redis as redis_sync

        redis_sync.Redis.from_url(redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis (rate limiter) not reachable for the HTTP check: {exc}")
    from api.main import app
    from fastapi.testclient import TestClient

    request_a = _request(_unique("f02-http-a"), _unique("sub-a"))
    request_b = _request(_unique("f02-http-b"), _unique("sub-b"))
    try:
        a = bootstrap_first_tenant(request_a)
        b = bootstrap_first_tenant(request_b)
        _, token_a = issue_session(a.owner_user_id)
        client = TestClient(app)
        headers = {"Authorization": f"Bearer {token_a}"}
        own = client.get(f"/v1/tenants/{a.tenant_id}/status", headers=headers)
        other = client.get(f"/v1/tenants/{b.tenant_id}/status", headers=headers)
    finally:
        cleanup.track_request(request_a)
        cleanup.track_request(request_b)

    assert own.status_code == 200
    assert own.json() == {"id": str(a.tenant_id), "name": request_a.tenant_name, "status": "active"}
    assert other.status_code == 404  # not a member: identical non-enumerating response


def test_rls_force_rls_and_restricted_role_remain_intact(cleanup: _Cleanup) -> None:
    request = _request(_unique("f02-rls"), _unique("sub"))
    try:
        bootstrap_first_tenant(request)
    finally:
        cleanup.track_request(request)

    validation = validate_application_role(get_engine())
    admin = build_engine(get_migrations_database_config())
    try:
        with admin.connect() as conn:
            role_row = conn.execute(
                text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = :r"),
                {"r": validation.role_name},
            ).one()
            assert role_row == (False, False)
            for table in ("tenant_memberships", "roles", "role_permissions", "membership_roles"):
                rls = conn.execute(
                    text(
                        "SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
                        "JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = 'core' AND c.relname = :t"
                    ),
                    {"t": table},
                ).one()
                assert rls == (True, True), f"core.{table} must keep RLS + FORCE RLS"
                policies = conn.execute(
                    text(
                        "SELECT count(*) FROM pg_policies WHERE schemaname = 'core' "
                        "AND tablename = :t"
                    ),
                    {"t": table},
                ).scalar_one()
                assert policies >= 1
    finally:
        admin.dispose()


# --- Test 8: audit -------------------------------------------------------------------------


def test_audit_entries_carry_identifiers_only_and_no_secret(cleanup: _Cleanup) -> None:
    request = _request(_unique("f02-audit"), _unique("sub"))
    try:
        result = bootstrap_first_tenant(request)
    finally:
        cleanup.track_request(request)

    entries = list_audit_entries(result.tenant_id)
    assert len(entries) == 6
    for entry in entries:
        assert entry.actor_type == "system"
        assert entry.actor_user_id is None
        assert entry.outcome == "success"
        metadata = entry.entry_metadata or {}
        assert metadata.get("bootstrap") == "first_tenant"
        for key in metadata:
            assert key.lower() not in _FORBIDDEN_KEYS
        serialized = str(metadata)
        assert request.owner_subject not in serialized
        assert request.owner_issuer not in serialized
        assert "postgresql://" not in serialized


# --- Test 3 (DB side): conflicts and refused states ----------------------------------------


def test_same_name_owned_by_another_identity_is_refused_without_a_second_tenant(
    cleanup: _Cleanup,
) -> None:
    name = _unique("f02-conflict")
    first = _request(name, _unique("sub-owner"))
    intruder = _request(name, _unique("sub-intruder"))
    try:
        bootstrap_first_tenant(first)
        with pytest.raises(BootstrapConflictError):
            bootstrap_first_tenant(intruder)
        with pytest.raises(BootstrapConflictError):
            assess_bootstrap(intruder)
    finally:
        cleanup.track_request(first)
        cleanup.track_request(intruder)

    assert len(find_tenants_by_name(name)) == 1
    assert find_external_identity(intruder.owner_issuer, intruder.owner_subject) is None
    tenant = find_tenants_by_name(name)[0]
    assert len(list_tenant_members(tenant.id)) == 1


def test_ambiguous_name_is_refused(cleanup: _Cleanup) -> None:
    from core.tenancy import create_tenant

    name = _unique("f02-ambiguous")
    create_tenant(name)
    create_tenant(name)
    request = _request(name, _unique("sub"))
    try:
        with pytest.raises(BootstrapConflictError, match="more than one"):
            bootstrap_first_tenant(request)
        with pytest.raises(BootstrapConflictError, match="more than one"):
            assess_bootstrap(request)
    finally:
        cleanup.track_request(request)
    assert len(find_tenants_by_name(name)) == 2  # nothing added
    assert find_external_identity(request.owner_issuer, request.owner_subject) is None


def test_suspended_tenant_is_never_resurrected(cleanup: _Cleanup) -> None:
    request = _request(_unique("f02-suspended"), _unique("sub"))
    try:
        result = bootstrap_first_tenant(request)
        transition_tenant_status(result.tenant_id, TenantStatus.SUSPENDED)
        with pytest.raises(BootstrapConflictError, match="suspended"):
            bootstrap_first_tenant(request)
    finally:
        cleanup.track_request(request)
    assert get_tenant(result.tenant_id).status == TenantStatus.SUSPENDED.value


def test_existing_member_without_the_owner_role_is_completed_not_duplicated(
    cleanup: _Cleanup,
) -> None:
    """A tenant whose only member is this identity (e.g. created by hand
    before the bootstrap existed) is completed in place."""
    from core.identity import link_external_identity
    from core.tenancy import create_tenant

    request = _request(_unique("f02-existing"), _unique("sub"))
    tenant = create_tenant(request.tenant_name)
    user = create_user()
    link_external_identity(user.id, request.owner_issuer, request.owner_subject)
    add_tenant_membership(tenant.id, user.id)
    try:
        result = bootstrap_first_tenant(request)
    finally:
        cleanup.track_request(request)

    assert result.tenant_id == tenant.id and result.owner_user_id == user.id
    assert "tenant" not in result.created and "owner_user" not in result.created
    assert "owner_membership" not in result.created
    assert "activation" in result.created and "role_assignment" in result.created
    assert get_role_permission(tenant.id, result.role_id, _first_permission_id()) is not None


def _first_permission_id() -> uuid.UUID:
    from core.rbac import get_permission

    resource, action = FIRST_TENANT_OWNER_PERMISSIONS[0]
    permission = get_permission(resource, action)
    assert permission is not None
    return permission.id


# --- Dry run ------------------------------------------------------------------------------


def test_dry_run_reads_only(cleanup: _Cleanup) -> None:
    request = _request(_unique("f02-dry"), _unique("sub"))
    try:
        plan = assess_bootstrap(request)
        assert plan.matching_tenants == 0 and plan.would_create[0] == "tenant"
        assert find_tenants_by_name(request.tenant_name) == []
        assert find_external_identity(request.owner_issuer, request.owner_subject) is None

        result = bootstrap_first_tenant(request)
        plan_after = assess_bootstrap(request)
    finally:
        cleanup.track_request(request)
    assert plan_after.matching_tenants == 1
    assert plan_after.tenant_id == result.tenant_id
    assert plan_after.owner_already_member is True


# --- The one Core addition: find_tenants_by_name ------------------------------------------


def test_find_tenants_by_name_is_exact_and_ordered(cleanup: _Cleanup) -> None:
    from core.tenancy import create_tenant

    name = _unique("f02-find")
    older = create_tenant(name)
    newer = create_tenant(name)
    create_tenant(name + "-suffix")
    request = _request(name, _unique("sub"))
    request_suffix = _request(name + "-suffix", _unique("sub"))
    cleanup.track_request(request)
    cleanup.track_request(request_suffix)

    found = find_tenants_by_name(name)
    assert [t.id for t in found] == [older.id, newer.id]
    assert find_tenants_by_name(name.upper()) == []
    assert find_tenants_by_name(name + " ") == []
