"""Foundation Authority & Evidence -- behavioral proof against a real
PostgreSQL database (docs/ADR/0031-foundation-authority-and-evidence.md).

- An authority-changing Core operation runs only for an explicit typed
  caller that `saas_os.core.rbac.can()` authorizes (or the one system purpose it
  names); missing, wrong-typed, unauthorized, cross-tenant, denied and
  inactive callers are all refused before any write.
- The change and its audit entry commit together: a forced failure after
  both were written leaves neither behind.
- The audit entry names the real caller, target and tenant, in the
  persisted `entry_metadata` column.
- Support access never satisfies an authority resource.
- `User.is_active == False` never produces an authenticated or authorized
  actor -- sessions, API keys and `can()` alike.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

from lifecycle_callers import platform_operator
from saas_os.api.main import create_app
from saas_os.core.api_keys import InvalidApiKeyError, create_api_key, validate_api_key
from saas_os.core.audit_log import record_in_transaction
from saas_os.core.authority import (
    CallerTypeError,
    ServiceAccountCaller,
    SystemAuthority,
    SystemCaller,
    UserCaller,
)
from saas_os.core.identity import InactiveUserError, issue_session, validate_session
from saas_os.core.identity.errors import InvitationNotAuthorizedError
from saas_os.core.identity.service import (
    add_tenant_membership,
    create_invitation,
    create_service_account,
    create_user,
    disable_service_account,
    get_membership,
    suspend_membership,
)
from saas_os.core.rbac import can, list_roles
from saas_os.core.rbac.authorization import AUTHORITY_RESOURCES
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.scope import RoleScope
from saas_os.core.rbac.service import (
    approve_support_access,
    assign_first_role_for_new_tenant,
    assign_role,
    assign_service_account_role,
    create_delegation,
    create_deny,
    create_role,
    create_support_access_request,
    delete_role,
    grant_permission,
    register_permission,
    remove_role,
    revoke_permission,
    revoke_tenant_support_access,
)
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db import tenant_session_scope
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine
from saas_os.infra.db.session import build_session_factory, session_scope
from saas_os.infra.observability import bind_correlation_context

pytestmark = pytest.mark.integration

PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_TENANT_TABLES = (
    "audit_log",
    "api_keys",
    "service_account_roles",
    "membership_roles",
    "role_permissions",
    "delegation_grants",
    "deny_grants",
    "support_access_requests",
    "invitations",
    "roles",
    "service_accounts",
    "tenant_memberships",
    "tenant_ancestry",
)


@pytest.fixture(autouse=True)
def _require_database() -> None:
    get_database_config.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.roles LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable/migrated: {exc}")
    finally:
        engine.dispose()


def _admin_execute(sql: str, params: dict[str, object]) -> list[tuple]:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            result = session.execute(text(sql), params)
            return (
                [tuple(row) for row in result] if sql.lstrip().upper().startswith("SELECT") else []
            )
    finally:
        engine.dispose()


@dataclass
class World:
    tenants: list[uuid.UUID] = field(default_factory=list)
    users: list[uuid.UUID] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)

    def tenant(self, parent_id: uuid.UUID | None = None) -> uuid.UUID:
        tenant_id = create_tenant(
            f"fae-{uuid.uuid4().hex[:10]}", parent_id=parent_id, caller=platform_operator()
        ).id
        self.tenants.append(tenant_id)
        return tenant_id

    def user(self) -> uuid.UUID:
        user_id = create_user().id
        self.users.append(user_id)
        return user_id

    def resource(self) -> str:
        name = f"faeprobe-{uuid.uuid4().hex[:8]}"
        self.resources.append(name)
        return name

    def principal(self, tenant_id: uuid.UUID, *capabilities: tuple[str, str]) -> UserCaller:
        """A member of `tenant_id` holding exactly `capabilities`, provisioned
        with explicit provisioning authority."""
        user_id = self.user()
        membership = add_tenant_membership(tenant_id, user_id, caller=PROVISIONING)
        role = create_role(tenant_id, f"role-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        for resource, action in capabilities:
            permission = register_permission(resource, action)
            grant_permission(tenant_id, role.id, permission.id, caller=PROVISIONING)
        assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=PROVISIONING)
        return UserCaller(user_id)

    def service_account(
        self, tenant_id: uuid.UUID, *capabilities: tuple[str, str]
    ) -> ServiceAccountCaller:
        account = create_service_account(
            tenant_id, f"sa-{uuid.uuid4().hex[:8]}", caller=PROVISIONING
        )
        if capabilities:
            admin = self.principal(tenant_id, ("service_account_role", "create"), *capabilities)
            role = create_role(tenant_id, f"sa-role-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
            for resource, action in capabilities:
                permission = register_permission(resource, action)
                grant_permission(tenant_id, role.id, permission.id, caller=PROVISIONING)
            assign_service_account_role(
                caller=admin, tenant_id=tenant_id, service_account_id=account.id, role_id=role.id
            )
        return ServiceAccountCaller(account.id, tenant_id)

    def set_active(self, user_id: uuid.UUID, active: bool) -> None:
        _admin_execute(
            "UPDATE core.users SET is_active = :a WHERE id = :u", {"a": active, "u": str(user_id)}
        )

    def cleanup(self) -> None:
        for tenant_id in reversed(self.tenants):
            for table in _TENANT_TABLES:
                _admin_execute(
                    f"DELETE FROM core.{table} WHERE tenant_id = :t",  # noqa: S608 -- fixed names
                    {"t": str(tenant_id)},
                )
            _admin_execute(
                "DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t",
                {"t": str(tenant_id)},
            )
            _admin_execute("DELETE FROM core.tenants WHERE id = :t", {"t": str(tenant_id)})
        for user_id in self.users:
            _admin_execute(
                "DELETE FROM core.audit_log WHERE actor_user_id = :u", {"u": str(user_id)}
            )
            _admin_execute("DELETE FROM core.sessions WHERE user_id = :u", {"u": str(user_id)})
            _admin_execute("DELETE FROM core.users WHERE id = :u", {"u": str(user_id)})
        for resource in self.resources:
            _admin_execute("DELETE FROM core.permissions WHERE resource = :r", {"r": resource})


@pytest.fixture
def world() -> Iterator[World]:
    built = World()
    try:
        yield built
    finally:
        built.cleanup()


def _audit_rows(tenant_id: uuid.UUID, action: str) -> list[tuple]:
    """The persisted audit row itself. The JSON payload's database column is
    `metadata` -- `entry_metadata` is only the ORM attribute name."""
    return _admin_execute(
        "SELECT actor_type, actor_user_id, actor_service_account_id, resource_type, "
        "resource_id, metadata FROM core.audit_log WHERE tenant_id = :t AND action = :a",
        {"t": str(tenant_id), "a": action},
    )


def _audit_row_for(tenant_id: uuid.UUID, action: str, resource_id: uuid.UUID) -> tuple:
    (row,) = [row for row in _audit_rows(tenant_id, action) if row[4] == str(resource_id)]
    return row


def _role_names(tenant_id: uuid.UUID) -> set[str]:
    return {role.name for role in list_roles(tenant_id)}


# --- 1. Caller contract ------------------------------------------------------------------


def test_missing_or_untyped_caller_is_refused_before_any_write(world: World) -> None:
    tenant_id = world.tenant()
    with pytest.raises(TypeError):
        create_role(tenant_id, "no-caller")  # type: ignore[call-arg]
    for bad in (None, str(world.user()), {"user_id": world.user()}):
        with pytest.raises(CallerTypeError):
            create_role(tenant_id, "untyped", caller=bad)  # type: ignore[arg-type]
    assert _role_names(tenant_id) == set()
    assert _audit_rows(tenant_id, "role.create") == []


def test_wrong_caller_type_is_refused(world: World) -> None:
    tenant_id = world.tenant()
    admin = world.principal(tenant_id, ("delegation_grant", "create"))
    permission = register_permission(world.resource(), "read")
    with pytest.raises(CallerTypeError):
        create_delegation(
            caller=PROVISIONING,  # type: ignore[arg-type] -- a delegation needs a human delegator
            delegate_user_id=admin.user_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
    with pytest.raises(CallerTypeError):
        assign_role(
            tenant_id,
            uuid.uuid4(),
            uuid.uuid4(),
            caller=ServiceAccountCaller(uuid.uuid4(), tenant_id),  # type: ignore[arg-type]
        )
    # A system purpose the operation does not accept is not a bypass either.
    with pytest.raises(AuthorityNotAuthorizedError):
        create_role(
            tenant_id, "purge-cannot-provision", caller=SystemCaller(SystemAuthority.TENANT_PURGE)
        )
    with pytest.raises(AuthorityNotAuthorizedError):
        revoke_tenant_support_access(tenant_id, caller=PROVISIONING)
    assert "purge-cannot-provision" not in _role_names(tenant_id)


def test_ambient_correlation_context_confers_no_authority(world: World) -> None:
    tenant_id = world.tenant()
    authorized = world.principal(tenant_id, ("role", "create"))
    unauthorized = world.principal(tenant_id)
    with bind_correlation_context(tenant_id=str(tenant_id), request_id=str(authorized.user_id)):
        with pytest.raises(AuthorityNotAuthorizedError):
            create_role(tenant_id, "ambient", caller=unauthorized)
    assert "ambient" not in _role_names(tenant_id)


# --- 2. Authorization -------------------------------------------------------------------


@pytest.mark.parametrize(
    "operation",
    [
        "create_role",
        "delete_role",
        "grant_permission",
        "revoke_permission",
        "remove_role",
        "add_tenant_membership",
        "create_service_account",
        "disable_service_account",
        "suspend_membership",
    ],
)
def test_unauthorized_principal_cannot_change_authority(world: World, operation: str) -> None:
    tenant_id = world.tenant()
    nobody = world.principal(tenant_id)  # a member with no capability at all
    role = create_role(tenant_id, "target-role", caller=PROVISIONING)
    permission = register_permission(world.resource(), "read")
    member = world.user()
    membership = add_tenant_membership(tenant_id, member, caller=PROVISIONING)
    account = create_service_account(tenant_id, "target-sa", caller=PROVISIONING)
    calls = {
        "create_role": lambda: create_role(tenant_id, "denied", caller=nobody),
        "delete_role": lambda: delete_role(tenant_id, role.id, caller=nobody),
        "grant_permission": lambda: grant_permission(
            tenant_id, role.id, permission.id, caller=nobody
        ),
        "revoke_permission": lambda: revoke_permission(
            tenant_id, role.id, permission.id, caller=nobody
        ),
        "remove_role": lambda: remove_role(tenant_id, membership.id, role.id, caller=nobody),
        "add_tenant_membership": lambda: add_tenant_membership(
            tenant_id, world.user(), caller=nobody
        ),
        "create_service_account": lambda: create_service_account(
            tenant_id, "denied-sa", caller=nobody
        ),
        "disable_service_account": lambda: disable_service_account(
            tenant_id, account.id, caller=nobody
        ),
        "suspend_membership": lambda: suspend_membership(tenant_id, membership.id, caller=nobody),
    }
    before = _admin_execute(
        "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t", {"t": str(tenant_id)}
    )
    with pytest.raises(AuthorityNotAuthorizedError):
        calls[operation]()
    after = _admin_execute(
        "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t", {"t": str(tenant_id)}
    )
    assert after == before  # nothing written, nothing recorded
    assert "denied" not in _role_names(tenant_id)


def test_authorized_principal_succeeds_and_the_evidence_names_it(world: World) -> None:
    tenant_id = world.tenant()
    admin = world.principal(tenant_id, ("role", "create"))
    role = create_role(tenant_id, "made-by-admin", caller=admin)
    assert _audit_row_for(tenant_id, "role.create", role.id) == (
        "user",
        admin.user_id,
        None,
        "role",
        str(role.id),
        {"role_name": "made-by-admin"},
    )


def test_service_account_caller_is_authorized_through_can(world: World) -> None:
    tenant_id = world.tenant()
    machine = world.service_account(tenant_id, ("role", "create"))
    role = create_role(tenant_id, "made-by-machine", caller=machine)
    actor_type, actor_user, actor_sa, *_ = _audit_row_for(tenant_id, "role.create", role.id)
    assert (actor_type, actor_user, actor_sa) == (
        "service_account",
        None,
        machine.service_account_id,
    )
    assert role.name == "made-by-machine"

    unprivileged = world.service_account(tenant_id)
    with pytest.raises(AuthorityNotAuthorizedError):
        create_role(tenant_id, "denied-machine", caller=unprivileged)


def test_cross_tenant_principal_is_refused(world: World) -> None:
    tenant_a, tenant_b = world.tenant(), world.tenant()
    admin_of_a = world.principal(tenant_a, ("role", "create"))
    with pytest.raises(AuthorityNotAuthorizedError):
        create_role(tenant_b, "from-a", caller=admin_of_a)
    assert _role_names(tenant_b) == set()


def test_explicit_deny_overrides_the_capability(world: World) -> None:
    tenant_id = world.tenant()
    admin = world.principal(tenant_id, ("role", "create"))
    grantor = world.principal(tenant_id, ("deny_grant", "create"))
    create_role(tenant_id, "before-deny", caller=admin)
    create_deny(
        caller=grantor,
        principal_user_id=admin.user_id,
        tenant_id=tenant_id,
        scope_mode=RoleScope.SELF,
        permission_id=register_permission("role", "create").id,
    )
    with pytest.raises(AuthorityNotAuthorizedError):
        create_role(tenant_id, "after-deny", caller=admin)


def test_valid_delegated_authority_is_honored(world: World) -> None:
    tenant_id = world.tenant()
    delegator = world.principal(tenant_id, ("role", "create"), ("delegation_grant", "create"))
    delegate = UserCaller(world.user())  # no membership, no role of its own
    with pytest.raises(AuthorityNotAuthorizedError):
        create_role(tenant_id, "before-delegation", caller=delegate)
    create_delegation(
        caller=delegator,
        delegate_user_id=delegate.user_id,
        tenant_id=tenant_id,
        scope_mode=RoleScope.SELF,
        permission_id=register_permission("role", "create").id,
    )
    create_role(tenant_id, "delegated", caller=delegate)
    assert "delegated" in _role_names(tenant_id)


def test_grant_permission_cannot_amplify_the_callers_own_authority(world: World) -> None:
    tenant_id = world.tenant()
    held = register_permission(world.resource(), "read")
    not_held = register_permission(world.resource(), "write")
    admin = world.principal(tenant_id, ("role_permission", "grant"), (held.resource, "read"))
    role = create_role(tenant_id, "target", caller=PROVISIONING)
    grant_permission(tenant_id, role.id, held.id, caller=admin)
    with pytest.raises(AuthorityNotAuthorizedError):
        grant_permission(tenant_id, role.id, not_held.id, caller=admin)
    machine = world.service_account(
        tenant_id, ("role_permission", "grant"), (held.resource, "read")
    )
    with pytest.raises(AuthorityNotAuthorizedError):  # anti-amplification is human-only
        grant_permission(tenant_id, role.id, held.id, caller=machine)


def test_provisioning_authority_is_recorded_as_system(world: World) -> None:
    tenant_id = world.tenant()
    role = create_role(tenant_id, "provisioned", caller=PROVISIONING)
    assert _audit_rows(tenant_id, "role.create") == [
        (
            "system",
            None,
            None,
            "role",
            str(role.id),
            {
                "role_name": "provisioned",
                "system_authority": "provisioning",
            },
        )
    ]


# --- 3. Same-transaction evidence ----------------------------------------------------------


def _fail_after_recording(monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    import saas_os.core.audit_log

    real = saas_os.core.audit_log.record_in_transaction

    def _record_then_fail(*args: object, **kwargs: object) -> object:
        real(*args, **kwargs)  # type: ignore[arg-type]
        raise RuntimeError("forced failure after the change and its evidence were written")

    monkeypatch.setattr(target, _record_then_fail)


def test_a_rolled_back_change_leaves_no_evidence_behind(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = world.tenant()
    admin = world.principal(tenant_id, ("role", "create"), ("membership", "create"))
    _fail_after_recording(monkeypatch, "saas_os.core.rbac.service.record_in_transaction")
    with pytest.raises(RuntimeError, match="forced failure"):
        create_role(tenant_id, "rolled-back", caller=admin)
    assert "rolled-back" not in _role_names(tenant_id)
    assert [row for row in _audit_rows(tenant_id, "role.create") if row[1] == admin.user_id] == []

    member = world.user()
    _fail_after_recording(monkeypatch, "saas_os.core.identity.service.record_in_transaction")
    with pytest.raises(RuntimeError, match="forced failure"):
        add_tenant_membership(tenant_id, member, caller=admin)
    assert get_membership(tenant_id, member) is None
    assert [
        row for row in _audit_rows(tenant_id, "membership.create") if row[1] == admin.user_id
    ] == []


def test_a_committed_change_always_has_its_evidence(world: World) -> None:
    tenant_id = world.tenant()
    admin = world.principal(tenant_id, ("membership", "create"))
    member = world.user()
    membership = add_tenant_membership(tenant_id, member, caller=admin)
    rows = _audit_rows(tenant_id, "membership.create")
    assert (
        "user",
        admin.user_id,
        None,
        "tenant_membership",
        str(membership.id),
        {"user_id": str(member)},
    ) in rows


def test_evidence_cannot_be_written_for_another_tenant(world: World) -> None:
    """`record_in_transaction()` writes through the mutation's own
    tenant-scoped session; RLS refuses an entry for any other tenant."""
    tenant_a, tenant_b = world.tenant(), world.tenant()
    with pytest.raises(DBAPIError):
        with tenant_session_scope(tenant_a) as session:
            record_in_transaction(
                session,
                caller=PROVISIONING,
                tenant_id=tenant_b,
                action="role.create",
                resource_type="role",
            )
    assert _audit_rows(tenant_b, "role.create") == []


# --- 4. Support access ---------------------------------------------------------------------


def test_support_access_never_satisfies_an_authority_resource(world: World) -> None:
    tenant_id = world.tenant()
    engineer = UserCaller(world.user())
    approver = world.principal(tenant_id, ("support_access_request", "approve"))
    request = create_support_access_request(
        caller=engineer,
        tenant_id=tenant_id,
        reason="investigate a ticket",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    approve_support_access(caller=approver, tenant_id=tenant_id, request_id=request.id)

    ordinary = world.resource()
    assert can(actor_id=engineer.user_id, tenant_id=tenant_id, action="read", resource=ordinary)
    for resource in sorted(AUTHORITY_RESOURCES):
        for action in ("create", "grant", "delete", "suspend", "approve"):
            assert not can(
                actor_id=engineer.user_id, tenant_id=tenant_id, action=action, resource=resource
            ), (resource, action)

    with pytest.raises(AuthorityNotAuthorizedError):
        create_role(tenant_id, "support-made", caller=engineer)
    with pytest.raises(AuthorityNotAuthorizedError):
        add_tenant_membership(tenant_id, engineer.user_id, caller=engineer)
    with pytest.raises(InvitationNotAuthorizedError):
        create_invitation(tenant_id, "support@example.com", caller=engineer)
    assert get_membership(tenant_id, engineer.user_id) is None


# --- 5. User.is_active -------------------------------------------------------------------------


def test_inactive_user_is_never_an_authorized_actor(world: World) -> None:
    tenant_id = world.tenant()
    admin = world.principal(tenant_id, ("role", "create"))
    assert can(actor_id=admin.user_id, tenant_id=tenant_id, action="create", resource="role")

    world.set_active(admin.user_id, False)
    assert not can(actor_id=admin.user_id, tenant_id=tenant_id, action="create", resource="role")
    with pytest.raises(AuthorityNotAuthorizedError):
        create_role(tenant_id, "inactive-made", caller=admin)
    with pytest.raises(AuthorityNotAuthorizedError):
        create_api_key(tenant_id, "inactive-key", caller=admin)
    with pytest.raises(AuthorityNotAuthorizedError):
        create_support_access_request(
            caller=admin,
            tenant_id=tenant_id,
            reason="x",
            requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

    world.set_active(admin.user_id, True)
    create_role(tenant_id, "active-again", caller=admin)


def test_inactive_user_gets_no_session_and_existing_sessions_stop_working(world: World) -> None:
    tenant_id = world.tenant()
    member = world.principal(tenant_id)
    _, raw_token = issue_session(member.user_id)
    assert validate_session(raw_token).user_id == member.user_id
    client = TestClient(create_app())
    headers = {"Authorization": f"Bearer {raw_token}"}
    assert client.get("/auth/me", headers=headers).status_code == 200

    world.set_active(member.user_id, False)
    with pytest.raises(InactiveUserError):
        validate_session(raw_token)
    with pytest.raises(InactiveUserError):
        issue_session(member.user_id)
    assert client.get("/auth/me", headers=headers).status_code == 401

    # Documented contract: the check is live, the session is not revoked --
    # it is bounded by its own expiry, and reactivation restores it.
    world.set_active(member.user_id, True)
    assert validate_session(raw_token).user_id == member.user_id


def test_inactive_users_api_key_does_not_authenticate(world: World) -> None:
    tenant_id = world.tenant()
    member = world.principal(tenant_id)
    key, raw_key = create_api_key(tenant_id, "member-key", caller=member)
    assert validate_api_key(raw_key).id == key.id

    world.set_active(member.user_id, False)
    with pytest.raises(InvalidApiKeyError):
        validate_api_key(raw_key)
    denials = _admin_execute(
        "SELECT metadata FROM core.audit_log WHERE tenant_id = :t AND "
        "action = 'api_key.validate' AND outcome = 'denied'",
        {"t": str(tenant_id)},
    )
    assert denials == [({"denied_gate": "inactive_user"},)]


def test_service_accounts_are_unaffected_by_user_deactivation(world: World) -> None:
    tenant_id = world.tenant()
    machine = world.service_account(tenant_id, ("role", "create"))
    someone = world.principal(tenant_id)
    world.set_active(someone.user_id, False)
    create_role(tenant_id, "machine-still-works", caller=machine)
    assert "machine-still-works" in _role_names(tenant_id)
