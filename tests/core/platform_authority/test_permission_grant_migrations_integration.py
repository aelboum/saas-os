"""Permission grant migrations for existing tenants (ADR 0060, option C;
owner decisions of 2026-11-01; docs/architecture/
PERMISSION-GRANT-MIGRATIONS-DESIGN.md section 7): authority, isolation,
refusals without partial writes, idempotency, a suspended tenant,
atomicity, concurrency and recovery. PostgreSQL.

Every test names its tenants explicitly (never `all_tenants` with `apply`),
so tenants other tests left open are never changed. Cleanup: the ledger
rows of the test's tenants and the permissions it registered are deleted
with the privileged role; `Scene` turns the tenants into tombstones and
deletes their grants; `PlatformWorld` empties the platform tables, so no
grant of `platform.permission_grant:apply` outlives a test (it would make
the migration's downgrade refuse, by design).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from phase_c_helpers import BILLING, PROVISIONING, TENANT_PURGE, Pause, Scene, pause_after
from platform_helpers import BOOTSTRAP, PlatformWorld, join, start, wait_until_blocked_by
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError

import saas_os.core.permission_grants.apply as apply_module
from saas_os.core.authority import ServiceAccountCaller, SystemAuthority, SystemCaller, UserCaller
from saas_os.core.permission_grants import (
    TENANT_CHANGED,
    TENANT_CLOSED,
    TENANT_FAILED,
    TENANT_NOT_FOUND,
    TENANT_UNCHANGED,
    AuthorityPermissionGrantError,
    PermissionGrantMigration,
    PermissionGrantMigrationChangedError,
    PermissionGrantRunResult,
    UnregisteredPermissionGrantError,
    apply_permission_grant_migrations,
    permission_grant_migration_digest,
)
from saas_os.core.platform_authority import PlatformNotAuthorizedError, PlatformPermission
from saas_os.core.rbac import (
    AuthorityNotAuthorizedError,
    assign_first_role_for_new_tenant,
    can,
    create_role,
    grant_permission,
    register_permission,
    revoke_permission,
)
from saas_os.core.rbac.service import grant_registered_permission_to_role
from saas_os.core.tenancy import TenantStatus, purge_tenant
from saas_os.core.tenancy.purge_participants import TenantPurgeParticipantRegistry
from saas_os.infra.db import session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

P = PlatformPermission
NS = "grt_app"
REASON = "integration test: reports module"
ACTION = "platform.permission_grant.apply"


class Grants:
    """Registered permissions, migrations and inspection for one test."""

    def __init__(self, scene: Scene, platform: PlatformWorld) -> None:
        self.scene = scene
        self.platform = platform
        self.resource = f"grt_{uuid.uuid4().hex[:10]}.report"
        self.read = register_permission(self.resource, "read")
        self.export = register_permission(self.resource, "export")
        self.share = register_permission(self.resource, "share")
        self.permission_ids = [self.read.id, self.export.id, self.share.id]

    def migration(
        self,
        migration_id: str = "2026-11-reports",
        *,
        role_name: str = "admin",
        actions: tuple[str, ...] = ("read", "export"),
    ) -> PermissionGrantMigration:
        return PermissionGrantMigration(
            migration_id,
            NS,
            role_name,
            tuple((self.resource, action) for action in actions),
            "Reports module, release 4.2",
        )

    def tenant(
        self, *, role_name: str | None = "admin", actions: tuple[str, ...] = ()
    ) -> tuple[uuid.UUID, uuid.UUID | None, uuid.UUID]:
        """An ACTIVE tenant with a member holding the role `role_name`
        (if any), which already holds `actions`. Returns `(tenant, role,
        member user)`."""
        tenant = self.scene.tenant(active=True)
        user, membership = self.scene.member(tenant)
        if role_name is None:
            return tenant, None, user
        role = create_role(tenant, role_name, caller=PROVISIONING)
        for action in actions:
            permission = register_permission(self.resource, action)
            grant_permission(tenant, role.id, permission.id, caller=PROVISIONING)
        assign_first_role_for_new_tenant(tenant, membership, role.id, caller=PROVISIONING)
        return tenant, role.id, user

    def held(self, tenant: uuid.UUID, role: uuid.UUID | None = None) -> set[str]:
        sql = (
            "SELECT p.action FROM core.role_permissions rp "
            "JOIN core.permissions p ON p.id = rp.permission_id "
            "WHERE rp.tenant_id = :t AND p.resource = :r"
        )
        params: dict[str, Any] = {"t": tenant, "r": self.resource}
        if role is not None:
            sql += " AND rp.role_id = :role"
            params["role"] = role
        return {row[0] for row in self.platform.execute(sql, params)}

    def ledger(self, tenant: uuid.UUID) -> list[dict[str, Any]]:
        rows = self.platform.execute(
            "SELECT migration_id, content_digest, outcome, grants_added, "
            "applied_by_platform_audit_id FROM core.permission_grant_applications "
            "WHERE tenant_id = :t ORDER BY migration_id",
            {"t": tenant},
        )
        keys = ("migration_id", "digest", "outcome", "grants_added", "run_id")
        return [dict(zip(keys, row, strict=True)) for row in rows]

    def roles(self, tenant: uuid.UUID) -> int:
        return self.platform.scalar(
            "SELECT count(*) FROM core.roles WHERE tenant_id = :t", {"t": tenant}
        )

    def audit_count(self, tenant: uuid.UUID) -> int:
        return self.platform.scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t", {"t": tenant}
        )

    def cleanup(self) -> None:
        if self.scene.tenants:
            self.platform.execute(
                "DELETE FROM core.permission_grant_applications WHERE tenant_id = ANY(:t)",
                {"t": self.scene.tenants},
            )
        self.platform.execute(
            "DELETE FROM core.role_permissions WHERE permission_id = ANY(:p)",
            {"p": self.permission_ids},
        )
        self.platform.execute(
            "DELETE FROM core.permissions WHERE resource = :r", {"r": self.resource}
        )


@pytest.fixture
def grants(scene: Scene, platform: PlatformWorld) -> Iterator[Grants]:
    built = Grants(scene, platform)
    try:
        yield built
    finally:
        built.cleanup()


def _run(
    grants: Grants,
    caller: object,
    tenants: list[uuid.UUID],
    migrations: list[PermissionGrantMigration] | None = None,
    *,
    apply: bool = True,
) -> PermissionGrantRunResult:
    return apply_permission_grant_migrations(
        migrations if migrations is not None else [grants.migration()],
        namespace=NS,
        caller=caller,
        reason=REASON,
        tenant_ids=tenants,
        apply=apply,
    )


def _operator(platform: PlatformWorld) -> UserCaller:
    return platform.operator([P.PERMISSION_GRANT_APPLY])[0]


# --- the procedure ---------------------------------------------------------------


def test_a_dry_run_counts_per_tenant_and_writes_nothing(
    grants: Grants, platform: PlatformWorld
) -> None:
    tenant, role, _ = grants.tenant(actions=("read",))
    operator = _operator(platform)
    platform.clear_audit()
    before = grants.audit_count(tenant)

    result = _run(grants, operator, [tenant], apply=False)

    assert (result.applied, result.run_id) == (False, None)
    (only,) = result.tenants
    assert (only.outcome, only.migrations_applied, only.grants_added) == (TENANT_CHANGED, 1, 1)
    assert only.grants_already_present == 1
    assert grants.held(tenant, role) == {"read"}
    assert grants.ledger(tenant) == []
    assert grants.audit_count(tenant) == before
    assert platform.audit() == []


def test_apply_adds_only_the_missing_grants_with_ledger_tenant_and_platform_evidence(
    grants: Grants, scene: Scene, platform: PlatformWorld
) -> None:
    tenant, role, _ = grants.tenant(actions=("read",))
    operator = _operator(platform)
    platform.clear_audit()
    migration = grants.migration()

    result = _run(grants, operator, [tenant], [migration])

    assert result.applied and result.run_id is not None
    (only,) = result.tenants
    assert (only.outcome, only.grants_added, only.grants_already_present) == (
        TENANT_CHANGED,
        1,
        1,
    )
    assert grants.held(tenant, role) == {"read", "export"}
    assert grants.roles(tenant) == 1  # no role created
    (ledger,) = grants.ledger(tenant)
    assert ledger == {
        "migration_id": migration.id,
        "digest": permission_grant_migration_digest(migration),
        "outcome": "applied",
        "grants_added": 1,
        "run_id": result.run_id,
    }

    # Tenant evidence: one grant row by the system purpose, naming the
    # migration and the operator; one application row by the operator.
    (grant_row,) = [
        row
        for row in scene.tenant_audit(tenant, "role_permission.grant")
        if row["metadata"].get("migration_id") == migration.id
    ]
    assert grant_row["actor_type"] == "system" and grant_row["actor_user_id"] is None
    assert grant_row["resource_id"] == str(role)
    assert grant_row["metadata"]["system_authority"] == "permission_upgrade"
    assert grant_row["metadata"]["namespace"] == NS
    assert grant_row["metadata"]["operator_user_id"] == str(operator.user_id)
    assert grant_row["metadata"]["run_id"] == str(result.run_id)
    assert grant_row["metadata"]["permission"] == f"{grants.resource}:export"
    (application,) = scene.tenant_audit(tenant, "permission_grant_migration.apply")
    assert application["actor_user_id"] == operator.user_id
    assert application["metadata"]["migration_ids"] == [migration.id]
    assert application["metadata"]["grants_added"] == 1

    # Platform evidence: one row per run, its id the run id, counts only.
    (row,) = platform.audit(action=ACTION, outcome="success")
    assert row["actor_user_id"] == operator.user_id and row["reason"] == REASON
    assert row["target_id"] == NS and row["target_tenant_id"] == tenant
    run_ids = platform.execute(
        "SELECT id FROM core.platform_audit_log WHERE action = :a", {"a": ACTION}
    )
    assert run_ids == [(result.run_id,)]
    assert row["metadata"]["tenants_changed"] == 1
    assert row["metadata"]["grants_added"] == 1
    assert row["metadata"]["grants_already_present"] == 1
    assert row["metadata"]["migration_ids"] == [migration.id]
    assert grants.resource not in str(row) and "admin" not in str(row)


def test_a_migration_grant_is_audited_with_the_shape_of_an_ordinary_grant(
    grants: Grants, scene: Scene, platform: PlatformWorld
) -> None:
    """Owner decision B: one audit action for every grant. A grant made by
    a migration and one made through `grant_permission()` by a tenant
    administrator share the action, resource type, resource id shape,
    outcome and metadata keys; the migration's row only adds the purpose
    and the migration's identity."""
    tenant, role, _ = grants.tenant()
    assert role is not None
    administrator, _ = scene.admin(
        tenant, extra=(("role_permission", "grant"), (grants.resource, "share"))
    )
    grant_permission(tenant, role, grants.share.id, caller=administrator)
    operator = _operator(platform)
    result = _run(grants, operator, [tenant], [grants.migration(actions=("read",))])

    # The grants to the target role (the administrator's own role holds
    # `share` too, from the setup).
    rows = [
        r
        for r in scene.tenant_audit(tenant, "role_permission.grant")
        if r["resource_id"] == str(role)
    ]
    (ordinary,) = [r for r in rows if r["metadata"].get("permission") == f"{grants.resource}:share"]
    (migrated,) = [r for r in rows if r["metadata"].get("permission") == f"{grants.resource}:read"]
    for key in ("action", "resource_type", "resource_id", "outcome"):
        assert migrated[key] == ordinary[key], key
    assert migrated["action"] == "role_permission.grant"
    assert (migrated["resource_type"], migrated["resource_id"]) == ("role", str(role))
    assert set(ordinary["metadata"]) == {"permission_id", "permission"}
    assert set(migrated["metadata"]) - set(ordinary["metadata"]) == {
        "migration_id",
        "namespace",
        "operator_user_id",
        "run_id",
        "system_authority",
    }
    assert migrated["metadata"]["permission_id"] == str(grants.read.id)
    assert migrated["metadata"]["system_authority"] == "permission_upgrade"
    assert migrated["metadata"]["run_id"] == str(result.run_id)
    assert (ordinary["actor_type"], ordinary["actor_user_id"]) == (
        "user",
        administrator.user_id,
    )
    assert (migrated["actor_type"], migrated["actor_user_id"]) == ("system", None)


def test_a_second_run_changes_nothing(grants: Grants, platform: PlatformWorld) -> None:
    tenant, role, _ = grants.tenant()
    operator = _operator(platform)
    _run(grants, operator, [tenant])
    ledger, audit = grants.ledger(tenant), grants.audit_count(tenant)

    again = _run(grants, operator, [tenant])

    (only,) = again.tenants
    assert (only.outcome, only.migrations_already_applied, only.grants_added) == (
        TENANT_UNCHANGED,
        1,
        0,
    )
    assert grants.ledger(tenant) == ledger and grants.audit_count(tenant) == audit
    assert grants.held(tenant, role) == {"read", "export"}


def test_a_grant_the_tenant_administrator_revoked_is_not_restored(
    grants: Grants, scene: Scene, platform: PlatformWorld
) -> None:
    tenant, role, _ = grants.tenant()
    assert role is not None
    operator = _operator(platform)
    _run(grants, operator, [tenant])
    administrator, _ = scene.admin(tenant, extra=(("role_permission", "revoke"),))
    revoke_permission(tenant, role, grants.export.id, caller=administrator)
    assert grants.held(tenant, role) == {"read"}

    again = _run(grants, operator, [tenant])

    assert again.tenants[0].outcome == TENANT_UNCHANGED
    assert grants.held(tenant, role) == {"read"}  # the administrator's decision stands


def test_a_missing_role_is_recorded_and_never_created(
    grants: Grants, platform: PlatformWorld
) -> None:
    tenant, _, _ = grants.tenant(role_name=None)
    operator = _operator(platform)
    roles = grants.roles(tenant)

    result = _run(grants, operator, [tenant])

    (only,) = result.tenants
    assert (only.outcome, only.roles_missing, only.migrations_applied) == (TENANT_CHANGED, 1, 0)
    assert grants.roles(tenant) == roles and grants.held(tenant) == set()
    (ledger,) = grants.ledger(tenant)
    assert (ledger["outcome"], ledger["grants_added"]) == ("role_missing", 0)
    # Recorded once: a later run does not look again.
    assert _run(grants, operator, [tenant]).tenants[0].migrations_already_applied == 1


def test_only_the_named_migrations_role_and_no_other_is_touched(
    grants: Grants, scene: Scene, platform: PlatformWorld
) -> None:
    tenant, admin_role, user = grants.tenant()
    other = create_role(tenant, "viewer", caller=PROVISIONING)
    operator = _operator(platform)
    _run(grants, operator, [tenant])
    assert grants.held(tenant, admin_role) == {"read", "export"}
    assert grants.held(tenant, other.id) == set()
    assert can(actor_id=user, tenant_id=tenant, action="export", resource=grants.resource)


# --- isolation -------------------------------------------------------------------


def test_a_run_for_one_tenant_never_touches_another_with_the_same_role_name(
    grants: Grants, platform: PlatformWorld
) -> None:
    tenant_a, role_a, _ = grants.tenant()
    tenant_b, role_b, user_b = grants.tenant(actions=("share",))
    operator = _operator(platform)
    audit_b = grants.audit_count(tenant_b)

    result = _run(grants, operator, [tenant_a])

    assert [r.tenant_id for r in result.tenants] == [tenant_a]
    assert grants.held(tenant_a, role_a) == {"read", "export"}
    assert grants.held(tenant_b, role_b) == {"share"}
    assert grants.ledger(tenant_b) == [] and grants.audit_count(tenant_b) == audit_b
    assert not can(actor_id=user_b, tenant_id=tenant_b, action="read", resource=grants.resource)
    # Row-level security: an untenanted session sees no ledger row at all,
    # and tenant B's session sees none of tenant A's.
    query = text("SELECT count(*) FROM core.permission_grant_applications")
    with session_scope() as session:
        assert session.execute(query).scalar_one() == 0
    with tenant_session_scope(tenant_b) as session:
        assert session.execute(query).scalar_one() == 0
    with tenant_session_scope(tenant_a) as session:
        assert session.execute(query).scalar_one() == 1


def test_the_runtime_role_cannot_rewrite_or_remove_a_ledger_row(
    grants: Grants, platform: PlatformWorld
) -> None:
    tenant, _, _ = grants.tenant()
    _run(grants, _operator(platform), [tenant])
    for statement in (
        "UPDATE core.permission_grant_applications SET grants_added = 0",
        "DELETE FROM core.permission_grant_applications",
    ):
        with (
            pytest.raises(ProgrammingError, match="permission denied"),
            tenant_session_scope(tenant) as session,
        ):
            session.execute(text(statement))
    assert len(grants.ledger(tenant)) == 1


# --- retention (owner decision A of 2026-11-01) ------------------------------------

# Every column of the ledger: which migration, applied to which tenant, by
# which run, with what digest, outcome and count. Nothing else is kept.
_LEDGER_COLUMNS = {
    "id",
    "tenant_id",
    "namespace",
    "migration_id",
    "content_digest",
    "outcome",
    "grants_added",
    "applied_at",
    "applied_by_platform_audit_id",
}


def _ledger_rows(platform: PlatformWorld, tenant: uuid.UUID) -> list[tuple[Any, ...]]:
    return platform.execute(
        "SELECT * FROM core.permission_grant_applications WHERE tenant_id = :t "
        "ORDER BY migration_id",
        {"t": tenant},
    )


def test_the_ledger_survives_the_purge_as_minimal_history_and_the_id_is_never_reused(
    grants: Grants, scene: Scene, platform: PlatformWorld
) -> None:
    """SECURITY_RETAIN: the real purge keeps the ledger rows unchanged next
    to the tombstone and removes the operational data they describe; the
    rows hold no name; the runtime role still cannot remove them; the
    tombstone (and so the tenant id) can never be freed while they exist;
    and the retained rows lend no authority to a later run."""
    tenant, _, _ = grants.tenant()
    operator = _operator(platform)
    _run(grants, operator, [grants.tenant()[0]])  # another tenant's history, untouched
    _run(grants, operator, [tenant], [grants.migration(), grants.migration("2026-12-share")])
    before = _ledger_rows(platform, tenant)
    assert len(before) == 2
    others = platform.scalar(
        "SELECT count(*) FROM core.permission_grant_applications WHERE tenant_id <> :t",
        {"t": tenant},
    )

    scene.set_status(tenant, TenantStatus.DELETED)
    purge_tenant(tenant, caller=TENANT_PURGE, registry=TenantPurgeParticipantRegistry())

    assert scene.status(tenant) == TenantStatus.PURGED.value
    assert _ledger_rows(platform, tenant) == before
    assert (
        platform.scalar(
            "SELECT count(*) FROM core.permission_grant_applications WHERE tenant_id <> :t",
            {"t": tenant},
        )
        == others
    )
    # The grants, the role and the memberships the history describes are gone.
    assert grants.held(tenant) == set() and grants.roles(tenant) == 0
    assert (
        platform.scalar(
            "SELECT count(*) FROM core.tenant_memberships WHERE tenant_id = :t", {"t": tenant}
        )
        == 0
    )
    # Minimal: exactly the reviewed columns, and no role, permission or
    # tenant name in what is kept.
    columns = {
        row[0]
        for row in platform.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'core' AND table_name = 'permission_grant_applications'"
        )
    }
    assert columns == _LEDGER_COLUMNS
    assert grants.resource not in str(before) and "admin" not in str(before)
    # Append-only after the purge as before it.
    with (
        pytest.raises(ProgrammingError, match="permission denied"),
        tenant_session_scope(tenant) as session,
    ):
        session.execute(text("DELETE FROM core.permission_grant_applications"))
    # The id stays taken: the ledger's foreign key onto the tombstone is
    # NO ACTION, so the tombstone cannot be deleted while history names
    # it, and a new tenant with that id is refused by the primary key.
    fk_on_delete = platform.scalar(
        "SELECT confdeltype FROM pg_constraint "
        "WHERE conname = 'fk_permission_grant_applications_tenant_id' "
        "AND confrelid = 'core.tenants'::regclass"
    )
    assert fk_on_delete == "a"
    with pytest.raises(IntegrityError):
        platform.execute("DELETE FROM core.tenants WHERE id = :t", {"t": tenant})
    with pytest.raises(IntegrityError, match="duplicate key"):
        platform.execute(
            "INSERT INTO core.tenants (id, name, status) VALUES (:t, 'reuse', 'pending')",
            {"t": tenant},
        )
    # Retained history lends no authority: the tombstone is closed for good.
    again = _run(grants, operator, [tenant])
    assert again.tenants[0].outcome == TENANT_CLOSED
    assert _ledger_rows(platform, tenant) == before


# --- tenant states -----------------------------------------------------------------


def test_a_suspended_tenant_receives_the_grant_but_its_members_cannot_use_it(
    grants: Grants, scene: Scene, platform: PlatformWorld
) -> None:
    """Owner decision Q3: a suspended tenant receives grants; its
    memberships authorize nothing until it is reactivated."""
    tenant, role, user = grants.tenant()
    scene.set_status(tenant, TenantStatus.SUSPENDED)

    result = _run(grants, _operator(platform), [tenant])

    assert result.tenants[0].outcome == TENANT_CHANGED
    assert grants.held(tenant, role) == {"read", "export"}
    assert not can(actor_id=user, tenant_id=tenant, action="read", resource=grants.resource)
    scene.set_status(tenant, TenantStatus.ACTIVE)
    assert can(actor_id=user, tenant_id=tenant, action="read", resource=grants.resource)


def test_a_pending_tenant_receives_the_grant(
    grants: Grants, scene: Scene, platform: PlatformWorld
) -> None:
    tenant, role, _ = grants.tenant()
    scene.set_status(tenant, TenantStatus.PENDING)
    assert _run(grants, _operator(platform), [tenant]).tenants[0].outcome == TENANT_CHANGED
    assert grants.held(tenant, role) == {"read", "export"}


@pytest.mark.parametrize("status", [TenantStatus.DELETED, TenantStatus.PURGING])
def test_a_closed_tenant_is_reported_and_left_untouched(
    grants: Grants, scene: Scene, platform: PlatformWorld, status: TenantStatus
) -> None:
    tenant, role, _ = grants.tenant()
    scene.set_status(tenant, status)
    audit = grants.audit_count(tenant)

    result = _run(grants, _operator(platform), [tenant])

    assert result.tenants[0].outcome == TENANT_CLOSED
    assert grants.held(tenant, role) == set() and grants.ledger(tenant) == []
    assert grants.audit_count(tenant) == audit
    (row,) = platform.audit(action=ACTION, outcome="success")
    assert row["metadata"]["tenants_tenant_closed"] == 1


def test_an_unknown_tenant_is_reported(grants: Grants, platform: PlatformWorld) -> None:
    result = _run(grants, _operator(platform), [uuid.uuid4()])
    assert result.tenants[0].outcome == TENANT_NOT_FOUND
    (row,) = platform.audit(action=ACTION, outcome="success")
    assert row["target_tenant_id"] is None


def test_all_tenants_lists_open_tenants_only(
    grants: Grants, scene: Scene, platform: PlatformWorld
) -> None:
    """A dry run over every open tenant: nothing is written anywhere."""
    open_tenant, _, _ = grants.tenant()
    closed, _, _ = grants.tenant()
    scene.set_status(closed, TenantStatus.DELETED)

    result = apply_permission_grant_migrations(
        [grants.migration()],
        namespace=NS,
        caller=_operator(platform),
        reason=REASON,
        all_tenants=True,
    )

    seen = {r.tenant_id for r in result.tenants}
    assert open_tenant in seen and closed not in seen
    assert not result.applied and grants.ledger(open_tenant) == []


# --- authority -------------------------------------------------------------------


def _refused_without_writes(
    grants: Grants, platform: PlatformWorld, caller: object, *, recorded: bool = True
) -> None:
    tenant, role, _ = grants.tenant()
    audit = grants.audit_count(tenant)
    platform.clear_audit()
    with pytest.raises(PlatformNotAuthorizedError):
        _run(grants, caller, [tenant])
    assert grants.held(tenant, role) == set() and grants.ledger(tenant) == []
    assert grants.audit_count(tenant) == audit
    assert platform.audit(action=ACTION, outcome="success") == []
    denied = platform.audit(action=ACTION, outcome="denied")
    if recorded:
        (row,) = denied
        assert row["reason"] == "not_authorized"
    else:
        assert denied == []


def test_an_operator_without_the_permission_is_refused(
    grants: Grants, platform: PlatformWorld
) -> None:
    _refused_without_writes(grants, platform, platform.operator()[0])


def test_an_operator_holding_another_permission_is_refused(
    grants: Grants, platform: PlatformWorld
) -> None:
    _refused_without_writes(grants, platform, platform.operator([P.OUTBOX_REPLAY])[0])


def test_a_person_who_is_not_an_operator_is_refused(
    grants: Grants, platform: PlatformWorld
) -> None:
    _refused_without_writes(grants, platform, UserCaller(platform.user()))


def test_a_service_account_is_refused(grants: Grants, platform: PlatformWorld) -> None:
    """A service account is never a platform actor: refused, and no
    platform row can name it."""
    caller = ServiceAccountCaller(uuid.uuid4(), uuid.uuid4())
    _refused_without_writes(grants, platform, caller, recorded=False)


@pytest.mark.parametrize("purpose", list(SystemAuthority))
def test_every_system_purpose_is_refused(
    grants: Grants, platform: PlatformWorld, purpose: SystemAuthority
) -> None:
    """Including `PERMISSION_UPGRADE` itself: the operation is a person's
    (no system purpose), whatever purpose the run uses inside a tenant."""
    _refused_without_writes(grants, platform, SystemCaller(purpose))


def test_a_user_still_cannot_grant_a_permission_they_do_not_hold(
    grants: Grants, scene: Scene
) -> None:
    """The anti-amplification rule is unchanged, and the purpose's one
    function refuses a person."""
    tenant, role, _ = grants.tenant()
    assert role is not None
    administrator, _ = scene.admin(tenant, extra=(("role_permission", "grant"),))
    with pytest.raises(AuthorityNotAuthorizedError):
        grant_permission(tenant, role, grants.read.id, caller=administrator)
    for caller in (administrator, PROVISIONING, TENANT_PURGE, BILLING, BOOTSTRAP):
        with pytest.raises(AuthorityNotAuthorizedError), tenant_session_scope(tenant) as session:
            grant_registered_permission_to_role(
                session,
                tenant_id=tenant,
                role_id=role,
                permission_id=grants.read.id,
                caller=caller,
                metadata={},
            )
    assert grants.held(tenant, role) == set()


def test_the_purpose_function_refuses_an_authority_permission_and_another_tenants_role(
    grants: Grants,
) -> None:
    tenant, role, _ = grants.tenant()
    other, other_role, _ = grants.tenant()
    assert role is not None and other_role is not None
    upgrade = SystemCaller(SystemAuthority.PERMISSION_UPGRADE)
    authority = register_permission("role_permission", "grant")
    with pytest.raises(AuthorityNotAuthorizedError), tenant_session_scope(tenant) as session:
        grant_registered_permission_to_role(
            session,
            tenant_id=tenant,
            role_id=role,
            permission_id=authority.id,
            caller=upgrade,
            metadata={},
        )
    from saas_os.core.rbac.errors import RoleNotFoundError

    with pytest.raises(RoleNotFoundError), tenant_session_scope(tenant) as session:
        grant_registered_permission_to_role(
            session,
            tenant_id=tenant,
            role_id=other_role,
            permission_id=grants.read.id,
            caller=upgrade,
            metadata={},
        )
    assert grants.held(tenant) == set() and grants.held(other) == set()


# --- refusals without partial writes ------------------------------------------------


def _refusal_writes_nothing(
    grants: Grants,
    platform: PlatformWorld,
    migrations: list[PermissionGrantMigration],
    error: type[Exception],
    code: str,
    tenants: list[uuid.UUID],
) -> None:
    before = {t: (grants.held(t), grants.ledger(t), grants.audit_count(t)) for t in tenants}
    platform.clear_audit()
    with pytest.raises(error):
        _run(grants, _operator(platform), tenants, migrations)
    for tenant in tenants:
        assert (grants.held(tenant), grants.ledger(tenant), grants.audit_count(tenant)) == before[
            tenant
        ]
    assert platform.audit(action=ACTION, outcome="success") == []
    (row,) = platform.audit(action=ACTION, outcome="denied")
    assert row["reason"] == code


def test_an_unregistered_permission_refuses_the_whole_run(
    grants: Grants, platform: PlatformWorld
) -> None:
    tenant_a, _, _ = grants.tenant()
    tenant_b, _, _ = grants.tenant()
    unregistered = PermissionGrantMigration(
        "2026-11-later", NS, "admin", ((grants.resource, "never_registered"),), "later"
    )
    _refusal_writes_nothing(
        grants,
        platform,
        [grants.migration(), unregistered],
        UnregisteredPermissionGrantError,
        "unregistered_permission",
        [tenant_a, tenant_b],
    )
    assert (
        platform.scalar(
            "SELECT count(*) FROM core.permissions WHERE resource = :r AND action = :a",
            {"r": grants.resource, "a": "never_registered"},
        )
        == 0
    )  # never registered by the run


def test_an_authority_permission_refuses_the_whole_run(
    grants: Grants, platform: PlatformWorld
) -> None:
    tenant, _, _ = grants.tenant()
    authority = PermissionGrantMigration(
        "2026-11-escalate", NS, "admin", (("membership_role", "create"),), "no"
    )
    _refusal_writes_nothing(
        grants,
        platform,
        [grants.migration(), authority],
        AuthorityPermissionGrantError,
        "authority_permission",
        [tenant],
    )


def test_an_edited_migration_refuses_the_whole_run(grants: Grants, platform: PlatformWorld) -> None:
    tenant_a, _, _ = grants.tenant()
    tenant_b, _, _ = grants.tenant()
    _run(grants, _operator(platform), [tenant_a])  # applied as declared
    edited = grants.migration(actions=("read", "export", "share"))  # same id, new content
    later = grants.migration("2026-12-sharing", actions=("share",))
    _refusal_writes_nothing(
        grants,
        platform,
        [edited, later],
        PermissionGrantMigrationChangedError,
        "declaration_changed",
        [tenant_b, tenant_a],
    )


# --- atomicity and recovery ----------------------------------------------------------


def _failing_application_audit(
    monkeypatch: pytest.MonkeyPatch, *, only: uuid.UUID | None = None
) -> None:
    """Make the tenant's `permission_grant_migration.apply` audit row (the
    last write of a tenant's transaction, after its grants and ledger rows)
    fail."""
    real = apply_module.record_in_transaction

    def failing(session: Any, **kwargs: Any) -> Any:
        if only is None or kwargs["tenant_id"] == only:
            raise RuntimeError("injected audit failure")
        return real(session, **kwargs)

    monkeypatch.setattr(apply_module, "record_in_transaction", failing)


def test_an_audit_failure_leaves_no_grant_and_no_ledger_row(
    grants: Grants, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant, role, _ = grants.tenant()
    audit = grants.audit_count(tenant)
    _failing_application_audit(monkeypatch)

    result = _run(grants, _operator(platform), [tenant])

    (only,) = result.tenants
    assert (only.outcome, only.error) == (TENANT_FAILED, "RuntimeError")
    assert grants.held(tenant, role) == set()  # the grants rolled back with it
    assert grants.ledger(tenant) == []
    assert grants.audit_count(tenant) == audit  # and their grant rows
    (row,) = platform.audit(action=ACTION, outcome="success")
    assert row["metadata"]["tenants_failed"] == 1 and row["metadata"]["grants_added"] == 0


def test_a_failed_tenant_is_applied_by_the_next_run_and_the_others_stay_applied(
    grants: Grants, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_a, role_a, _ = grants.tenant()
    tenant_b, role_b, _ = grants.tenant()
    operator = _operator(platform)
    _failing_application_audit(monkeypatch, only=tenant_b)

    first = _run(grants, operator, [tenant_a, tenant_b])

    assert [r.outcome for r in first.tenants] == [TENANT_CHANGED, TENANT_FAILED]
    assert first.failed_tenant_ids == (tenant_b,)
    assert grants.held(tenant_a, role_a) == {"read", "export"}
    assert grants.held(tenant_b, role_b) == set() and grants.ledger(tenant_b) == []

    monkeypatch.undo()
    second = _run(grants, operator, [tenant_a, tenant_b])

    assert [r.outcome for r in second.tenants] == [TENANT_UNCHANGED, TENANT_CHANGED]
    assert grants.held(tenant_b, role_b) == {"read", "export"}
    assert grants.ledger(tenant_a)[0]["run_id"] == first.run_id
    assert grants.ledger(tenant_b)[0]["run_id"] == second.run_id


# --- concurrency -------------------------------------------------------------------


def test_two_concurrent_runs_on_one_tenant_apply_it_once(
    grants: Grants, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Forced order: the first run holds the tenant's advisory lock (and
    nothing written yet) while the second reaches the same lock and blocks
    on it, as PostgreSQL reports; then the first commits. The second then
    reads the first's ledger row: `already_applied`, nothing added twice."""
    tenant, role, _ = grants.tenant()
    operator = _operator(platform)
    pause = Pause("first")
    pause_after(monkeypatch, apply_module, "acquire_tenant_advisory_lock", pause)

    first_thread, first = start(lambda: _run(grants, operator, [tenant]), "first")
    assert pause.paused.wait(timeout=30), "the first run never took the tenant's lock"
    second_thread, second = start(lambda: _run(grants, operator, [tenant]), "second")
    wait_until_blocked_by(platform.admin, pause.pid)
    pause.release.set()
    join(first_thread)
    join(second_thread)

    assert "error" not in first and "error" not in second, (first, second)
    (one,) = first["result"].tenants
    (two,) = second["result"].tenants
    assert (one.outcome, one.grants_added) == (TENANT_CHANGED, 2)
    assert (two.outcome, two.migrations_already_applied, two.grants_added) == (
        TENANT_UNCHANGED,
        1,
        0,
    )
    assert grants.held(tenant, role) == {"read", "export"}
    assert len(grants.ledger(tenant)) == 1
    assert (
        platform.scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND action = 'role_permission.grant' AND metadata->>'run_id' IS NOT NULL",
            {"t": tenant},
        )
        == 2
    )
