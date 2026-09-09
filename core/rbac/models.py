"""Role, Permission, RolePermission, and MembershipRole entities
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.3; docs/SECURITY.md section 3:
"Owned entirely by core/rbac ... Authorization is a single
policy-evaluation call (`can(actor, action, resource)`)").

Five isolation postures across four tables:

    core.roles              -- tenant-owned, RLS-protected. A role is
                                always local to one tenant (docs/IMPLEMENTATION-
                                ROADMAP.md Phase 3.3 section 6: "RBAC is
                                fundamentally tenant-scoped unless the
                                authoritative architecture explicitly
                                specifies a global role" -- nothing in
                                docs/SECURITY.md, docs/ARCHITECTURE.md, or
                                the roadmap specifies a platform/system
                                role, so none is added here).
    core.permissions         -- GLOBAL, not RLS-scoped. A permission is a
                                capability *definition* (a fixed `resource`
                                + `action` pair a piece of code declares
                                exists, e.g. "role", "create"), not
                                tenant-owned data -- mirrors docs/SECURITY.md
                                section 3's own example
                                (`dograh:call.transcript.read`): the
                                platform and future products register a
                                shared, global catalog of capabilities;
                                *granting* one of them to a tenant's role is
                                the tenant-scoped operation (`RolePermission`,
                                below).
    core.role_permissions    -- tenant-owned, RLS-protected. Which
                                permissions a tenant's role has been
                                granted.
    core.membership_roles    -- tenant-owned, RLS-protected. Which roles a
                                tenant's membership (docs/IMPLEMENTATION-
                                ROADMAP.md Phase 3.2, `core/identity`) has
                                been assigned.

Both join tables carry an explicit `tenant_id` column (not merely
reachable transitively through `role_id`/`membership_id`) for two reasons:
(1) it is what RLS's policy (`infra.db.rls.tenant_rls_statements()`) is
keyed on, identically to every other tenant-owned table; (2) it is one half
of a *composite* foreign key -- `(tenant_id, role_id) REFERENCES
roles(tenant_id, id)` and `(tenant_id, membership_id) REFERENCES
tenant_memberships(tenant_id, id)` -- so a row can never reference a role
or membership belonging to a different tenant, enforced by Postgres itself,
not by application code remembering to check
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 18: "An application
check alone is insufficient for a security-critical cross-tenant
relationship"). This is why `Role` additionally declares
`UniqueConstraint("tenant_id", "id")` below (redundant with the primary
key alone, but required as the composite FK's target) -- the same reason
`core/identity/models.py`'s `TenantMembership` gained one in this phase.

No role/permission is ever assigned directly to a global `User` -- every
assignment is anchored to a `TenantMembership`, so a user belonging to
tenant A never receives authorization in tenant B merely because the same
global user row exists (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 6).

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid

from infra.db import (
    Base,
    ForeignKey,
    ForeignKeyConstraint,
    Mapped,
    String,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class Role(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A tenant-local, named collection of permissions. No description,
    lifecycle/active flag, or other field beyond `name` -- none is
    specified by the roadmap's Phase 3.3 objective ("roles, permissions,
    and role assignment/authorization primitives"), and none is added
    speculatively.
    """

    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_name"),
        # Composite-FK target for role_permissions/membership_roles (see
        # module docstring) -- redundant with the primary key alone, but
        # required by Postgres as the exact tuple a composite FK references.
        UniqueConstraint("tenant_id", "id", name="uq_roles_tenant_id_id"),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)


class Permission(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A global capability definition: `resource` + `action`
    (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 8: "a stable
    representation such as ... resource + action"). Not tenant-owned --
    see module docstring. No product-specific permission is seeded here
    (e.g. no `dograh`/`recharge`/`crm` row); Product code registers its
    own via `core.rbac.register_permission()` without modifying this
    module.
    """

    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("resource", "action", name="uq_permissions_resource_action"),
        {"schema": "core"},
    )

    resource: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)


class RolePermission(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A grant of one `Permission` to one tenant's `Role` -- tenant-owned,
    RLS-protected. See module docstring for the composite-FK rationale.
    """

    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_role_permission"),
        ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["core.roles.tenant_id", "core.roles.id"],
            name="fk_role_permissions_tenant_role",
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    permission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.permissions.id"), nullable=False
    )


class MembershipRole(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An assignment of one tenant's `Role` to one `TenantMembership`
    (`core/identity`) -- tenant-owned, RLS-protected. See module docstring
    for the composite-FK rationale. Deliberately references
    `TenantMembership`, never `User` directly (docs/IMPLEMENTATION-ROADMAP.md
    Phase 3.3 section 6/10) -- authorization is always anchored to a
    specific tenant membership, never to a global user identity alone.
    """

    __tablename__ = "membership_roles"
    __table_args__ = (
        UniqueConstraint("membership_id", "role_id", name="uq_membership_roles_membership_role"),
        ForeignKeyConstraint(
            ["tenant_id", "membership_id"],
            ["core.tenant_memberships.tenant_id", "core.tenant_memberships.id"],
            name="fk_membership_roles_tenant_membership",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["core.roles.tenant_id", "core.roles.id"],
            name="fk_membership_roles_tenant_role",
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    membership_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
