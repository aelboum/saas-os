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
                                been assigned, and at what authorization
                                `scope` (`self` or `subtree` relative to
                                the membership's tenant -- architecture
                                research Phase B, `core/rbac/scope.py`).
    core.delegation_grants   -- tenant-owned, RLS-protected (architecture
                                research Phase C -- "Delegation"). An
                                explicit, scoped, time-bounded,
                                individually-revocable grant of exactly one
                                `Permission` from one principal to another,
                                over a named tenant scope -- see
                                `DelegationGrant`'s own docstring below for
                                the full model and its relationship to
                                ordinary membership-role authorization.

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
from datetime import datetime

from core.rbac.principal import PrincipalType
from core.rbac.scope import RoleScope
from infra.db import (
    Base,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Mapped,
    String,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    func,
    mapped_column,
    text,
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

    `scope` (architecture research: universal multi-tenant tenancy, Phase
    B; `core/rbac/scope.py`) declares how far this assignment reaches
    relative to the membership's own tenant -- `SELF` (the default: only
    that tenant, the only behavior that existed before this column) or
    `SUBTREE` (that tenant and its current descendants, evaluated live
    against `core.tenant_ancestry` by `core/rbac/authorization.py::can()`,
    never stored as a snapshot here). Structural hierarchy alone still
    grants nothing -- `scope` only ever *narrows or widens which tenant
    this specific, already-granted assignment reaches*; it never
    substitutes for a real membership, role, or permission grant.
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
        CheckConstraint("scope IN ('self', 'subtree')", name="ck_membership_roles_valid_scope"),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    membership_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False, default=RoleScope.SELF.value)


class DelegationGrant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An explicit, bilateral, scoped, time-bounded, individually-revocable
    grant of exactly one `Permission` from a delegator principal to a
    delegate principal, over `tenant_id` (architecture research: universal
    multi-tenant tenancy, Phase C -- "Delegation is intentionally separate
    from hierarchy"; `core/tenancy/models.py`'s `Tenant.parent_id`
    docstring: a parent-child relationship never itself creates
    authorization). Tenant-owned, RLS-protected, exactly like every other
    `core/rbac` table -- `tenant_id` here names the tenant this grant's
    authority *concerns* (the "scope tenant"), the same convention
    `Role.tenant_id`/`MembershipRole.tenant_id` already use for "the
    tenant this row's authority belongs to".

    **Hierarchy answers "where is this tenant structurally located?";
    delegation answers "who has explicitly been granted authority to act
    within this tenant scope?" -- the two are never merged.** A grant may
    target any tenant regardless of hierarchy relationship (unrelated,
    sibling, parent-to-child, child-to-parent), subject only to the
    delegator's own authorization (`core/rbac/service.py::create_delegation()`).
    No hierarchy relationship is required, checked, or implied by this
    table itself.

    Principals are named as `(principal_type, principal_id)` pairs
    (`core/rbac/principal.py::PrincipalType`), never a bare `user_id` --
    `permission_id` is a **global** `core.permissions` reference (plain FK,
    no composite-FK tenant pairing needed, since `Permission` is not
    tenant-owned), deliberately chosen over referencing a tenant-local
    `Role`: a `Role` only ever exists within one tenant, which cannot
    express "delegate this capability into an unrelated tenant" the way a
    global `Permission` reference does. This is also what keeps a
    `SUBTREE`-mode delegation from ever "automatically granting every
    permission of the delegator" -- exactly one `permission_id` is
    referenced per grant, evaluated by
    `core/rbac/authorization.py::can()` the same way a `MembershipRole`
    row's single permission grant is, never a broader bundle.

    `scope_mode` reuses `core/rbac/scope.py::RoleScope` directly (`SELF`
    or `SUBTREE`) rather than inventing an incompatible duplicate concept
    -- `SUBTREE` reaches `tenant_id` and its *current* descendants per the
    live `core.tenant_ancestry` closure table, exactly like a
    `SUBTREE`-scoped `MembershipRole`, and with the identical
    live-not-snapshotted evaluation: moving a descendant out from under
    `tenant_id` removes that descendant's authorization on the very next
    `can()` call, with no rewrite of this row.

    Time validity: not active before `starts_at`; inactive at/after
    `expires_at` (nullable -- no expiry if absent) or once `revoked_at` is
    set. All three are evaluated directly by `can()` on every call --
    no cache, no background deactivation job; a `revoked_at` write is
    authoritative for the very next authorization check
    (`core/rbac/authorization.py`).

    `allow_redelegate` (default `False`, architecture research's
    conservative recommendation) is stored for schema completeness with
    the requested conceptual model, but this phase implements no
    consuming logic for it: `create_delegation()`'s privilege-amplification
    check is built entirely on ordinary membership-role authorization
    (`core/rbac/authorization.py`'s `_actor_reaches_tenant_at_scope()`),
    which never considers `DelegationGrant` rows at all -- so a delegate
    cannot use delegated authority to create a further delegation in this
    phase, regardless of `allow_redelegate`'s value. A future phase that
    actually implements chaining owns adding the depth/cap fields and the
    consuming logic together; adding an unused depth-cap column now, with
    nothing enforcing it, would be exactly the kind of speculative field
    the rest of this codebase avoids.

    No `resource_constraint` field: `core/rbac`'s permission model is a
    `(resource, action)` *type* pair, not a per-instance resource id, so
    there is no existing generic representation to reference here without
    inventing a mini policy language -- explicitly out of scope
    (architecture research: "keep this field absent... rather than
    inventing a mini policy language").
    """

    __tablename__ = "delegation_grants"
    __table_args__ = (
        CheckConstraint(
            "delegator_principal_type IN ('user', 'system')",
            name="ck_delegation_grants_delegator_principal_type",
        ),
        CheckConstraint(
            "(delegator_principal_type = 'user' AND delegator_principal_id IS NOT NULL) "
            "OR (delegator_principal_type = 'system' AND delegator_principal_id IS NULL)",
            name="ck_delegation_grants_delegator_pairing",
        ),
        CheckConstraint(
            "delegate_principal_type IN ('user', 'system')",
            name="ck_delegation_grants_delegate_principal_type",
        ),
        CheckConstraint(
            "(delegate_principal_type = 'user' AND delegate_principal_id IS NOT NULL) "
            "OR (delegate_principal_type = 'system' AND delegate_principal_id IS NULL)",
            name="ck_delegation_grants_delegate_pairing",
        ),
        CheckConstraint(
            "scope_mode IN ('self', 'subtree')", name="ck_delegation_grants_valid_scope_mode"
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > starts_at",
            name="ck_delegation_grants_valid_time_range",
        ),
        # Active-lookup index (architecture research: "provide indexes for
        # active delegation lookup") -- the exact shape
        # `core/rbac/authorization.py`'s delegation check queries by:
        # "which of this tenant's grants delegate to this principal".
        Index(
            "ix_delegation_grants_tenant_delegate",
            "tenant_id",
            "delegate_principal_type",
            "delegate_principal_id",
        ),
        # Partial unique index, active grants only (`revoked_at IS NULL`):
        # blocks an accidental duplicate of the exact same still-active
        # grant (same tenant/delegate/scope/permission), without blocking
        # a second grant that differs in scope, permission, or validity
        # window, and without blocking re-granting after the prior grant
        # was revoked or allowed to expire (architecture research:
        # "prevent accidental duplicate active grants... do not
        # over-constrain").
        Index(
            "uq_delegation_grants_active_unique",
            "tenant_id",
            "delegate_principal_type",
            "delegate_principal_id",
            "scope_mode",
            "permission_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
        {"schema": "core"},
    )

    # `tenant_id` FK uses ON DELETE CASCADE, unlike `Tenant.parent_id`'s
    # plain (blocking) FK: a delegation grant has no meaning once its own
    # scope tenant no longer exists -- the same "structural data tied to a
    # tenant's existence" reasoning `core.tenant_ancestry` already applies
    # (`core/tenancy/models.py::TenantAncestry`'s own docstring), not the
    # "block, don't cascade" reasoning `Tenant.parent_id` uses for a
    # living *child* tenant.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id", ondelete="CASCADE"), nullable=False
    )

    delegator_principal_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default=PrincipalType.USER.value
    )
    delegator_principal_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    delegate_principal_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default=PrincipalType.USER.value
    )
    delegate_principal_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )

    scope_mode: Mapped[str] = mapped_column(
        String(20), nullable=False, default=RoleScope.SELF.value
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.permissions.id"), nullable=False
    )

    starts_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    allow_redelegate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
