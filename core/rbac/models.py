"""Role, Permission, RolePermission, and MembershipRole entities
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.3; docs/SECURITY.md section 3:
"Owned entirely by core/rbac ... Authorization is a single
policy-evaluation call (`can(actor, action, resource)`)").

Seven isolation postures across seven tables:

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
    core.deny_grants          -- tenant-owned, RLS-protected (architecture
                                research Phase D -- "Explicit Deny"). An
                                explicit, scoped, individually-revocable
                                block of exactly one `Permission` for one
                                principal, over a named tenant scope, that
                                overrides every allow path (ordinary,
                                inherited, and delegated) `can()` would
                                otherwise honor -- see `DenyGrant`'s own
                                docstring below.
    core.service_account_roles -- tenant-owned, RLS-protected (architecture
                                research Phase E -- "Principal + Service
                                Accounts + API Key Hardening"). Which
                                roles a tenant's `ServiceAccount`
                                (`core/identity`) has been assigned, and at
                                what authorization `scope` -- the exact
                                machine-principal analogue of
                                `MembershipRole`, never a second permission
                                model -- see `ServiceAccountRole`'s own
                                docstring below.

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

    **Delegate may be a service account (architecture research Phase E).**
    `delegate_principal_type` additionally accepts `'service_account'`,
    naming a `core/identity.ServiceAccount` via `delegate_service_account_id`
    instead of `delegate_principal_id` (this class's own `__table_args__`
    pairing `CheckConstraint`). This lets a service account receive
    explicit delegated authority exactly like a `User` delegate can --
    evaluated by `can()` through the identical query shape, never a
    second delegation mechanism. `delegator_principal_type` is
    deliberately NOT widened: this phase implements delegation *to* a
    service account, never *from* one (a service account delegating what
    it only itself received via delegation would be redelegation, out of
    scope regardless of principal type -- `core/rbac/authorization.py
    ::_actor_reaches_tenant_at_scope()`'s own docstring already prevents
    this for `User` delegators, and no code path in this phase lets a
    service account call `create_delegation()`/`create_delegation_to_service_account()`
    as the granting party in the first place, since both require a real
    `delegator_user_id`).
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
        # Delegate-side principal type additionally supports
        # 'service_account' (architecture research Phase E) -- the
        # delegator side above is deliberately left unchanged: this phase
        # constructs no delegation *from* a service account (that would be
        # a service account redelegating authority it never itself
        # created, exactly the "do not add redelegation functionality"
        # scope boundary), only delegations *to* one.
        CheckConstraint(
            "delegate_principal_type IN ('user', 'system', 'service_account')",
            name="ck_delegation_grants_delegate_principal_type",
        ),
        # Three-way pairing: exactly one of `delegate_principal_id`
        # (a `core.users` row, 'user' only) or
        # `delegate_service_account_id` (a `core.service_accounts` row,
        # 'service_account' only) is set, matching the principal type;
        # 'system' sets neither, identical to the delegator side.
        # `delegate_service_account_id` cannot share `delegate_principal_id`'s
        # plain FK to `core.users.id` (a single column cannot validly
        # target two different tables depending on a row's own type), so
        # it is its own nullable column with its own FK -- see this
        # class's own docstring for the alternative considered and why
        # this shape is preferred.
        CheckConstraint(
            "(delegate_principal_type = 'user' "
            " AND delegate_principal_id IS NOT NULL AND delegate_service_account_id IS NULL) "
            "OR (delegate_principal_type = 'system' "
            " AND delegate_principal_id IS NULL AND delegate_service_account_id IS NULL) "
            "OR (delegate_principal_type = 'service_account' "
            " AND delegate_principal_id IS NULL AND delegate_service_account_id IS NOT NULL)",
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
        # Includes `delegate_service_account_id` (Phase E) so a
        # service-account delegate's lookup is covered by the same index,
        # not a second one.
        Index(
            "ix_delegation_grants_tenant_delegate",
            "tenant_id",
            "delegate_principal_type",
            "delegate_principal_id",
            "delegate_service_account_id",
        ),
        # Partial unique index, active grants only (`revoked_at IS NULL`):
        # blocks an accidental duplicate of the exact same still-active
        # grant (same tenant/delegate/scope/permission), without blocking
        # a second grant that differs in scope, permission, or validity
        # window, and without blocking re-granting after the prior grant
        # was revoked or allowed to expire (architecture research:
        # "prevent accidental duplicate active grants... do not
        # over-constrain"). Includes `delegate_service_account_id` (Phase
        # E) for the identical reason the lookup index above does --
        # without it, two rows both naming `delegate_principal_id = NULL`
        # (every service-account-delegate row) would never collide on
        # this constraint regardless of `delegate_service_account_id`,
        # since SQL `NULL` never equals `NULL` in a uniqueness check.
        Index(
            "uq_delegation_grants_active_unique",
            "tenant_id",
            "delegate_principal_type",
            "delegate_principal_id",
            "delegate_service_account_id",
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
    # Architecture research Phase E: set only when
    # `delegate_principal_type == 'service_account'` -- see this class's
    # own docstring and the pairing CHECK above.
    delegate_service_account_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.service_accounts.id"), nullable=True
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


class DenyGrant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An explicit, scoped, individually-revocable block of exactly one
    `Permission` for one principal, over `tenant_id` (architecture
    research: universal multi-tenant tenancy, Phase D -- "Explicit Deny".
    "DENY overrides ALLOW"). Tenant-owned, RLS-protected, exactly like
    every other `core/rbac` table -- `tenant_id` here names the tenant
    this deny's scope *concerns* (the "scope tenant"), the same convention
    `DelegationGrant.tenant_id` already uses.

    **Deny is its own explicit authorization construct, never implied by
    hierarchy or by delegation.** A deny targets an ordinary principal
    (`(principal_type, principal_id)`, `core/rbac/principal.py::PrincipalType`
    -- this phase constructs only `PrincipalType.USER`, mirroring
    `DelegationGrant`) at a `Permission`, evaluated by
    `core/rbac/authorization.py::can()` **before** every allow path (
    ordinary membership-role, inherited-via-SUBTREE, and delegated) is
    even attempted -- a matching, unrevoked `DenyGrant` makes `can()`
    return `False` immediately, regardless of what any allow path would
    otherwise have granted. A `DenyGrant` never itself grants anything:
    there is no code path where matching one contributes to an `ALLOW`
    result (module docstring's own "DENY overrides ALLOW" rule).

    Unlike `DelegationGrant`, a `DenyGrant` is **unilateral, not
    bilateral**: it names only the principal being denied, not who issued
    it (that is recorded, as with every other `core/rbac` write, in
    `core.audit_log` at creation time -- `core/rbac/service.py::create_deny()`
    -- not duplicated onto this row as a speculative "grantor" column).

    `scope_mode` reuses `core/rbac/scope.py::RoleScope` exactly like
    `DelegationGrant.scope_mode` does, with the identical live,
    never-snapshotted evaluation against `core.tenant_ancestry`:

        SELF    -- affects only `tenant_id` itself. Matched by `can()`
                   only when the tenant being evaluated *is* `tenant_id`.
        SUBTREE -- affects `tenant_id` and its *current* descendants.
                   Matched by `can()` both at `tenant_id` itself and at
                   every tenant that has `tenant_id` as a live ancestor --
                   this is precisely how an ancestor's `SUBTREE` deny
                   overrides an allow (ordinary, inherited, or delegated)
                   granted at a descendant.

    A deny at a tenant unrelated to the one being evaluated (not the
    target tenant itself and not one of its live ancestors) is never
    considered -- `can()` walks exactly the same ancestor chain for deny
    as it already does for every allow path, never a wider one.

    **Deliberately not time-bounded** (no `starts_at`/`expires_at`),
    unlike `DelegationGrant`: a deny is a restrictive control, not a
    grant, so the safe default on "forgetting to manage its lifecycle" is
    the opposite of a delegation's -- a delegation that is forgotten
    should lapse (time-bounded, so access is not silently held open
    forever); a deny that is forgotten should keep blocking (so access is
    never silently restored without an explicit `revoke_deny()` call).
    Only `revoked_at` (nullable, `NULL` while active) models its
    lifecycle, evaluated live by `can()` on every call, exactly like
    `DelegationGrant.revoked_at` -- no cache, no background job, a write
    is authoritative for the very next authorization check.

    **No anti-amplification check on creation** (unlike
    `create_delegation()`'s `_actor_reaches_tenant_at_scope()`): a deny
    can only ever remove authority, never grant more than its creator
    already effectively controls, so `create_deny()` does not require the
    creator to already hold the permission being denied -- only the
    separate "manage deny grants in this tenant" capability
    (`(resource="deny_grant", action="create")`), checked through the
    same `can()` chokepoint every other `core/rbac` management operation
    uses. There is no privilege-amplification concern here for the same
    reason there is no `resource_constraint`-shaped concern: a `DenyGrant`
    subtracts from what `can()` would otherwise answer, it never adds.

    No `resource_constraint` field, for the identical reason
    `DelegationGrant` has none -- see that class's own docstring.

    **Principal may be a service account (architecture research Phase
    E).** `principal_type` additionally accepts `'service_account'`,
    naming a `core/identity.ServiceAccount` via
    `principal_service_account_id` instead of `principal_id` (this
    class's own `__table_args__` pairing `CheckConstraint`) -- so a
    service account can be explicitly denied a permission exactly like a
    `User` principal can, through the identical `can()` evaluation, never
    a second deny mechanism. This is what lets an explicit deny override
    a service account's ordinary-role or delegated authority (Phase E's
    own "DENY overrides ALLOW" requirement, applied to machine
    principals).
    """

    __tablename__ = "deny_grants"
    __table_args__ = (
        CheckConstraint(
            "principal_type IN ('user', 'system', 'service_account')",
            name="ck_deny_grants_principal_type",
        ),
        # Three-way pairing, mirroring `DelegationGrant`'s delegate-side
        # pairing exactly (architecture research Phase E) -- see that
        # class's own `__table_args__` comment for why
        # `principal_service_account_id` is a separate column rather than
        # widening `principal_id`'s own FK target.
        CheckConstraint(
            "(principal_type = 'user' "
            " AND principal_id IS NOT NULL AND principal_service_account_id IS NULL) "
            "OR (principal_type = 'system' "
            " AND principal_id IS NULL AND principal_service_account_id IS NULL) "
            "OR (principal_type = 'service_account' "
            " AND principal_id IS NULL AND principal_service_account_id IS NOT NULL)",
            name="ck_deny_grants_principal_pairing",
        ),
        CheckConstraint(
            "scope_mode IN ('self', 'subtree')", name="ck_deny_grants_valid_scope_mode"
        ),
        # Active-lookup index -- the exact shape
        # `core/rbac/authorization.py`'s deny check queries by: "which of
        # this tenant's denies name this principal". Includes
        # `principal_service_account_id` (Phase E), mirroring
        # `ix_delegation_grants_tenant_delegate`.
        Index(
            "ix_deny_grants_tenant_principal",
            "tenant_id",
            "principal_type",
            "principal_id",
            "principal_service_account_id",
        ),
        # Partial unique index, active denies only (`revoked_at IS NULL`):
        # blocks an accidental duplicate of the exact same still-active
        # deny (same tenant/principal/scope/permission), without blocking
        # a second deny that differs in scope or permission, and without
        # blocking re-denying after the prior deny was revoked -- mirrors
        # `uq_delegation_grants_active_unique` exactly, including the same
        # `principal_service_account_id` inclusion for the same
        # NULL-never-equals-NULL reason.
        Index(
            "uq_deny_grants_active_unique",
            "tenant_id",
            "principal_type",
            "principal_id",
            "principal_service_account_id",
            "scope_mode",
            "permission_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
        {"schema": "core"},
    )

    # `tenant_id` FK uses ON DELETE CASCADE, unlike `Tenant.parent_id`'s
    # plain (blocking) FK -- a deny grant has no meaning once its own
    # scope tenant no longer exists, the same reasoning
    # `DelegationGrant.tenant_id` already applies.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id", ondelete="CASCADE"), nullable=False
    )

    principal_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default=PrincipalType.USER.value
    )
    principal_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    # Architecture research Phase E: set only when
    # `principal_type == 'service_account'` -- see this class's own
    # docstring and the pairing CHECK above.
    principal_service_account_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.service_accounts.id"), nullable=True
    )

    scope_mode: Mapped[str] = mapped_column(
        String(20), nullable=False, default=RoleScope.SELF.value
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.permissions.id"), nullable=False
    )

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ServiceAccountRole(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An assignment of one tenant's `Role` to one `core/identity.ServiceAccount`
    (architecture research: universal multi-tenant tenancy, Phase E --
    "Principal + Service Accounts + API Key Hardening") -- tenant-owned,
    RLS-protected. The machine-principal analogue of `MembershipRole`,
    reusing the identical `Role`/`Permission`/`RolePermission` entities
    and the identical `scope` semantics (`RoleScope.SELF`/`SUBTREE`,
    `core/rbac/scope.py`) -- never a second permission model.

    **Structurally anchored to the service account's own tenant, unlike
    `MembershipRole`.** `MembershipRole` references a `TenantMembership`,
    and a `User` may hold a *separate* `TenantMembership` (and therefore a
    separate role assignment) in each of several tenants -- this is
    exactly how a `SUBTREE`-scoped `MembershipRole` at an ancestor tenant
    reaches a descendant: the user is independently a member of that
    ancestor tenant too. A `ServiceAccount` has no such second identity to
    hold a second assignment: the composite foreign key below,
    `(tenant_id, service_account_id) -> service_accounts(tenant_id, id)`,
    can only ever be satisfied when `tenant_id` equals the service
    account's own, single, fixed `tenant_id`
    (`core/identity/models.py::ServiceAccount`'s own docstring) -- so
    every `ServiceAccountRole` a given service account ever holds lives in
    that one tenant. A `SUBTREE`-scoped row there still reaches that
    tenant's current descendants exactly like a `SUBTREE`-scoped
    `MembershipRole` does (`core/rbac/authorization.py::can()` walks the
    identical live `core.tenant_ancestry` chain for both), but a service
    account can never be assigned a role "in" a different tenant the way a
    multi-tenant `User` can -- this is what makes "a service account must
    not automatically gain authority over parent or child tenants" (and,
    by the same structural argument, any *unrelated* tenant) true without
    an extra runtime check: there is no row for `can()` to find anywhere
    but this service account's own tenant and that tenant's descendants.

    Broader, hierarchy-independent authorization for a service account
    (an unrelated tenant, or authority the assigning actor does not
    itself already hold at the required scope) is `DelegationGrant`'s
    job, not this table's -- identical division of responsibility to the
    ordinary `MembershipRole`/`DelegationGrant` split
    (`DelegationGrant`'s own docstring: "delegation is intentionally
    separate from hierarchy").

    Assignment (`core/rbac/service.py::assign_service_account_role()`) is
    authorized through the same `can()` chokepoint every other
    `core/rbac` management operation uses (the dedicated
    `(resource="service_account_role", action="create")` capability), AND
    carries its own anti-amplification check -- unlike ordinary
    `assign_role()` for a `User` membership, which this phase leaves
    exactly as-is (trusting its caller, Phase 8's ingress-layer
    responsibility): a service account is a machine credential, reachable
    by anyone holding one of its API keys, so granting it a role is
    treated with the same "the assignor must already hold at least this
    much authority, through ordinary membership-role authorization alone,
    never delegation" discipline `_actor_reaches_tenant_at_scope()`
    already enforces for delegation creation -- checked once per
    permission the role grants, since a `Role` (unlike a `DelegationGrant`)
    may carry more than one (`core/rbac/service.py::assign_service_account_role()`'s
    own docstring).
    """

    __tablename__ = "service_account_roles"
    __table_args__ = (
        UniqueConstraint(
            "service_account_id", "role_id", name="uq_service_account_roles_service_account_role"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "service_account_id"],
            ["core.service_accounts.tenant_id", "core.service_accounts.id"],
            name="fk_service_account_roles_tenant_service_account",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["core.roles.tenant_id", "core.roles.id"],
            name="fk_service_account_roles_tenant_role",
        ),
        CheckConstraint(
            "scope IN ('self', 'subtree')", name="ck_service_account_roles_valid_scope"
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    service_account_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False, default=RoleScope.SELF.value)
