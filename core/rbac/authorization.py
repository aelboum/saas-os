"""The single policy-evaluation chokepoint (docs/SECURITY.md section 3:
"Authorization is a single policy-evaluation call (`can(actor, action,
resource)`)"; docs/IMPLEMENTATION-ROADMAP.md Phase 3.3: "implement the
single `can(actor, action, resource)` evaluation chokepoint").

`can()` answers exactly one question: is `actor_id` (a `core/identity`
user) allowed to perform `action` on `resource` within `tenant_id`. It is
usable independently of HTTP -- no FastAPI dependency, no middleware, no
route -- so both a future ingress-layer check (Phase 8) and a future
Control-Plane tool invocation (Phase 7, `docs/AI-CONTROL-PLANE.md`) can
call the exact same function and get the exact same answer, per
docs/SECURITY.md section 3's own requirement ("no code path outside this
module makes an authorization decision").

Evaluation path (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 11,
extended by architecture research Phase B's scoped roles, Phase C's
delegation, and Phase D's explicit deny), every step fail-closed -- any
missing link in the chain returns `False`, never raises and never
defaults to allow.

**Step 0, before any allow path is even attempted: explicit deny
(architecture research Phase D -- "DENY overrides ALLOW").** At the
target tenant itself (either `RoleScope`) and at each strict ancestor
(`SUBTREE` only), is there an unrevoked `DenyGrant` naming this actor and
this exact `(resource, action)`? If so, `can()` returns `False`
immediately -- no ordinary, inherited, or delegated allow path below is
even evaluated. This is a hard override, not merely "checked first and
then re-weighed against an allow": there is no branch of this function
that can reach a `return True` once a deny has matched. A `DenyGrant`
itself never grants anything -- see `core/rbac/models.py::DenyGrant`'s
own docstring.

Only once no deny matches does this function try, at every tenant
considered (the target itself, then each strict ancestor), two
independent allow paths -- **ordinary membership-role authorization OR
valid delegated authorization** (architecture research Phase C) -- either
one succeeding is enough; delegation is not a parallel `can_delegated()`
system, it is one more path this same function checks:

    1. tenant exists                          (core.tenancy.get_tenant)
    2. user exists                            (core.identity.get_user)
    3. `tenant_id` and its live ancestor       (core.tenancy.get_ancestor_ids,
       chain (Phase A's `core.tenant_ancestry`)  Phase A)
    4. no explicit deny (Phase D, step 0       (core.rbac.DenyGrant)
       above) matches at `tenant_id` itself
       or at any of that ancestor chain
    5. at `tenant_id` itself, OR at each       (core.identity.TenantMembership;
       ancestor tenant in turn, EITHER --       core.rbac.DelegationGrant)
       (a) the actor has a membership there
       with >=1 role assignment whose `scope`
       reaches the *original* target
       `tenant_id` (`SELF` only reaches the
       membership's own tenant; `SUBTREE`
       also reaches every descendant), OR
       (b) the actor is the delegate of a
       valid (unexpired, unrevoked, started)
       `DelegationGrant` at that same
       candidate tenant, whose `scope_mode`
       reaches `tenant_id` the identical way
    6. >=1 of those roles/grants references    (core.rbac.RolePermission;
       the requested (resource, action) --      core.rbac.DelegationGrant.permission_id)
       a role via `RolePermission`, a
       delegation via its own single
       `permission_id` (never a whole role's
       permission set)
    7. every record above belongs to the       (RLS + composite FKs;
       tenant it is queried under               docs/IMPLEMENTATION-ROADMAP.md
                                                 Phase 3.3 section 18)

The deny check (step 0/4) and the allow checks (steps 5-6) walk the
*identical* ancestor chain, with the *identical* scope-widening rule
(`SELF` counts only at the exact tenant; `SUBTREE` also counts from every
strict ancestor) -- this is what makes "an ancestor deny with `SUBTREE`
scope overrides an allow granted at a descendant" fall out of the same
mechanism `core/rbac/scope.py::RoleScope` already uses for allow, rather
than a second, bespoke hierarchy-walk implementation.

Structural hierarchy (Phase A) grants nothing by itself: the ancestor
chain in step 3 only ever *selects which tenants' memberships and
delegation grants are even candidates* -- a hit still requires a real
membership (with a role, with a matching permission, with a scope wide
enough to reach the target) **or** a real, currently-valid delegation
grant (naming this actor as delegate, with a scope wide enough to reach
the target, referencing exactly this permission) in one of those tenants.
A user with neither along the whole chain is denied exactly as before
Phase B/C existed, and for any tenant with no ancestors (every tenant
before Phase A, and every tenant that has never been given a parent),
step 3's candidate set is just `{tenant_id}` itself -- collapsing this
function back to precisely its pre-Phase-B behavior when no delegation
grant exists either, since `SELF` and `SUBTREE` are indistinguishable at
the target tenant itself (`_tenant_grants_permission()` below always
allows either scope there, and `_tenant_grants_permission_via_delegation()`
mirrors that symmetrically).

Delegation never widens what it evaluates beyond the one `permission_id`
a grant names: a `SUBTREE`-mode `DelegationGrant` reaches its scope
tenant's descendants exactly the way a `SUBTREE`-scoped `MembershipRole`
does, never "every permission the delegator happens to hold" -- see
`core/rbac/models.py::DelegationGrant`'s own docstring. Delegation-grant
*creation* (`core/rbac/service.py::create_delegation()`) is authorized by
a wholly separate check, `_actor_reaches_tenant_at_scope()` below, which
never itself consults `DelegationGrant` rows -- so a delegate cannot use
delegated authority to create a further delegation in this phase (no
implicit redelegation), independent of any grant's `allow_redelegate`
value.

Step 6 is not a separate check performed by this function -- it is a
structural guarantee of the schema itself (`core/rbac/models.py`'s
composite foreign keys, and `DelegationGrant.tenant_id`'s plain FK) and of
every query below running through `tenant_session_scope(candidate_tenant_id)`
(RLS-protected, docs/MULTI-TENANCY.md) -- one such scoped query per
candidate tenant in the chain, never a single query spanning more than
one tenant's rows, and never a second GUC or an
`authorized_tenant_ids`-shaped policy (that remains explicitly out of
scope for this phase, `docs/MULTI-TENANCY.md` section 8). A membership,
role, or delegation grant belonging to a tenant outside the current
candidate's own `tenant_session_scope()` is not merely filtered out by
this function's own logic -- it is structurally unreachable through that
candidate's query in the first place.

This module reaches `core/identity`'s membership data and
`core/tenancy`'s ancestry data only through their published interfaces
(`core.identity.get_user`/`get_membership`, `core.tenancy.get_tenant`/
`get_ancestor_ids`) -- never by importing or querying another module's
ORM models directly (docs/DATA-ARCHITECTURE.md section 3: "No module
reads another module's tables directly, even for read-only purposes.
Cross-module reads happen through the owning module's published
interface"). Only `core/rbac`'s own tables (`MembershipRole`,
`RolePermission`, `Permission`, `DelegationGrant`) are queried directly
here.

This module never logs the requested permission's outcome, the actor, or
the tenant (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 22: audit
logging is Phase 3.4's, not built here) -- but every input to a future
audit entry (actor_id, tenant_id, action, resource, and the boolean
result) is already a plain value `can()`'s caller holds, so Phase 3.4 can
wrap this call with logging without this module changing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from core.identity import get_membership, get_user
from core.rbac.models import DelegationGrant, DenyGrant, MembershipRole, Permission, RolePermission
from core.rbac.principal import PrincipalType
from core.rbac.scope import RoleScope
from core.tenancy import TenantNotFoundError, get_ancestor_ids, get_tenant
from infra.db import select, tenant_session_scope

_TARGET_TENANT_SCOPES = (RoleScope.SELF, RoleScope.SUBTREE)
_ANCESTOR_TENANT_SCOPES = (RoleScope.SUBTREE,)


def _tenant_grants_permission(
    *,
    candidate_tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    action: str,
    resource: str,
    allowed_scopes: tuple[RoleScope, ...],
) -> bool:
    """Does `actor_id`'s membership in `candidate_tenant_id` (if any) have
    a role, with one of `allowed_scopes`, granting `(resource, action)`?
    One `tenant_session_scope(candidate_tenant_id)` query, exactly the
    shape `can()` used before Phase B for its single target tenant --
    `can()` now calls this once per candidate tenant in the ancestor
    chain instead of once overall (module docstring).
    """
    membership = get_membership(candidate_tenant_id, actor_id)
    if membership is None:
        return False

    with tenant_session_scope(candidate_tenant_id) as session:
        granting_role = session.execute(
            select(MembershipRole.role_id)
            .join(RolePermission, RolePermission.role_id == MembershipRole.role_id)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(
                MembershipRole.tenant_id == candidate_tenant_id,
                MembershipRole.membership_id == membership.id,
                MembershipRole.scope.in_([scope.value for scope in allowed_scopes]),
                RolePermission.tenant_id == candidate_tenant_id,
                Permission.resource == resource,
                Permission.action == action,
            )
            .limit(1)
        ).scalar_one_or_none()

        return granting_role is not None


def _tenant_grants_permission_via_delegation(
    *,
    candidate_tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    action: str,
    resource: str,
    allowed_scope_modes: tuple[RoleScope, ...],
) -> bool:
    """Is `actor_id` the delegate of a currently-valid `DelegationGrant`
    at `candidate_tenant_id`, with one of `allowed_scope_modes`, granting
    `(resource, action)`? Mirrors `_tenant_grants_permission()` exactly --
    same tenant-scoped query shape, same `allowed_scopes`-as-a-set
    parameterization -- so `can()` can try both paths symmetrically at
    every candidate tenant (module docstring).

    "Currently-valid" is evaluated live, against one `now` computed once
    per `can()` call (never cached, never a background deactivation job,
    architecture research Phase C): `starts_at <= now`, `revoked_at IS
    NULL`, and `expires_at IS NULL OR expires_at > now`. A grant that was
    valid a moment ago and has since been revoked or expired is excluded
    from this query the instant that becomes true -- there is no
    intermediate "still authorized until something notices" state.

    Only `PrincipalType.USER` delegates are ever matched: no code path in
    this phase constructs a `PrincipalType.SYSTEM` delegate
    (`core/rbac/principal.py`), so this function does not need to resolve
    one.
    """
    now = datetime.now(UTC)

    with tenant_session_scope(candidate_tenant_id) as session:
        granting_delegation = session.execute(
            select(DelegationGrant.id)
            .join(Permission, Permission.id == DelegationGrant.permission_id)
            .where(
                DelegationGrant.tenant_id == candidate_tenant_id,
                DelegationGrant.delegate_principal_type == PrincipalType.USER.value,
                DelegationGrant.delegate_principal_id == actor_id,
                DelegationGrant.scope_mode.in_([mode.value for mode in allowed_scope_modes]),
                DelegationGrant.revoked_at.is_(None),
                DelegationGrant.starts_at <= now,
                (DelegationGrant.expires_at.is_(None)) | (DelegationGrant.expires_at > now),
                Permission.resource == resource,
                Permission.action == action,
            )
            .limit(1)
        ).scalar_one_or_none()

        return granting_delegation is not None


def _tenant_denies_permission(
    *,
    candidate_tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    action: str,
    resource: str,
    allowed_scope_modes: tuple[RoleScope, ...],
) -> bool:
    """Is there an unrevoked `DenyGrant` at `candidate_tenant_id`, naming
    `actor_id` as principal, with one of `allowed_scope_modes`, blocking
    `(resource, action)`? Mirrors `_tenant_grants_permission_via_delegation()`'s
    query shape exactly (architecture research Phase D), so `can()`'s deny
    check walks the same candidate-tenant loop the allow checks do.

    Deliberately no time-validity filter beyond `revoked_at IS NULL` --
    unlike `DelegationGrant`, a `DenyGrant` has no `starts_at`/`expires_at`
    (`core/rbac/models.py::DenyGrant`'s own docstring: a forgotten deny
    should keep blocking, not silently lapse).

    Only `PrincipalType.USER` principals are ever matched -- no code path
    in this phase constructs a `PrincipalType.SYSTEM` deny principal
    (`core/rbac/principal.py`), identical to the delegation check above.
    """
    with tenant_session_scope(candidate_tenant_id) as session:
        denying_grant = session.execute(
            select(DenyGrant.id)
            .join(Permission, Permission.id == DenyGrant.permission_id)
            .where(
                DenyGrant.tenant_id == candidate_tenant_id,
                DenyGrant.principal_type == PrincipalType.USER.value,
                DenyGrant.principal_id == actor_id,
                DenyGrant.scope_mode.in_([mode.value for mode in allowed_scope_modes]),
                DenyGrant.revoked_at.is_(None),
                Permission.resource == resource,
                Permission.action == action,
            )
            .limit(1)
        ).scalar_one_or_none()

        return denying_grant is not None


def _actor_is_denied(
    *, actor_id: uuid.UUID, tenant_id: uuid.UUID, action: str, resource: str
) -> bool:
    """Does any unrevoked `DenyGrant` block `actor_id` from `(resource,
    action)` at `tenant_id` -- at `tenant_id` itself (either scope) or at
    any of its live ancestors (`SUBTREE` only, architecture research Phase
    D)? Walks the identical `core.tenancy.get_ancestor_ids(tenant_id)`
    chain `can()`'s own allow loop walks below, with the identical
    scope-widening rule -- see `_tenant_denies_permission()` and this
    module's own docstring.

    Called once, before any allow path is attempted, by `can()` -- never
    called from within an allow-path helper, so there is no branch of
    this module where a deny is checked only *after* an allow has already
    been decided.
    """
    if _tenant_denies_permission(
        candidate_tenant_id=tenant_id,
        actor_id=actor_id,
        action=action,
        resource=resource,
        allowed_scope_modes=_TARGET_TENANT_SCOPES,
    ):
        return True
    for ancestor_id in get_ancestor_ids(tenant_id):
        if ancestor_id == tenant_id:
            continue
        if _tenant_denies_permission(
            candidate_tenant_id=ancestor_id,
            actor_id=actor_id,
            action=action,
            resource=resource,
            allowed_scope_modes=_ANCESTOR_TENANT_SCOPES,
        ):
            return True
    return False


def _actor_reaches_tenant_at_scope(
    *,
    actor_id: uuid.UUID,
    tenant_id: uuid.UUID,
    action: str,
    resource: str,
    required_scope: RoleScope,
) -> bool:
    """Does `actor_id` hold, through **ordinary membership-role
    authorization only** (never delegation -- see below), at least
    `required_scope`-level authority reaching `tenant_id` for `(action,
    resource)`? Used exclusively by `core/rbac/service.py::create_delegation()`
    to enforce "a delegator may delegate only permissions/roles the
    delegator currently possesses within the delegation's target scope"
    (architecture research Phase C) -- i.e. the anti-amplification check.

    `required_scope=SELF`: equivalent to plain `can()` at `tenant_id` --
    any role reaching `tenant_id` itself is enough, since the resulting
    `SELF`-mode delegation can never authorize more than `tenant_id`
    itself, which the delegator can already do.

    `required_scope=SUBTREE`: a role that only reaches `tenant_id` at
    `SELF` scope is deliberately NOT enough here, even though it would
    satisfy plain `can()` at `tenant_id` -- a `SUBTREE`-mode delegation
    reaches `tenant_id`'s descendants too, so the delegator's *own*
    authority must itself be `SUBTREE`-capable (at `tenant_id`, or
    inherited via `SUBTREE` from one of `tenant_id`'s ancestors), or the
    delegate would end up with strictly more reach than the delegator --
    exactly the privilege amplification this function exists to prevent.

    Deliberately never consults `DelegationGrant` at all, in either
    branch: if it did, a delegate could use delegated authority to create
    a further delegation (implicit redelegation), which architecture
    research Phase C requires be impossible by default
    (`allow_redelegate = false`, and no code path in this phase implements
    the alternative regardless of that field's value --
    `core/rbac/models.py::DelegationGrant`'s own docstring).
    """
    if required_scope is RoleScope.SELF:
        return _tenant_grants_permission(
            candidate_tenant_id=tenant_id,
            actor_id=actor_id,
            action=action,
            resource=resource,
            allowed_scopes=_TARGET_TENANT_SCOPES,
        )

    # required_scope is SUBTREE: a SELF-only role AT tenant_id does not
    # qualify -- only a SUBTREE-capable role does, whether held directly
    # at tenant_id or inherited via SUBTREE from one of its ancestors.
    if _tenant_grants_permission(
        candidate_tenant_id=tenant_id,
        actor_id=actor_id,
        action=action,
        resource=resource,
        allowed_scopes=_ANCESTOR_TENANT_SCOPES,
    ):
        return True
    for ancestor_id in get_ancestor_ids(tenant_id):
        if ancestor_id == tenant_id:
            continue
        if _tenant_grants_permission(
            candidate_tenant_id=ancestor_id,
            actor_id=actor_id,
            action=action,
            resource=resource,
            allowed_scopes=_ANCESTOR_TENANT_SCOPES,
        ):
            return True
    return False


def can(*, actor_id: uuid.UUID, tenant_id: uuid.UUID, action: str, resource: str) -> bool:
    """Is `actor_id` allowed to perform `action` on `resource` within
    `tenant_id`? Always returns a plain `bool` -- deny is a normal return
    value, never an exception (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3
    section 12: "Never interpret missing RBAC information as permission
    granted").
    """
    try:
        get_tenant(tenant_id)
    except TenantNotFoundError:
        return False

    if get_user(actor_id) is None:
        return False

    # Explicit deny (architecture research Phase D -- "DENY overrides
    # ALLOW"), checked before any allow path below is even attempted. A
    # match here is a hard override: no code path past this point can
    # still return True once `_actor_is_denied()` returns True (module
    # docstring's step 0).
    if _actor_is_denied(actor_id=actor_id, tenant_id=tenant_id, action=action, resource=resource):
        return False

    # The target tenant itself: either scope authorizes it, via ordinary
    # membership-role authorization OR a valid delegation grant (module
    # docstring) -- checked first since it is the common case (a flat,
    # non-hierarchical tenant, or a direct SELF-scoped assignment) and
    # needs no ancestor lookup at all.
    if _tenant_grants_permission(
        candidate_tenant_id=tenant_id,
        actor_id=actor_id,
        action=action,
        resource=resource,
        allowed_scopes=_TARGET_TENANT_SCOPES,
    ):
        return True
    if _tenant_grants_permission_via_delegation(
        candidate_tenant_id=tenant_id,
        actor_id=actor_id,
        action=action,
        resource=resource,
        allowed_scope_modes=_TARGET_TENANT_SCOPES,
    ):
        return True

    # Strict ancestors: only a SUBTREE-scoped assignment or a SUBTREE-mode
    # delegation there reaches down to `tenant_id`. Evaluated against the
    # *current* live ancestor chain (core.tenancy.get_ancestor_ids), never
    # a value cached at assignment/grant time -- if the hierarchy changes,
    # this answer changes with it, with no rewrite of any MembershipRole
    # or DelegationGrant row.
    for ancestor_id in get_ancestor_ids(tenant_id):
        if ancestor_id == tenant_id:
            continue
        if _tenant_grants_permission(
            candidate_tenant_id=ancestor_id,
            actor_id=actor_id,
            action=action,
            resource=resource,
            allowed_scopes=_ANCESTOR_TENANT_SCOPES,
        ):
            return True
        if _tenant_grants_permission_via_delegation(
            candidate_tenant_id=ancestor_id,
            actor_id=actor_id,
            action=action,
            resource=resource,
            allowed_scope_modes=_ANCESTOR_TENANT_SCOPES,
        ):
            return True

    return False
