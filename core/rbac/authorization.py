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
extended by architecture research Phase B's scoped roles), every step
fail-closed -- any missing link in the chain returns `False`, never
raises and never defaults to allow:

    1. tenant exists                          (core.tenancy.get_tenant)
    2. user exists                            (core.identity.get_user)
    3. `tenant_id` and its live ancestor       (core.tenancy.get_ancestor_ids,
       chain (Phase A's `core.tenant_ancestry`)  Phase A)
    4. for `tenant_id` itself, OR for each     (core.identity.TenantMembership)
       ancestor tenant in turn: the actor
       has a membership there
    5. that membership has >=1 role assignment (core.rbac.MembershipRole)
       whose `scope` reaches the *original*
       target `tenant_id` -- `SELF` only
       reaches the membership's own tenant;
       `SUBTREE` also reaches every
       descendant, i.e. every non-self
       candidate in step 3/4
    6. >=1 of those roles grants the           (core.rbac.RolePermission)
       requested (resource, action)
    7. every record above belongs to the       (RLS + composite FKs;
       tenant it is queried under               docs/IMPLEMENTATION-ROADMAP.md
                                                 Phase 3.3 section 18)

Structural hierarchy (Phase A) grants nothing by itself: the ancestor
chain in step 3 only ever *selects which tenants' memberships are even
candidates* -- a hit still requires a real membership in one of those
tenants, with a role, with a matching permission, with a scope wide
enough to reach the target. A user with zero memberships along the whole
chain is denied exactly as before Phase B existed, and for any tenant
with no ancestors (every tenant before Phase A, and every tenant that has
never been given a parent), step 3's candidate set is just `{tenant_id}`
itself -- collapsing this function back to precisely its pre-Phase-B
behavior, since `SELF` and `SUBTREE` are indistinguishable at the target
tenant itself (`_tenant_grants_permission()` below always allows either
scope there).

Step 7 is not a separate check performed by this function -- it is a
structural guarantee of the schema itself (`core/rbac/models.py`'s
composite foreign keys) and of every query below running through
`tenant_session_scope(candidate_tenant_id)` (RLS-protected,
docs/MULTI-TENANCY.md) -- one such scoped query per candidate tenant in
the chain, never a single query spanning more than one tenant's rows, and
never a second GUC or an `authorized_tenant_ids`-shaped policy (that
remains explicitly out of scope for this phase, `docs/MULTI-TENANCY.md`
section 8). A membership, role, or grant belonging to a tenant outside
the current candidate's own `tenant_session_scope()` is not merely
filtered out by this function's own logic -- it is structurally
unreachable through that candidate's query in the first place.

This module reaches `core/identity`'s membership data and
`core/tenancy`'s ancestry data only through their published interfaces
(`core.identity.get_user`/`get_membership`, `core.tenancy.get_tenant`/
`get_ancestor_ids`) -- never by importing or querying another module's
ORM models directly (docs/DATA-ARCHITECTURE.md section 3: "No module
reads another module's tables directly, even for read-only purposes.
Cross-module reads happen through the owning module's published
interface"). Only `core/rbac`'s own tables (`MembershipRole`,
`RolePermission`, `Permission`) are queried directly here.

This module never logs the requested permission's outcome, the actor, or
the tenant (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 22: audit
logging is Phase 3.4's, not built here) -- but every input to a future
audit entry (actor_id, tenant_id, action, resource, and the boolean
result) is already a plain value `can()`'s caller holds, so Phase 3.4 can
wrap this call with logging without this module changing.
"""

from __future__ import annotations

import uuid

from core.identity import get_membership, get_user
from core.rbac.models import MembershipRole, Permission, RolePermission
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

    # The target tenant itself: either scope authorizes it (module
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

    # Strict ancestors: only a SUBTREE-scoped assignment there reaches
    # down to `tenant_id`. Evaluated against the *current* live ancestor
    # chain (core.tenancy.get_ancestor_ids), never a value cached at
    # assignment time -- if the hierarchy changes, this answer changes
    # with it, with no rewrite of any MembershipRole row.
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
