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

Evaluation path (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 11),
every step fail-closed -- any missing link in the chain returns `False`,
never raises and never defaults to allow:

    1. tenant exists                         (core.tenancy.get_tenant)
    2. user exists                           (core.identity.get_user)
    3. user has a membership in the tenant   (core.identity.TenantMembership)
    4. that membership has >=1 role          (core.rbac.MembershipRole)
    5. >=1 of those roles grants the         (core.rbac.RolePermission)
       requested (resource, action)
    6. every record above belongs to the     (RLS + composite FKs;
       same tenant                            docs/IMPLEMENTATION-ROADMAP.md
                                               Phase 3.3 section 18)

Step 6 is not a separate check performed by this function -- it is a
structural guarantee of the schema itself (`core/rbac/models.py`'s
composite foreign keys) and of every query below running through
`tenant_session_scope(tenant_id)` (RLS-protected, docs/MULTI-TENANCY.md).
A membership, role, or grant belonging to a different tenant is not merely
filtered out by this function's own logic -- it is structurally
unreachable through these queries in the first place.

This module reaches `core/identity`'s membership data only through its
published interface (`core.identity.get_user`, `core.identity.get_membership`)
-- never by importing or querying `core.identity`'s ORM models directly
(docs/DATA-ARCHITECTURE.md section 3: "No module reads another module's
tables directly, even for read-only purposes. Cross-module reads happen
through the owning module's published interface"). Only `core/rbac`'s own
tables (`MembershipRole`, `RolePermission`, `Permission`) are queried
directly here.

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
from core.tenancy import TenantNotFoundError, get_tenant
from infra.db import select, tenant_session_scope


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

    membership = get_membership(tenant_id, actor_id)
    if membership is None:
        return False

    with tenant_session_scope(tenant_id) as session:
        granting_role = session.execute(
            select(MembershipRole.role_id)
            .join(RolePermission, RolePermission.role_id == MembershipRole.role_id)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(
                MembershipRole.tenant_id == tenant_id,
                MembershipRole.membership_id == membership.id,
                RolePermission.tenant_id == tenant_id,
                Permission.resource == resource,
                Permission.action == action,
            )
            .limit(1)
        ).scalar_one_or_none()

        return granting_role is not None
