"""The single policy-evaluation chokepoint (docs/SECURITY.md section 3:
"Authorization is a single policy-evaluation call (`can(actor, action,
resource)`)"; docs/IMPLEMENTATION-ROADMAP.md Phase 3.3: "implement the
single `can(actor, action, resource)` evaluation chokepoint").

`can()` answers exactly one question: is `actor_id` (a `core/identity`
`User` or `ServiceAccount`, named by `actor_type` -- architecture research
Phase E) allowed to perform `action` on `resource` within `tenant_id`. It
is usable independently of HTTP -- no FastAPI dependency, no middleware,
no route -- so both a future ingress-layer check (Phase 8) and a future
Control-Plane tool invocation (Phase 7, `docs/AI-CONTROL-PLANE.md`) can
call the exact same function and get the exact same answer, per
docs/SECURITY.md section 3's own requirement ("no code path outside this
module makes an authorization decision").

**Machine principals (architecture research Phase E).** `actor_type`
defaults to `PrincipalType.USER` -- every pre-Phase-E caller's behavior is
byte-for-byte unchanged. Passing `actor_type=PrincipalType.SERVICE_ACCOUNT`
evaluates a `core/identity.ServiceAccount` instead: `actor_id` is the
service account's id, and the caller must additionally supply
`actor_tenant_id` -- the ONE tenant this service account belongs to
(`core/identity/models.py::ServiceAccount`'s own docstring: fixed at
creation, never reassigned), which is generally NOT the same value as
`tenant_id` (the tenant the action itself is being evaluated against --
an ancestor, a descendant, or an unrelated tenant the service account was
explicitly delegated into). This is exactly analogous to how `get_user()`
resolves a `User` globally, independent of `tenant_id`, except a service
account has no global table to resolve from (it is tenant-owned,
RLS-protected) -- `actor_tenant_id` is what makes that resolution
possible without either a global service-account registry or an
`app.authorized_tenant_ids`-shaped bypass. `can()` never bypasses `core/rbac`'s
existing machinery for this: it is one more actor shape the same
deny-then-allow evaluation below already handles, never a parallel
machine-authorization engine. No other `actor_type` is accepted --
`PrincipalType.SYSTEM` or anything else fails closed (`return False`)
before any allow/deny path is even attempted, since no code path in this
phase constructs a `SYSTEM` actor for `can()` to evaluate.

**Support access (architecture research Phase F -- "Audit + Support
Access").** A platform support engineer's own real `PrincipalType.USER`
identity may hold an explicitly-approved `SupportAccessRequest`
(`core/rbac/models.py`) granting time-bounded, tenant-level access to a
target tenant -- never impersonation, never a changed identity: `actor_id`
is always the operator's own user id, so the *existing* deny check below
already covers them, with no support-specific deny logic added. Checked
as the LAST allow path, only once every ordinary and delegated allow has
already failed (`_actor_has_support_access()`'s own docstring) -- and
never for a handful of hardcoded RBAC/credential-management resources
(`_SUPPORT_ACCESS_EXCLUDED_RESOURCES`), so a support grant can never
create a delegation, a deny, a service-account role, an API key, a
service account, or a further support grant.

**Membership lifecycle (architecture research Phase G -- "Invitation /
Membership Lifecycle").** A `TenantMembership` now carries an explicit
`core.identity.MembershipStatus` (`ACTIVE`/`SUSPENDED`/`REVOKED`).
Ordinary membership-role authorization (`_tenant_grants_permission()`)
requires `status == ACTIVE` before it will honor any `MembershipRole` the
membership holds -- a suspended or revoked membership is authorized
exactly as if it held no roles at all, regardless of what
`core.rbac.membership_roles` rows still exist for it (no cascading
cleanup is performed or needed; `status` is the single, live, authoritative
switch). Delegated authorization for a `USER` delegate carries the
identical restriction when, and only when, the delegate genuinely holds a
membership at the tenant the delegation concerns
(`_delegate_user_membership_permits_authorization()`) -- a delegate with
no membership there at all is unaffected, preserving Phase C's original
"delegation is intentionally separate from hierarchy" design. Explicit
deny, service-account authorization, and support access are unaffected by
membership status entirely (none of them relies on a human
`TenantMembership` row in the first place).

Evaluation path (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 11,
extended by architecture research Phase B's scoped roles, Phase C's
delegation, Phase D's explicit deny, Phase F's support access, and Phase
G's membership lifecycle), every step fail-closed -- any missing link in
the chain returns `False`, never raises and never defaults to allow.

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
       (a) the actor has an ACTIVE membership
       there (architecture research Phase G --
       `SUSPENDED`/`REVOKED` fails this step
       immediately, module docstring below)
       with >=1 role assignment whose
       `scope` reaches the *original* target
       `tenant_id` (`SELF` only reaches the
       membership's own tenant; `SUBTREE`
       also reaches every descendant), OR
       (b) the actor is the delegate of a
       valid (unexpired, unrevoked, started)
       `DelegationGrant` at that same
       candidate tenant, whose `scope_mode`
       reaches `tenant_id` the identical way
       -- and, if the delegate also happens to
       hold a membership at that candidate
       tenant, that membership is not
       `SUSPENDED`/`REVOKED` (Phase G;
       `_delegate_user_membership_permits_authorization()`)
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

from core.identity import (
    MembershipStatus,
    ServiceAccountStatus,
    get_membership,
    get_service_account,
    get_user,
)
from core.rbac.models import (
    DelegationGrant,
    DenyGrant,
    MembershipRole,
    Permission,
    RolePermission,
    ServiceAccountRole,
    SupportAccessRequest,
)
from core.rbac.principal import PrincipalType
from core.rbac.scope import RoleScope
from core.tenancy import TenantNotFoundError, get_ancestor_ids, get_tenant
from infra.db import select, tenant_session_scope

_TARGET_TENANT_SCOPES = (RoleScope.SELF, RoleScope.SUBTREE)
_ANCESTOR_TENANT_SCOPES = (RoleScope.SUBTREE,)

# architecture research Phase F -- "Audit + Support Access": the fixed,
# hardcoded set of resources an active `SupportAccessRequest` can NEVER
# satisfy, regardless of scope -- never a policy engine, never
# configurable, never per-tenant. Each entry is a persistent-privilege- or
# further-support-creation vector that must not be reachable from a
# temporary, revocable support session (this phase's own approved
# security requirement: "avoid privilege amplification" -- "a support
# grant must never itself be able to create: delegation grants, deny
# grants, service-account roles, unrestricted support grants"):
#
#     delegation_grant, deny_grant, service_account_role -- named
#         explicitly by the approved design.
#     support_access_request -- prevents a support grant from approving,
#         denying, or revoking ANY support-access request (including
#         itself or another one) -- "unrestricted support grants".
#     api_key, service_account -- not named explicitly, but the identical
#         principle applies: a support session that could mint a new,
#         non-expiring API key or a new service account would leave a
#         persistent artifact that silently outlives the support grant
#         that created it, exactly the amplification this list exists to
#         prevent.
_SUPPORT_ACCESS_EXCLUDED_RESOURCES = frozenset(
    {
        "delegation_grant",
        "deny_grant",
        "service_account_role",
        "support_access_request",
        "api_key",
        "service_account",
    }
)


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

    **Requires an ACTIVE membership (architecture research Phase G --
    "Invitation / Membership Lifecycle").** A membership that is
    `SUSPENDED` or `REVOKED` fails this check immediately, before any
    `MembershipRole` row is even queried -- membership
    `status` is authoritative for membership validity, so a stale role
    assignment can never outlive its own membership's own lifecycle
    (`core/identity/models.py::MembershipStatus`'s own docstring). This is
    the one place ordinary membership-role authorization is gated by
    membership status; every candidate tenant in `can()`'s ancestor walk
    goes through this same function, so the rule applies uniformly to
    both direct (`SELF`) and scoped (`SUBTREE`) role authorization.
    """
    membership = get_membership(candidate_tenant_id, actor_id)
    if membership is None or membership.status != MembershipStatus.ACTIVE.value:
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


def _tenant_grants_permission_for_service_account(
    *,
    candidate_tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    action: str,
    resource: str,
    allowed_scopes: tuple[RoleScope, ...],
) -> bool:
    """The `ServiceAccountRole` analogue of `_tenant_grants_permission()`
    (architecture research Phase E). No `get_membership()`-equivalent
    pre-check is needed: `ServiceAccountRole`'s own composite foreign key
    `(tenant_id, service_account_id) -> service_accounts(tenant_id, id)`
    already guarantees a row can only ever exist at the service account's
    own tenant, so a query at any *other* candidate tenant structurally
    returns zero rows -- there is nothing analogous to "is this actor
    even a member here" to check first (`core/rbac/models.py
    ::ServiceAccountRole`'s own docstring).
    """
    with tenant_session_scope(candidate_tenant_id) as session:
        granting_role = session.execute(
            select(ServiceAccountRole.role_id)
            .join(RolePermission, RolePermission.role_id == ServiceAccountRole.role_id)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(
                ServiceAccountRole.tenant_id == candidate_tenant_id,
                ServiceAccountRole.service_account_id == actor_id,
                ServiceAccountRole.scope.in_([scope.value for scope in allowed_scopes]),
                RolePermission.tenant_id == candidate_tenant_id,
                Permission.resource == resource,
                Permission.action == action,
            )
            .limit(1)
        ).scalar_one_or_none()

        return granting_role is not None


def _actor_grants_permission(
    *,
    candidate_tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_type: PrincipalType,
    action: str,
    resource: str,
    allowed_scopes: tuple[RoleScope, ...],
) -> bool:
    """Dispatch to the `User`-membership or `ServiceAccountRole` allow
    check, by `actor_type` (architecture research Phase E) -- the one
    switch point `can()`'s own ordinary-allow calls go through, so the
    ancestor-walk logic below never needs its own `if actor_type is ...`
    branching."""
    if actor_type is PrincipalType.USER:
        return _tenant_grants_permission(
            candidate_tenant_id=candidate_tenant_id,
            actor_id=actor_id,
            action=action,
            resource=resource,
            allowed_scopes=allowed_scopes,
        )
    return _tenant_grants_permission_for_service_account(
        candidate_tenant_id=candidate_tenant_id,
        actor_id=actor_id,
        action=action,
        resource=resource,
        allowed_scopes=allowed_scopes,
    )


def _delegate_user_membership_permits_authorization(
    *, candidate_tenant_id: uuid.UUID, actor_id: uuid.UUID
) -> bool:
    """Does an existing `TenantMembership` for `actor_id` at
    `candidate_tenant_id` (if any) permit delegated authorization there
    (architecture research Phase G section 7: "if a delegation grant
    references a USER principal, the relevant user must still satisfy
    the membership lifecycle rules required by the existing authorization
    model")?

    Delegation is intentionally NOT membership-gated in general --
    `DelegationGrant`'s own docstring: "a grant may target any tenant
    regardless of hierarchy relationship... no hierarchy relationship is
    required, checked, or implied by this table itself" -- a delegate who
    has never been a member of `candidate_tenant_id` at all is unaffected
    by this function (returns `True`, preserving Phase C's original,
    unchanged cross-tenant delegation behavior). The only new restriction
    (Phase G): if the delegate genuinely DOES hold a membership row at
    this exact tenant, and that membership is not `ACTIVE`, delegation
    must not become a side channel that keeps authorizing a suspended or
    revoked member -- exactly the "stale membership continuing to
    authorize access" scenario this phase exists to close.
    """
    membership = get_membership(candidate_tenant_id, actor_id)
    if membership is None:
        return True
    return membership.status == MembershipStatus.ACTIVE.value


def _tenant_grants_permission_via_delegation(
    *,
    candidate_tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_type: PrincipalType,
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

    `actor_type` (architecture research Phase E; `USER` or
    `SERVICE_ACCOUNT`) selects both the CHECK-constrained
    `delegate_principal_type` value to match and which id column names
    the delegate -- `delegate_principal_id` for `USER`,
    `delegate_service_account_id` for `SERVICE_ACCOUNT`
    (`core/rbac/models.py::DelegationGrant`'s own pairing CHECK). No code
    path in this phase constructs a `PrincipalType.SYSTEM` delegate
    (`core/rbac/principal.py`), so this function is never called with
    that type.
    """
    if actor_type is PrincipalType.USER and not _delegate_user_membership_permits_authorization(
        candidate_tenant_id=candidate_tenant_id, actor_id=actor_id
    ):
        return False

    now = datetime.now(UTC)
    delegate_id_column = (
        DelegationGrant.delegate_principal_id
        if actor_type is PrincipalType.USER
        else DelegationGrant.delegate_service_account_id
    )

    with tenant_session_scope(candidate_tenant_id) as session:
        granting_delegation = session.execute(
            select(DelegationGrant.id)
            .join(Permission, Permission.id == DelegationGrant.permission_id)
            .where(
                DelegationGrant.tenant_id == candidate_tenant_id,
                DelegationGrant.delegate_principal_type == actor_type.value,
                delegate_id_column == actor_id,
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
    actor_type: PrincipalType,
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

    `actor_type` (architecture research Phase E; `USER` or
    `SERVICE_ACCOUNT`) selects both the CHECK-constrained `principal_type`
    value to match and which id column names the principal --
    `principal_id` for `USER`, `principal_service_account_id` for
    `SERVICE_ACCOUNT` (`core/rbac/models.py::DenyGrant`'s own pairing
    CHECK). No code path in this phase constructs a `PrincipalType.SYSTEM`
    deny principal (`core/rbac/principal.py`), so this function is never
    called with that type.
    """
    principal_id_column = (
        DenyGrant.principal_id
        if actor_type is PrincipalType.USER
        else DenyGrant.principal_service_account_id
    )

    with tenant_session_scope(candidate_tenant_id) as session:
        denying_grant = session.execute(
            select(DenyGrant.id)
            .join(Permission, Permission.id == DenyGrant.permission_id)
            .where(
                DenyGrant.tenant_id == candidate_tenant_id,
                DenyGrant.principal_type == actor_type.value,
                principal_id_column == actor_id,
                DenyGrant.scope_mode.in_([mode.value for mode in allowed_scope_modes]),
                DenyGrant.revoked_at.is_(None),
                Permission.resource == resource,
                Permission.action == action,
            )
            .limit(1)
        ).scalar_one_or_none()

        return denying_grant is not None


def _actor_is_denied(
    *,
    actor_id: uuid.UUID,
    actor_type: PrincipalType,
    tenant_id: uuid.UUID,
    action: str,
    resource: str,
) -> bool:
    """Does any unrevoked `DenyGrant` block `actor_id` from `(resource,
    action)` at `tenant_id` -- at `tenant_id` itself (either scope) or at
    any of its live ancestors (`SUBTREE` only, architecture research Phase
    D)? Walks the identical `core.tenancy.get_ancestor_ids(tenant_id)`
    chain `can()`'s own allow loop walks below, with the identical
    scope-widening rule -- see `_tenant_denies_permission()` and this
    module's own docstring. `actor_type` (Phase E) is threaded straight
    through to `_tenant_denies_permission()`.

    Called once, before any allow path is attempted, by `can()` -- never
    called from within an allow-path helper, so there is no branch of
    this module where a deny is checked only *after* an allow has already
    been decided.
    """
    if _tenant_denies_permission(
        candidate_tenant_id=tenant_id,
        actor_id=actor_id,
        actor_type=actor_type,
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
            actor_type=actor_type,
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


def _tenant_grants_support_access(
    *,
    candidate_tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    resource: str,
    allowed_scope_modes: tuple[RoleScope, ...],
) -> bool:
    """Is there a currently-ACTIVE `SupportAccessRequest` at
    `candidate_tenant_id`, naming `actor_id` as requester, with one of
    `allowed_scope_modes` (architecture research Phase F)? Mirrors
    `_tenant_grants_permission_via_delegation()`'s query shape, with two
    deliberate differences: no `permission_id`/`(resource, action)` join
    at all (`SupportAccessRequest` is tenant-level, never
    permission-scoped -- that class's own docstring), and the
    `resource in _SUPPORT_ACCESS_EXCLUDED_RESOURCES` short-circuit, which
    makes a subset of resources structurally unreachable through this
    path regardless of how broad the request's scope is.

    "Currently-ACTIVE" is evaluated live, against one `now` per call,
    exactly like `_tenant_grants_permission_via_delegation()`'s own
    validity window: `approved_at IS NOT NULL`, `denied_at IS NULL`,
    `revoked_at IS NULL`, and `requested_starts_at <= now <
    requested_expires_at`.
    """
    if resource in _SUPPORT_ACCESS_EXCLUDED_RESOURCES:
        return False

    now = datetime.now(UTC)

    with tenant_session_scope(candidate_tenant_id) as session:
        granting_request = session.execute(
            select(SupportAccessRequest.id)
            .where(
                SupportAccessRequest.tenant_id == candidate_tenant_id,
                SupportAccessRequest.requester_user_id == actor_id,
                SupportAccessRequest.scope_mode.in_([mode.value for mode in allowed_scope_modes]),
                SupportAccessRequest.approved_at.is_not(None),
                SupportAccessRequest.denied_at.is_(None),
                SupportAccessRequest.revoked_at.is_(None),
                SupportAccessRequest.requested_starts_at <= now,
                SupportAccessRequest.requested_expires_at > now,
            )
            .limit(1)
        ).scalar_one_or_none()

        return granting_request is not None


def _actor_has_support_access(*, actor_id: uuid.UUID, tenant_id: uuid.UUID, resource: str) -> bool:
    """Does `actor_id` (a support engineer's own real `core.identity` user
    id -- never an impersonated identity) hold currently-ACTIVE support
    access reaching `tenant_id` for `resource` -- at `tenant_id` itself
    (either scope) or at any of its live ancestors (`SUBTREE` only,
    architecture research Phase F)? Walks the identical
    `core.tenancy.get_ancestor_ids(tenant_id)` chain `can()`'s own
    ordinary-allow loop walks, with the identical scope-widening rule --
    see `_tenant_grants_support_access()` and this module's own docstring.

    Called by `can()` only as the LAST allow path, after both ordinary
    membership-role and delegated authorization have already failed at
    every candidate tenant -- support access is the narrowest, most
    exceptional path, never checked ahead of a tenant's own ordinary
    authorization (module docstring's precedence list, step 4). Explicit
    deny has already been checked, unconditionally, before any allow path
    at all (module docstring's step 0) -- support access adds no deny
    logic of its own, and needs none: it is evaluated under the operator's
    own real `actor_id`, the exact identity `_actor_is_denied()` already
    checked.
    """
    if _tenant_grants_support_access(
        candidate_tenant_id=tenant_id,
        actor_id=actor_id,
        resource=resource,
        allowed_scope_modes=_TARGET_TENANT_SCOPES,
    ):
        return True
    for ancestor_id in get_ancestor_ids(tenant_id):
        if ancestor_id == tenant_id:
            continue
        if _tenant_grants_support_access(
            candidate_tenant_id=ancestor_id,
            actor_id=actor_id,
            resource=resource,
            allowed_scope_modes=_ANCESTOR_TENANT_SCOPES,
        ):
            return True
    return False


def can(
    *,
    actor_id: uuid.UUID,
    tenant_id: uuid.UUID,
    action: str,
    resource: str,
    actor_type: PrincipalType = PrincipalType.USER,
    actor_tenant_id: uuid.UUID | None = None,
) -> bool:
    """Is `actor_id` allowed to perform `action` on `resource` within
    `tenant_id`? Always returns a plain `bool` -- deny is a normal return
    value, never an exception (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3
    section 12: "Never interpret missing RBAC information as permission
    granted").

    `actor_type` defaults to `PrincipalType.USER` -- every pre-Phase-E
    call site is unaffected. `actor_type=PrincipalType.SERVICE_ACCOUNT`
    additionally requires `actor_tenant_id` (the service account's own,
    single, fixed tenant -- module docstring's "Machine principals"
    section); omitting it fails closed rather than guessing. Any other
    `actor_type` also fails closed: no code path in this phase constructs
    a `PrincipalType.SYSTEM` (or other) actor for `can()` to evaluate.

    Full precedence (architecture research Phase F's own approved design):
    1. explicit deny (unconditional, evaluated once, before any allow
       path); 2. ordinary membership-role/service-account-role
       authorization; 3. valid delegation authorization; 4. explicitly
       approved support access (architecture research Phase F -- checked
       last, and only for a `USER` actor); 5. otherwise deny. See the
       module docstring's own step-by-step list and
       `_actor_has_support_access()`'s own docstring.
    """
    try:
        get_tenant(tenant_id)
    except TenantNotFoundError:
        return False

    if actor_type is PrincipalType.USER:
        if get_user(actor_id) is None:
            return False
    elif actor_type is PrincipalType.SERVICE_ACCOUNT:
        if actor_tenant_id is None:
            return False
        service_account = get_service_account(actor_tenant_id, actor_id)
        if service_account is None or service_account.status != ServiceAccountStatus.ACTIVE.value:
            return False
    else:
        return False

    # Explicit deny (architecture research Phase D -- "DENY overrides
    # ALLOW"), checked before any allow path below is even attempted. A
    # match here is a hard override: no code path past this point can
    # still return True once `_actor_is_denied()` returns True (module
    # docstring's step 0).
    if _actor_is_denied(
        actor_id=actor_id,
        actor_type=actor_type,
        tenant_id=tenant_id,
        action=action,
        resource=resource,
    ):
        return False

    # The target tenant itself: either scope authorizes it, via ordinary
    # membership-role/service-account-role authorization OR a valid
    # delegation grant (module docstring) -- checked first since it is
    # the common case (a flat, non-hierarchical tenant, or a direct
    # SELF-scoped assignment) and needs no ancestor lookup at all.
    if _actor_grants_permission(
        candidate_tenant_id=tenant_id,
        actor_id=actor_id,
        actor_type=actor_type,
        action=action,
        resource=resource,
        allowed_scopes=_TARGET_TENANT_SCOPES,
    ):
        return True
    if _tenant_grants_permission_via_delegation(
        candidate_tenant_id=tenant_id,
        actor_id=actor_id,
        actor_type=actor_type,
        action=action,
        resource=resource,
        allowed_scope_modes=_TARGET_TENANT_SCOPES,
    ):
        return True

    # Strict ancestors: only a SUBTREE-scoped assignment or a SUBTREE-mode
    # delegation there reaches down to `tenant_id`. Evaluated against the
    # *current* live ancestor chain (core.tenancy.get_ancestor_ids), never
    # a value cached at assignment/grant time -- if the hierarchy changes,
    # this answer changes with it, with no rewrite of any MembershipRole,
    # ServiceAccountRole, or DelegationGrant row.
    for ancestor_id in get_ancestor_ids(tenant_id):
        if ancestor_id == tenant_id:
            continue
        if _actor_grants_permission(
            candidate_tenant_id=ancestor_id,
            actor_id=actor_id,
            actor_type=actor_type,
            action=action,
            resource=resource,
            allowed_scopes=_ANCESTOR_TENANT_SCOPES,
        ):
            return True
        if _tenant_grants_permission_via_delegation(
            candidate_tenant_id=ancestor_id,
            actor_id=actor_id,
            actor_type=actor_type,
            action=action,
            resource=resource,
            allowed_scope_modes=_ANCESTOR_TENANT_SCOPES,
        ):
            return True

    # Support access (architecture research Phase F -- "Audit + Support
    # Access"): the narrowest, most exceptional allow path, checked LAST
    # -- only once every ordinary and delegated allow has already failed
    # at every candidate tenant (module docstring's precedence list, step
    # 4). Never evaluated for a SERVICE_ACCOUNT actor: a support request's
    # own `requester_user_id` is always a real human `core.identity` user
    # (`core/rbac/models.py::SupportAccessRequest`'s own docstring -- "not
    # a new authentication identity"), so there is no principal for this
    # path to even query when `actor_type` is anything else.
    if actor_type is PrincipalType.USER and _actor_has_support_access(
        actor_id=actor_id, tenant_id=tenant_id, resource=resource
    ):
        return True

    return False
