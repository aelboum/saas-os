"""Phase I reference-consumer demonstration scenarios (architecture
research: universal multi-tenant tenancy, Phase I -- "Reference Consumer
Extension").

Every function here is ordinary consumer *business logic*, calling only
the installed `saas-os` package's own published API (`core.tenancy`,
`core.rbac`, `core.identity`, `core.api_keys`, `core.billing`,
`core.usage`, `core.audit_log`) -- exactly the same way any other
independent product would. This module never reaches into a SaaS OS
table directly, never re-implements hierarchy/RBAC/delegation/billing
logic, and never bypasses `core.rbac.authorization.can()`. It is
illustrative and non-production: `tests/test_reference_consumer_scenarios_integration.py`
(in the SaaS OS repository itself, not shipped) is what actually asserts
the SaaS-OS-guaranteed behavior these scenarios exercise -- this module
only *sets up and drives* each scenario, mirroring the same
service-layer/test-layer split every `core/*` module in SaaS OS itself
already uses.

Each `demonstrate_*` function returns a small, plain dataclass of the ids
it created, for a caller (a test, or a real product's own code) to act on
further. None of them assert anything themselves -- that is deliberate:
a reference consumer's own code should look like normal product code, not
a test suite in disguise.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from core.api_keys.service import create_service_account_api_key, validate_api_key
from core.billing.provider import BillingProvider, FakeBillingProvider
from core.billing.service import create_plan, resolve_billing_owner, subscribe
from core.identity.service import (
    add_tenant_membership,
    create_invitation,
    create_service_account,
    create_user,
    get_membership,
)
from core.rbac.scope import RoleScope
from core.rbac.service import (
    approve_support_access,
    assign_role,
    assign_service_account_role,
    create_delegation,
    create_deny,
    create_role,
    create_support_access_request,
    grant_permission,
    register_permission,
)

from core.tenancy import create_tenant, set_tenant_billing_inheritance

# The one consumer-owned permission every scenario below grants/checks
# against -- reuses `reference_consumer/tools.py`'s own resource/action
# pair rather than inventing a second one, so a single `core.rbac`
# permission row is shared by every demonstration in this module.
WIDGET_RESOURCE = "reference_consumer.widgets"
WIDGET_ACTION = "read"


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _widget_role(tenant_id: uuid.UUID) -> uuid.UUID:
    """Create a role in `tenant_id` granting the one consumer permission
    every scenario below uses -- idempotent registration, mirroring
    `reference_consumer/tools.py`'s own permission pair."""
    role = create_role(tenant_id, _unique("widget-role"))
    permission = register_permission(WIDGET_RESOURCE, WIDGET_ACTION)
    grant_permission(tenant_id, role.id, permission.id)
    return role.id


# --- 1. B2B hierarchical tenancy --------------------------------------


@dataclass(frozen=True)
class B2BHierarchy:
    business_tenant_id: uuid.UUID
    department_tenant_id: uuid.UUID
    team_tenant_id: uuid.UUID
    business_admin_user_id: uuid.UUID


def provision_b2b_hierarchy() -> B2BHierarchy:
    """A business tenant with one department child and one nested team
    grandchild -- `Tenant.parent_id`/`core.tenant_ancestry` maintained
    entirely by `core.tenancy.create_tenant()`, never duplicated here."""
    business = create_tenant(_unique("business"))
    department = create_tenant(_unique("department"), parent_id=business.id)
    team = create_tenant(_unique("team"), parent_id=department.id)

    admin = create_user()
    add_tenant_membership(business.id, admin.id)

    return B2BHierarchy(
        business_tenant_id=business.id,
        department_tenant_id=department.id,
        team_tenant_id=team.id,
        business_admin_user_id=admin.id,
    )


# --- 2. B2C personal tenancy --------------------------------------------


@dataclass(frozen=True)
class B2CPersonalTenant:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    owner_role_id: uuid.UUID


def provision_personal_tenant_for_new_user() -> B2CPersonalTenant:
    """A new user always receives a personal (root) tenant of their own,
    with an "owner" role granting the one consumer permission -- there is
    no user-without-a-tenant state in this reference flow. Uses only
    `core.identity`/`core.tenancy`/`core.rbac` -- no `Account` table."""
    user = create_user()
    personal_tenant = create_tenant(_unique(f"personal-{user.id.hex[:8]}"))
    membership = add_tenant_membership(personal_tenant.id, user.id)

    owner_role = create_role(personal_tenant.id, "owner")
    permission = register_permission(WIDGET_RESOURCE, WIDGET_ACTION)
    grant_permission(personal_tenant.id, owner_role.id, permission.id)
    assign_role(personal_tenant.id, membership.id, owner_role.id, scope=RoleScope.SELF)

    return B2CPersonalTenant(
        user_id=user.id, tenant_id=personal_tenant.id, owner_role_id=owner_role.id
    )


# --- 3. B2B2C-style customer tenancy/membership -------------------------


@dataclass(frozen=True)
class B2B2CCustomers:
    business_tenant_id: uuid.UUID
    customer_a_tenant_id: uuid.UUID
    customer_b_tenant_id: uuid.UUID
    customer_a_user_id: uuid.UUID
    customer_b_user_id: uuid.UUID
    business_support_user_id: uuid.UUID


def provision_b2b2c_customers() -> B2B2CCustomers:
    """A business tenant with two customer child tenants -- each customer
    is its own `Tenant`/`TenantMembership`, never a second isolation
    abstraction (no `Customer` table). Customer A and Customer B are
    siblings: structurally related (both children of the same business
    tenant) but never implicitly authorized into each other."""
    business = create_tenant(_unique("biz"))
    customer_a = create_tenant(_unique("cust-a"), parent_id=business.id)
    customer_b = create_tenant(_unique("cust-b"), parent_id=business.id)

    customer_a_user = create_user()
    add_tenant_membership(customer_a.id, customer_a_user.id)
    customer_a_role_id = _widget_role(customer_a.id)
    customer_a_membership = get_membership(customer_a.id, customer_a_user.id)
    assert customer_a_membership is not None
    assign_role(customer_a.id, customer_a_membership.id, customer_a_role_id, scope=RoleScope.SELF)

    customer_b_user = create_user()
    add_tenant_membership(customer_b.id, customer_b_user.id)
    customer_b_role_id = _widget_role(customer_b.id)
    customer_b_membership = get_membership(customer_b.id, customer_b_user.id)
    assert customer_b_membership is not None
    assign_role(customer_b.id, customer_b_membership.id, customer_b_role_id, scope=RoleScope.SELF)

    # The business's own support user -- deliberately given NO role at
    # either customer tenant here: business access to customer data must
    # be authorization-driven (a SUBTREE role, or delegation), never
    # implied by the parent-child structure alone.
    business_support_user = create_user()
    add_tenant_membership(business.id, business_support_user.id)

    return B2B2CCustomers(
        business_tenant_id=business.id,
        customer_a_tenant_id=customer_a.id,
        customer_b_tenant_id=customer_b.id,
        customer_a_user_id=customer_a_user.id,
        customer_b_user_id=customer_b_user.id,
        business_support_user_id=business_support_user.id,
    )


def grant_business_subtree_access(business_tenant_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """Give `user_id` a SUBTREE-scoped role at `business_tenant_id` --
    the explicit, authorization-driven way a business gains reach into
    its customer tenants (never automatic from hierarchy alone)."""
    membership = get_membership(business_tenant_id, user_id)
    assert membership is not None
    role_id = _widget_role(business_tenant_id)
    assign_role(business_tenant_id, membership.id, role_id, scope=RoleScope.SUBTREE)


def delegate_customer_access(
    *, delegator_user_id: uuid.UUID, delegate_user_id: uuid.UUID, customer_tenant_id: uuid.UUID
) -> uuid.UUID:
    """An explicit, scoped delegation from a customer's own admin to
    (for example) a business support user -- the OTHER authorization-
    driven way to reach a specific customer tenant without a structural
    SUBTREE grant at the business level. Returns the new
    `DelegationGrant.id`.

    `delegator_user_id` must already hold BOTH the ordinary
    `(WIDGET_RESOURCE, WIDGET_ACTION)` authority being delegated (anti-
    amplification -- `create_delegation()`'s own docstring) and the
    dedicated `(resource="delegation_grant", action="create")`
    capability; this function grants the latter here, mirroring how a
    real product would provision its first tenant admin."""
    delegator_membership = get_membership(customer_tenant_id, delegator_user_id)
    assert delegator_membership is not None
    delegation_admin_role = create_role(customer_tenant_id, _unique("delegation-admin"))
    delegation_permission = register_permission("delegation_grant", "create")
    grant_permission(customer_tenant_id, delegation_admin_role.id, delegation_permission.id)
    assign_role(
        customer_tenant_id,
        delegator_membership.id,
        delegation_admin_role.id,
        scope=RoleScope.SELF,
    )

    permission = register_permission(WIDGET_RESOURCE, WIDGET_ACTION)
    grant = create_delegation(
        delegator_user_id=delegator_user_id,
        delegate_user_id=delegate_user_id,
        tenant_id=customer_tenant_id,
        scope_mode=RoleScope.SELF,
        permission_id=permission.id,
    )
    return grant.id


# --- Explicit deny -------------------------------------------------------


def deny_widget_access(
    *, grantor_user_id: uuid.UUID, principal_user_id: uuid.UUID, tenant_id: uuid.UUID
) -> uuid.UUID:
    """Explicitly deny `principal_user_id` the one consumer permission at
    `tenant_id` -- overrides any allow, including an inherited SUBTREE
    role or an active delegation (`core.rbac.authorization.can()`'s own
    step 0). `grantor_user_id` must hold the dedicated
    `(resource="deny_grant", action="create")` capability; this function
    grants it here."""
    grantor_membership = get_membership(tenant_id, grantor_user_id)
    assert grantor_membership is not None
    deny_admin_role = create_role(tenant_id, _unique("deny-admin"))
    deny_permission = register_permission("deny_grant", "create")
    grant_permission(tenant_id, deny_admin_role.id, deny_permission.id)
    assign_role(tenant_id, grantor_membership.id, deny_admin_role.id, scope=RoleScope.SELF)

    permission = register_permission(WIDGET_RESOURCE, WIDGET_ACTION)
    deny = create_deny(
        grantor_user_id=grantor_user_id,
        principal_user_id=principal_user_id,
        tenant_id=tenant_id,
        scope_mode=RoleScope.SELF,
        permission_id=permission.id,
    )
    return deny.id


# --- 7. Service accounts + 8. API-key hardening -------------------------


@dataclass(frozen=True)
class ServiceAccountWithKey:
    service_account_id: uuid.UUID
    api_key_id: uuid.UUID
    raw_api_key: str


def provision_service_account_with_key(
    *, tenant_id: uuid.UUID, actor_user_id: uuid.UUID, expires_at: datetime | None = None
) -> ServiceAccountWithKey:
    """A tenant-bound machine identity for the consumer's own background
    job/integration use case, with a hardened, hashed-at-rest API key --
    `core/api_keys`/`core/identity` own every guarantee here (secret
    hashing, expiry, revocation, tenant binding); this function only
    composes them.

    `actor_user_id` must already hold: the ordinary widget permission
    being granted to the service account (anti-amplification --
    `assign_service_account_role()`'s own docstring), the dedicated
    `(resource="service_account_role", action="create")` capability, and
    the dedicated `(resource="api_key", action="create")` capability.
    This function grants all three here, mirroring how a real product
    would provision its first tenant admin."""
    actor_membership = get_membership(tenant_id, actor_user_id)
    assert actor_membership is not None
    admin_role = create_role(tenant_id, _unique("svc-admin"))
    for resource, action in (
        (WIDGET_RESOURCE, WIDGET_ACTION),
        ("service_account_role", "create"),
        ("api_key", "create"),
    ):
        permission = register_permission(resource, action)
        grant_permission(tenant_id, admin_role.id, permission.id)
    assign_role(tenant_id, actor_membership.id, admin_role.id, scope=RoleScope.SELF)

    account = create_service_account(tenant_id, _unique("svc"))
    role_id = _widget_role(tenant_id)
    assign_service_account_role(
        actor_user_id=actor_user_id,
        tenant_id=tenant_id,
        service_account_id=account.id,
        role_id=role_id,
        scope=RoleScope.SELF,
    )
    key, raw_key = create_service_account_api_key(
        actor_user_id=actor_user_id,
        tenant_id=tenant_id,
        service_account_id=account.id,
        name=_unique("integration-key"),
        expires_at=expires_at,
    )
    return ServiceAccountWithKey(
        service_account_id=account.id, api_key_id=key.id, raw_api_key=raw_key
    )


def authenticate_with_api_key(raw_key: str):
    """Resolve a raw API key exactly the way the consumer's own ingress
    layer would -- `validate_api_key()` is the complete authentication
    step; authorization for whatever the caller then does remains a
    separate, explicit `core.rbac.can()` call (never implied by a
    successful key lookup)."""
    return validate_api_key(raw_key)


# --- 10. Membership lifecycle + 11. Invitations --------------------------


@dataclass(frozen=True)
class InvitationFlow:
    tenant_id: uuid.UUID
    inviter_user_id: uuid.UUID
    invitation_id: uuid.UUID
    raw_token: str


def invite_team_member(*, tenant_id: uuid.UUID, invited_email: str) -> InvitationFlow:
    """Invite a new team member into an existing tenant -- the inviter
    must already hold the dedicated `(resource="invitation",
    action="create")` capability (`core.identity.service.create_invitation()`'s
    own gate, via `can()`); this function grants that capability to a
    fresh inviter user first, mirroring how a real product would
    provision its first tenant admin."""
    inviter = create_user()
    inviter_membership = add_tenant_membership(tenant_id, inviter.id)
    role = create_role(tenant_id, _unique("invite-admin"))
    for action in ("create", "revoke"):
        permission = register_permission("invitation", action)
        grant_permission(tenant_id, role.id, permission.id)
    assign_role(tenant_id, inviter_membership.id, role.id, scope=RoleScope.SELF)

    invitation, raw_token = create_invitation(tenant_id, inviter.id, invited_email)
    return InvitationFlow(
        tenant_id=tenant_id,
        inviter_user_id=inviter.id,
        invitation_id=invitation.id,
        raw_token=raw_token,
    )


# --- 12/13. Hierarchy-aware billing & usage ------------------------------


@dataclass(frozen=True)
class BillingSetup:
    parent_tenant_id: uuid.UUID
    child_tenant_id: uuid.UUID
    plan_key: str
    provider: BillingProvider


def provision_hierarchy_aware_billing() -> BillingSetup:
    """A parent tenant that owns its own billing, and a child tenant that
    explicitly opts into inheriting it (`inherits_billing=True`, never
    inferred from `parent_id` alone) -- `core.billing.service
    .resolve_billing_owner()` is the one function that ever resolves
    which tenant's `Subscription` applies; this module never re-derives
    that logic."""
    parent = create_tenant(_unique("billing-parent"))
    child = create_tenant(_unique("billing-child"), parent_id=parent.id)
    set_tenant_billing_inheritance(child.id, True)

    plan_key = _unique("plan")
    create_plan(plan_key, "Reference Plan", entitlements={"widgets": 10})
    provider = FakeBillingProvider()
    subscribe(parent.id, plan_key, provider=provider)

    return BillingSetup(
        parent_tenant_id=parent.id, child_tenant_id=child.id, plan_key=plan_key, provider=provider
    )


def resolve_effective_billing_owner(tenant_id: uuid.UUID) -> uuid.UUID:
    return resolve_billing_owner(tenant_id)


# --- 9. Support access ----------------------------------------------------


@dataclass(frozen=True)
class SupportAccessFlow:
    tenant_id: uuid.UUID
    support_engineer_user_id: uuid.UUID
    approver_user_id: uuid.UUID
    request_id: uuid.UUID


def request_and_approve_support_access(*, tenant_id: uuid.UUID) -> SupportAccessFlow:
    """A platform support engineer's own explicit request for time-
    bounded access to `tenant_id`, approved by a tenant admin -- never
    impersonation: `approve_support_access()` never changes who the
    engineer is, and `core.rbac.authorization.can()` always evaluates the
    engineer's own real identity, so the pre-existing explicit-deny check
    already covers a support-authorized action with no special-casing
    (`core/rbac/authorization.py::can()`'s own docstring)."""
    engineer = create_user()

    approver = create_user()
    approver_membership = add_tenant_membership(tenant_id, approver.id)
    approver_role = create_role(tenant_id, _unique("support-admin"))
    for action in ("approve", "deny", "revoke"):
        permission = register_permission("support_access_request", action)
        grant_permission(tenant_id, approver_role.id, permission.id)
    assign_role(tenant_id, approver_membership.id, approver_role.id, scope=RoleScope.SELF)

    now = datetime.now(UTC)
    request = create_support_access_request(
        requester_user_id=engineer.id,
        tenant_id=tenant_id,
        reason="Reference consumer Phase I demonstration",
        requested_starts_at=now,
        requested_expires_at=now + timedelta(hours=1),
    )
    approve_support_access(approver_user_id=approver.id, tenant_id=tenant_id, request_id=request.id)

    return SupportAccessFlow(
        tenant_id=tenant_id,
        support_engineer_user_id=engineer.id,
        approver_user_id=approver.id,
        request_id=request.id,
    )
