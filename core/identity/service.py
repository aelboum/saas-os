"""User, external-identity, and tenant-membership operations
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.2).

Users and external identities are global (docs/MULTI-TENANCY.md section 1:
"a user is a global identity ... independent of any tenant") -- CRUD here
uses `infra.db.session_scope()`, never `tenant_session_scope()`, mirroring
`core/tenancy/service.py`'s reasoning for the tenant registry itself: a
user's own identity must be resolvable before any tenant context can be
established.

`TenantMembership` IS tenant-owned data -- linking a user to a tenant is
itself something a tenant's own security boundary must protect
(docs/MULTI-TENANCY.md section 4). `add_tenant_membership` and
`list_tenant_members` take an explicit `tenant_id` and use
`tenant_session_scope()`, so the RLS policy on `core.tenant_memberships`
(applied by this phase's migration via `infra.db.rls.tenant_rls_statements()`)
is the exact same enforcement mechanism protecting every other tenant-owned
table.

Deliberately NOT provided: a "list every tenant this user belongs to"
global query. Unlike `core.users`/`core.external_identities`/`core.sessions`,
`core.tenant_memberships` genuinely IS RLS-protected (this module's own
design choice, matching the security test matrix's requirement that
membership rows are tenant-isolated) -- an untenanted `session_scope()`
query against it returns zero rows *by policy*, not by omission, so there
is no code path in this phase that can honestly answer "which tenants does
this user belong to" without already having a tenant context. Resolving
that for a login/tenant-picker flow is a cross-tenant, platform-level
operation (docs/MULTI-TENANCY.md section 5: "a distinct, explicitly logged
code path") that needs the audit logging Phase 3.4 (`core/audit-log`) adds
-- adding it here, unaudited, would either bypass RLS via the privileged
migrations role (reintroducing the exact superuser/BYPASSRLS escape hatch
Phase 3.1's security correction eliminated) or silently return nothing,
neither of which this module will do quietly. A caller that already has a
tenant context (Phase 8's HTTP layer, once a tenant has been selected) can
always ask "is this user a member of *this* tenant" via `list_tenant_members`.

No role/permission is assigned anywhere in this module -- that is
core/rbac's table to define in Phase 3.3 (docs/ADR/0005-...).
"""

from __future__ import annotations

import uuid

from core.identity.errors import (
    DuplicateExternalIdentityError,
    DuplicateServiceAccountNameError,
    ServiceAccountNotFoundError,
    UserNotFoundError,
)
from core.identity.models import (
    ExternalIdentity,
    ServiceAccount,
    ServiceAccountStatus,
    TenantMembership,
    User,
)
from infra.db import IntegrityError, select, session_scope, tenant_session_scope


def create_user() -> User:
    with session_scope() as session:
        user = User()
        session.add(user)
        session.flush()
        session.refresh(user)
        session.expunge(user)
        return user


def get_user(user_id: uuid.UUID) -> User | None:
    with session_scope() as session:
        user = session.get(User, user_id)
        if user is not None:
            session.expunge(user)
        return user


def _get_user_or_raise(user_id: uuid.UUID) -> User:
    user = get_user(user_id)
    if user is None:
        raise UserNotFoundError(user_id)
    return user


def find_external_identity(issuer: str, subject: str) -> ExternalIdentity | None:
    with session_scope() as session:
        identity = session.execute(
            select(ExternalIdentity).where(
                ExternalIdentity.issuer == issuer, ExternalIdentity.subject == subject
            )
        ).scalar_one_or_none()
        if identity is not None:
            session.expunge(identity)
        return identity


def link_external_identity(user_id: uuid.UUID, issuer: str, subject: str) -> ExternalIdentity:
    """Link (issuer, subject) to `user_id`. The database-level unique
    constraint on (issuer, subject) is the real enforcement mechanism;
    catching `IntegrityError` here is defense in depth for the
    race-condition path -- two concurrent logins racing to create the same
    never-before-seen external identity link (`core/identity/errors.py`'s
    own docstring, docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 security
    review).
    """
    try:
        with session_scope() as session:
            identity = ExternalIdentity(user_id=user_id, issuer=issuer, subject=subject)
            session.add(identity)
            session.flush()
            session.refresh(identity)
            session.expunge(identity)
            return identity
    except IntegrityError as exc:
        raise DuplicateExternalIdentityError(issuer, subject) from exc


def get_or_create_user_for_external_identity(issuer: str, subject: str) -> User:
    """The standard OIDC login resolution: find the platform user already
    linked to (issuer, subject), or provision a new user + link on first
    login.

    Not itself one transaction across `create_user` and
    `link_external_identity` -- a crash between the two leaves an orphaned,
    harmless `User` row with no external identity (a bare `User` row grants
    no access to anything, since every RBAC/tenant check goes through an
    explicit membership or session, never a `User` row's mere existence).
    The *linking* step itself is race-safe via the (issuer, subject) unique
    constraint: if two concurrent first-logins for the same identity race,
    the loser's `link_external_identity` call raises
    `DuplicateExternalIdentityError`, and this function re-resolves to the
    winner's user rather than propagating the error.
    """
    existing = find_external_identity(issuer, subject)
    if existing is not None:
        return _get_user_or_raise(existing.user_id)

    user = create_user()
    try:
        link_external_identity(user.id, issuer, subject)
    except DuplicateExternalIdentityError:
        existing = find_external_identity(issuer, subject)
        if existing is None:
            # The constraint we just lost the race on now shows no owner --
            # only possible if that other login's transaction was rolled
            # back after ours observed the conflict. Re-raising surfaces
            # this as the same duplicate-identity error rather than a
            # misleading "identity not found".
            raise DuplicateExternalIdentityError(issuer, subject) from None
        return _get_user_or_raise(existing.user_id)
    return user


def add_tenant_membership(tenant_id: uuid.UUID, user_id: uuid.UUID) -> TenantMembership:
    with tenant_session_scope(tenant_id) as session:
        membership = TenantMembership(tenant_id=tenant_id, user_id=user_id)
        session.add(membership)
        session.flush()
        session.refresh(membership)
        session.expunge(membership)
        return membership


def get_membership(tenant_id: uuid.UUID, user_id: uuid.UUID) -> TenantMembership | None:
    """Resolve `user_id`'s membership within `tenant_id`, or `None` if the
    user is not a member. This is the published lookup other Core modules
    (`core/rbac`, docs/IMPLEMENTATION-ROADMAP.md Phase 3.3) use instead of
    querying `TenantMembership` directly -- docs/DATA-ARCHITECTURE.md
    section 3: "No module reads another module's tables directly, even for
    read-only purposes."
    """
    with tenant_session_scope(tenant_id) as session:
        membership = session.execute(
            select(TenantMembership).where(
                TenantMembership.tenant_id == tenant_id, TenantMembership.user_id == user_id
            )
        ).scalar_one_or_none()
        if membership is not None:
            session.expunge(membership)
        return membership


def list_tenant_members(tenant_id: uuid.UUID) -> list[TenantMembership]:
    with tenant_session_scope(tenant_id) as session:
        memberships = (
            session.execute(select(TenantMembership).where(TenantMembership.tenant_id == tenant_id))
            .scalars()
            .all()
        )
        for membership in memberships:
            session.expunge(membership)
        return list(memberships)


# --- Service accounts (architecture research: universal multi-tenant
# tenancy, Phase E -- "Principal + Service Accounts + API Key Hardening")
# ---------------------------------------------------------------------


def create_service_account(tenant_id: uuid.UUID, name: str) -> ServiceAccount:
    """Create a tenant-scoped machine identity. `tenant_id` is fixed for
    this row's entire lifetime -- there is no `move_service_account()`,
    unlike `core.tenancy.move_tenant()` (`ServiceAccount`'s own docstring:
    this is what makes "no implicit hierarchy access" a structural
    guarantee, not a convention).

    Deliberately ungated here -- like `add_tenant_membership()` above,
    this function trusts its caller's `tenant_id` argument; authorizing
    *who* may call it is Phase 8's ingress layer's job, mirroring every
    other `core/identity` entity-creation function (this module's own
    docstring). The database-level unique constraint on `(tenant_id,
    name)` is the real duplicate-name guard; catching `IntegrityError`
    here is defense in depth for the race-condition path, mirroring
    `link_external_identity()`.
    """
    try:
        with tenant_session_scope(tenant_id) as session:
            account = ServiceAccount(tenant_id=tenant_id, name=name)
            session.add(account)
            session.flush()
            session.refresh(account)
            session.expunge(account)
            return account
    except IntegrityError as exc:
        raise DuplicateServiceAccountNameError(tenant_id, name) from exc


def get_service_account(
    tenant_id: uuid.UUID, service_account_id: uuid.UUID
) -> ServiceAccount | None:
    """Resolve `service_account_id` within `tenant_id`, or `None` if it
    does not exist there -- the published lookup other Core modules
    (`core/rbac`, `core/api_keys`) use instead of querying `ServiceAccount`
    directly (docs/DATA-ARCHITECTURE.md section 3), mirroring
    `get_membership()`'s own shape exactly. Tenant-scoped (RLS-protected,
    `ServiceAccount`'s own docstring): there is no untenanted "does this
    id exist in any tenant" lookup, by the same structural design
    `core/tenancy`'s tenant registry and `core.tenant_memberships` already
    apply -- a caller must already know which tenant it is asking about.
    """
    with tenant_session_scope(tenant_id) as session:
        account = session.execute(
            select(ServiceAccount).where(
                ServiceAccount.tenant_id == tenant_id, ServiceAccount.id == service_account_id
            )
        ).scalar_one_or_none()
        if account is not None:
            session.expunge(account)
        return account


def list_service_accounts(tenant_id: uuid.UUID) -> list[ServiceAccount]:
    with tenant_session_scope(tenant_id) as session:
        accounts = (
            session.execute(select(ServiceAccount).where(ServiceAccount.tenant_id == tenant_id))
            .scalars()
            .all()
        )
        for account in accounts:
            session.expunge(account)
        return list(accounts)


def _set_service_account_status(
    tenant_id: uuid.UUID, service_account_id: uuid.UUID, status: ServiceAccountStatus
) -> ServiceAccount:
    with tenant_session_scope(tenant_id) as session:
        account = session.execute(
            select(ServiceAccount).where(
                ServiceAccount.tenant_id == tenant_id, ServiceAccount.id == service_account_id
            )
        ).scalar_one_or_none()
        if account is None:
            raise ServiceAccountNotFoundError(tenant_id, service_account_id)
        if account.status != status.value:
            account.status = status.value
            session.flush()
        session.refresh(account)
        session.expunge(account)
        return account


def disable_service_account(tenant_id: uuid.UUID, service_account_id: uuid.UUID) -> ServiceAccount:
    """Disable a service account, immediately -- the very next
    `core/rbac/authorization.py::can()` call or
    `core/api_keys/service.py::validate_api_key()` call re-reads `status`
    live, so there is nothing further to invalidate (no cache). Idempotent:
    disabling an already-disabled account is a no-op, not an error
    (mirrors `core/identity/sessions.py::revoke_session`)."""
    return _set_service_account_status(tenant_id, service_account_id, ServiceAccountStatus.DISABLED)


def enable_service_account(tenant_id: uuid.UUID, service_account_id: uuid.UUID) -> ServiceAccount:
    """Re-enable a disabled service account. Deliberately does NOT
    reactivate any API key that was revoked or has since expired while
    the account was disabled -- `status` only ever gates whether an
    otherwise-valid key/authorization check is honored; it never
    resurrects a key's own independent `revoked_at`/`expires_at` state
    (`core/api_keys/service.py::validate_api_key()`'s own ordering: those
    checks run before, and independently of, the owning service account's
    status). Idempotent, mirroring `disable_service_account()`."""
    return _set_service_account_status(tenant_id, service_account_id, ServiceAccountStatus.ACTIVE)
