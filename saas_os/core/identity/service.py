"""User, external-identity, and tenant-membership operations
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.2).

Users and external identities are global (docs/MULTI-TENANCY.md section 1:
"a user is a global identity ... independent of any tenant") -- CRUD here
uses `saas_os.infra.db.session_scope()`, never `tenant_session_scope()`, mirroring
`saas_os/core/tenancy/service.py`'s reasoning for the tenant registry itself: a
user's own identity must be resolvable before any tenant context can be
established.

`TenantMembership` IS tenant-owned data -- linking a user to a tenant is
itself something a tenant's own security boundary must protect
(docs/MULTI-TENANCY.md section 4). `add_tenant_membership` and
`list_tenant_members` take an explicit `tenant_id` and use
`tenant_session_scope()`, so the RLS policy on `core.tenant_memberships`
(applied by this phase's migration via `saas_os.infra.db.rls.tenant_rls_statements()`)
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
saas_os/core/rbac's table to define in Phase 3.3 (docs/ADR/0005-...).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from saas_os.core.audit_log import (
    record_in_transaction,
    referenced_service_account_ids,
)
from saas_os.core.authority import Caller, SystemAuthority, UserCaller, require_caller
from saas_os.core.identity.errors import (
    DuplicateExternalIdentityError,
    DuplicateInvitationError,
    DuplicateServiceAccountNameError,
    InvalidExternalIdentityError,
    InvalidInvitationEmailError,
    InvalidMembershipTransitionError,
    InvalidServiceAccountNameError,
    InvitationAlreadyAcceptedError,
    InvitationInvalidError,
    InvitationNotAuthorizedError,
    InvitationNotFoundError,
    MembershipNotFoundError,
    ServiceAccountNotFoundError,
    UserNotFoundError,
)
from saas_os.core.identity.models import (
    ExternalIdentity,
    Invitation,
    MembershipStatus,
    ServiceAccount,
    ServiceAccountStatus,
    TenantMembership,
    User,
)
from saas_os.core.tenancy import (
    TenantInaccessibleError,
    TenantNotFoundError,
    lock_accessible_tenant,
    require_open_tenant,
    require_purging_tenant,
)
from saas_os.infra.db import (
    IntegrityError,
    Session,
    bind_tenant_scope,
    select,
    session_scope,
    tenant_session_scope,
)

# 256 bits of entropy -- the same standard, non-guessable bearer-secret
# size `saas_os/core/identity/sessions.py`/`saas_os/core/api_keys/service.py` use.
_INVITATION_TOKEN_BYTES = 32
_DEFAULT_INVITATION_LIFETIME = timedelta(days=7)
_MAX_INVITATION_LIFETIME = timedelta(days=30)
_MAX_INVITED_EMAIL_LENGTH = 320
# An issuer, subject or service-account name with a control character is
# refused as invalid input: PostgreSQL cannot store or compare a NUL in
# `text`, and would otherwise refuse it as a raw `DataError` (2026-10-29
# NUL sweep).
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


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


# --- In-transaction principal locks (Foundation Authority & Evidence,
# ADR-0031) -------------------------------------------------------------
#
# `saas_os.core.rbac.can()` evaluates a protected mutation's authorization inside
# that mutation's own transaction. These are the published reads it uses
# for this module's rows: each reads the authoritative row in the caller's
# session and holds it `FOR SHARE` until that transaction ends, so a
# concurrent deactivation, suspension, revocation or disable (an `UPDATE`
# of that row) either committed first and is seen, or waits until the
# authorized mutation has committed. Column-only selects: nothing is added
# to the caller's identity map.
#
# `exclusive=True` takes `FOR NO KEY UPDATE` instead -- the lock an
# authority-*removing* write that does not itself update the row (creating
# a `DenyGrant` against this principal) takes, so it serializes with every
# in-flight decision that relied on the principal's absence of a deny.


@dataclass(frozen=True, slots=True)
class LockedMembership:
    id: uuid.UUID
    status: str


def lock_user_is_active(
    session: Session, user_id: uuid.UUID, *, exclusive: bool = False
) -> bool | None:
    """`User.is_active` for `user_id` (`None` if no such user), with the
    `core.users` row locked in `session`'s transaction. `core.users` is not
    RLS-scoped."""
    return session.execute(
        select(User.is_active)
        .where(User.id == user_id)
        .with_for_update(read=not exclusive, key_share=exclusive)
    ).scalar_one_or_none()


def lock_membership(
    session: Session, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> LockedMembership | None:
    """`user_id`'s membership in `tenant_id` (`None` if not a member),
    with the row locked `FOR SHARE` in `session`'s transaction -- read under
    `tenant_id`'s RLS scope, restored afterward."""
    with bind_tenant_scope(session, tenant_id):
        row = session.execute(
            select(TenantMembership.id, TenantMembership.status)
            .where(TenantMembership.tenant_id == tenant_id, TenantMembership.user_id == user_id)
            .with_for_update(read=True)
        ).one_or_none()
    return None if row is None else LockedMembership(id=row.id, status=row.status)


def lock_service_account_status(
    session: Session,
    tenant_id: uuid.UUID,
    service_account_id: uuid.UUID,
    *,
    exclusive: bool = False,
) -> str | None:
    """The service account's `status` (`None` if it does not exist in
    `tenant_id`), with the row locked in `session`'s transaction -- read
    under `tenant_id`'s RLS scope, restored afterward."""
    with bind_tenant_scope(session, tenant_id):
        return session.execute(
            select(ServiceAccount.status)
            .where(ServiceAccount.tenant_id == tenant_id, ServiceAccount.id == service_account_id)
            .with_for_update(read=not exclusive, key_share=exclusive)
        ).scalar_one_or_none()


def _get_user_or_raise(user_id: uuid.UUID) -> User:
    user = get_user(user_id)
    if user is None:
        raise UserNotFoundError(user_id)
    return user


def _validate_external_identity(issuer: str, subject: str) -> None:
    if _CONTROL_CHARACTERS.search(issuer) or _CONTROL_CHARACTERS.search(subject):
        raise InvalidExternalIdentityError("must not contain control characters")


def find_external_identity(issuer: str, subject: str) -> ExternalIdentity | None:
    _validate_external_identity(issuer, subject)
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
    never-before-seen external identity link (`saas_os/core/identity/errors.py`'s
    own docstring, docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 security
    review).
    """
    _validate_external_identity(issuer, subject)
    try:
        with session_scope() as session:
            identity = ExternalIdentity(user_id=user_id, issuer=issuer, subject=subject)
            session.add(identity)
            session.flush()
            session.refresh(identity)
            session.expunge(identity)
            return identity
    except IntegrityError:
        pass
    # Raised outside the handler: the database error's `DETAIL` repeats the
    # issuer and subject (`core.external_identities` has no row security to
    # hide it), and an error raised in the handler would keep it as its
    # `__cause__` or `__context__`.
    raise DuplicateExternalIdentityError(issuer, subject)


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
        pass
    else:
        return user
    existing = find_external_identity(issuer, subject)
    if existing is None:
        # The constraint we just lost the race on now shows no owner --
        # only possible if that other login's transaction was rolled
        # back after ours observed the conflict. Re-raising surfaces
        # this as the same duplicate-identity error rather than a
        # misleading "identity not found".
        raise DuplicateExternalIdentityError(issuer, subject)
    return _get_user_or_raise(existing.user_id)


def lock_external_identity_exists(session: Session, user_id: uuid.UUID) -> bool:
    """Is `user_id` linked to at least one external identity -- can anyone
    log in as this user? For the enrollment of a platform operator
    (ADR-0045 section 6). Serialization with identity erasure comes from
    the platform-owners lock both take first; the link row is also held
    `FOR SHARE` until the transaction ends, so that nothing deletes it
    while the enrollment is being decided. `core.external_identities` is
    global: `session` needs no tenant scope."""
    return (
        session.execute(
            select(ExternalIdentity.id)
            .where(ExternalIdentity.user_id == user_id)
            .limit(1)
            .with_for_update(read=True)
        ).first()
        is not None
    )


def find_user_id_for_external_identity_in_transaction(
    session: Session, issuer: str, subject: str
) -> uuid.UUID | None:
    """The user already linked to `(issuer, subject)`, or `None`, read in
    the caller's own transaction. Never creates anything. Both tables are
    global: `session` needs no tenant scope."""
    return session.execute(
        select(ExternalIdentity.user_id).where(
            ExternalIdentity.issuer == issuer, ExternalIdentity.subject == subject
        )
    ).scalar_one_or_none()


def get_or_create_user_id_for_external_identity_in_transaction(
    session: Session, issuer: str, subject: str
) -> uuid.UUID:
    """`get_or_create_user_for_external_identity()`, inside the caller's
    own transaction: the user row and its identity link are added to
    `session` and are never committed here, so they commit or roll back
    with whatever else that transaction does.

    For an operation that must not leave an identity behind when it is
    refused or fails (ADR-0045: platform owner bootstrap and recovery). The
    standalone function commits a user in one transaction and its link in
    another, before its caller has decided anything.

    Race-safe through the same `(issuer, subject)` unique constraint: the
    insert runs in a savepoint, and if a concurrent first login linked the
    identity first, the savepoint is rolled back (removing the user row
    just added) and that login's user is returned.
    """
    existing = find_user_id_for_external_identity_in_transaction(session, issuer, subject)
    if existing is not None:
        return existing
    try:
        with session.begin_nested():
            user = User()
            session.add(user)
            session.flush()
            session.add(ExternalIdentity(user_id=user.id, issuer=issuer, subject=subject))
            session.flush()
            return user.id
    except IntegrityError:
        pass
    # Outside the handler, as in `link_external_identity()`.
    existing = find_user_id_for_external_identity_in_transaction(session, issuer, subject)
    if existing is None:
        raise DuplicateExternalIdentityError(issuer, subject)
    return existing


def add_tenant_membership(
    tenant_id: uuid.UUID, user_id: uuid.UUID, *, caller: Caller
) -> TenantMembership:
    """Add `user_id` to `tenant_id` directly (the invitation flow is the
    self-service path). Authority (ADR-0031): `caller` must hold
    `(membership, create)` at `tenant_id`, or be a provisioning
    `SystemCaller`. Audited as `membership.create` in the same transaction
    as the insert."""
    from saas_os.core.rbac.service import authorize_caller

    require_caller("add_tenant_membership", caller)
    require_open_tenant(tenant_id)
    with tenant_session_scope(tenant_id) as session:
        authorize_caller(
            caller,
            session=session,
            operation="add_tenant_membership",
            tenant_id=tenant_id,
            resource="membership",
            action="create",
            system_authorities=frozenset({SystemAuthority.PROVISIONING}),
        )
        membership = TenantMembership(tenant_id=tenant_id, user_id=user_id)
        session.add(membership)
        session.flush()
        record_in_transaction(
            session,
            caller=caller,
            tenant_id=tenant_id,
            action="membership.create",
            resource_type="tenant_membership",
            resource_id=str(membership.id),
            metadata={"user_id": str(user_id)},
        )
        session.refresh(membership)
        session.expunge(membership)
        return membership


def get_membership(tenant_id: uuid.UUID, user_id: uuid.UUID) -> TenantMembership | None:
    """Resolve `user_id`'s membership within `tenant_id`, or `None` if the
    user is not a member. This is the published lookup other Core modules
    (`saas_os/core/rbac`, docs/IMPLEMENTATION-ROADMAP.md Phase 3.3) use instead of
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


def _check_page(limit: int | None, offset: int) -> None:
    if limit is not None and (not isinstance(limit, int) or limit < 0):
        raise ValueError("limit must be a non-negative integer or None.")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative integer.")


def list_tenant_members(
    tenant_id: uuid.UUID, *, limit: int | None = None, offset: int = 0
) -> list[TenantMembership]:
    """The tenant's memberships, oldest first (`created_at`, then `id`).
    `limit`/`offset` page in the database; without `limit`, all of them."""
    _check_page(limit, offset)
    statement = (
        select(TenantMembership)
        .where(TenantMembership.tenant_id == tenant_id)
        .order_by(TenantMembership.created_at, TenantMembership.id)
        .offset(offset)
    )
    if limit is not None:
        statement = statement.limit(limit)
    with tenant_session_scope(tenant_id) as session:
        memberships = session.execute(statement).scalars().all()
        for membership in memberships:
            session.expunge(membership)
        return list(memberships)


# --- Service accounts (architecture research: universal multi-tenant
# tenancy, Phase E -- "Principal + Service Accounts + API Key Hardening")
# ---------------------------------------------------------------------


def create_service_account(tenant_id: uuid.UUID, name: str, *, caller: Caller) -> ServiceAccount:
    """Create a tenant-scoped machine identity. `tenant_id` is fixed for
    this row's entire lifetime -- there is no `move_service_account()`,
    unlike `saas_os.core.tenancy.move_tenant()` (`ServiceAccount`'s own docstring:
    this is what makes "no implicit hierarchy access" a structural
    guarantee, not a convention).

    Who may call it is decided by its explicit typed caller (ADR-0031,
    below). The database-level unique constraint on `(tenant_id,
    name)` is the real duplicate-name guard; catching `IntegrityError`
    here is defense in depth for the race-condition path, mirroring
    `link_external_identity()`.

    RA-12-8: a service account is a machine *principal* -- the same
    RA-04 policy that keeps a human membership from authorizing anything
    while its tenant is `SUSPENDED` (not merely closed) must keep a new
    one from being created then either. `require_open_tenant()` alone
    admits `SUSPENDED`; `lock_accessible_tenant()` is called here, inside
    this same insert transaction (the identical primitive and pattern
    `accept_invitation()`'s own `_consume_locked_invitation()` already
    uses), so the wider check is race-safe -- a closure committing
    between the two calls cannot create a window a plain pre-check would
    leave open.

    Authority (ADR-0031): `caller` must hold `(service_account, create)` at
    `tenant_id`, or be a provisioning `SystemCaller` -- no longer "trusts
    its caller". Audited as `service_account.create` in the same
    transaction as the insert.
    """
    from saas_os.core.rbac.service import authorize_caller

    require_caller("create_service_account", caller)
    if _CONTROL_CHARACTERS.search(name):
        raise InvalidServiceAccountNameError("must not contain control characters")
    require_open_tenant(tenant_id)
    try:
        with tenant_session_scope(tenant_id) as session:
            authorize_caller(
                caller,
                session=session,
                operation="create_service_account",
                tenant_id=tenant_id,
                resource="service_account",
                action="create",
                system_authorities=frozenset({SystemAuthority.PROVISIONING}),
            )
            lock_accessible_tenant(session, tenant_id)
            account = ServiceAccount(tenant_id=tenant_id, name=name)
            session.add(account)
            session.flush()
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action="service_account.create",
                resource_type="service_account",
                resource_id=str(account.id),
                metadata={"name": name},
            )
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
    (`saas_os/core/rbac`, `saas_os/core/api_keys`) use instead of querying `ServiceAccount`
    directly (docs/DATA-ARCHITECTURE.md section 3), mirroring
    `get_membership()`'s own shape exactly. Tenant-scoped (RLS-protected,
    `ServiceAccount`'s own docstring): there is no untenanted "does this
    id exist in any tenant" lookup, by the same structural design
    `saas_os/core/tenancy`'s tenant registry and `core.tenant_memberships` already
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
    tenant_id: uuid.UUID,
    service_account_id: uuid.UUID,
    status: ServiceAccountStatus,
    *,
    caller: Caller,
    audit_action: str,
    authorize: Callable[[Session], None],
) -> ServiceAccount:
    """`authorize` is the operation's own capability check, run first in
    this transaction so the decision and the status write commit together
    (ADR-0031)."""
    with tenant_session_scope(tenant_id) as session:
        authorize(session)
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
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action=audit_action,
                resource_type="service_account",
                resource_id=str(service_account_id),
            )
        session.refresh(account)
        session.expunge(account)
        return account


def disable_service_account(
    tenant_id: uuid.UUID, service_account_id: uuid.UUID, *, caller: Caller
) -> ServiceAccount:
    """Disable a service account, immediately -- the very next
    `saas_os/core/rbac/authorization.py::can()` call or
    `saas_os/core/api_keys/service.py::validate_api_key()` call re-reads `status`
    live, so there is nothing further to invalidate (no cache). Idempotent:
    disabling an already-disabled account is a no-op, not an error
    (mirrors `saas_os/core/identity/sessions.py::revoke_session`).

    Authority (ADR-0031): `caller` must hold `(service_account, disable)`
    at `tenant_id`. Audited as `service_account.disable` in the same
    transaction, only when the status actually changes."""
    from saas_os.core.rbac.service import authorize_caller

    return _set_service_account_status(
        tenant_id,
        service_account_id,
        ServiceAccountStatus.DISABLED,
        caller=caller,
        audit_action="service_account.disable",
        authorize=lambda session: authorize_caller(
            caller,
            session=session,
            operation="disable_service_account",
            tenant_id=tenant_id,
            resource="service_account",
            action="disable",
        ),
    )


def enable_service_account(
    tenant_id: uuid.UUID, service_account_id: uuid.UUID, *, caller: Caller
) -> ServiceAccount:
    """Re-enable a disabled service account. Deliberately does NOT
    reactivate any API key that was revoked or has since expired while
    the account was disabled -- `status` only ever gates whether an
    otherwise-valid key/authorization check is honored; it never
    resurrects a key's own independent `revoked_at`/`expires_at` state
    (`saas_os/core/api_keys/service.py::validate_api_key()`'s own ordering: those
    checks run before, and independently of, the owning service account's
    status). Idempotent, mirroring `disable_service_account()`.

    Lifecycle-fenced (PRIV-03 P2): re-enabling is authority-*expanding*,
    so a closed tenant rejects it; `disable_service_account()` is not
    fenced, so a closed tenant can still be wound down.

    Authority (ADR-0031): `caller` must hold `(service_account, enable)` at
    `tenant_id`. Audited as `service_account.enable` in the same
    transaction, only when the status actually changes."""
    from saas_os.core.rbac.service import authorize_caller

    require_caller("enable_service_account", caller)
    require_open_tenant(tenant_id)
    return _set_service_account_status(
        tenant_id,
        service_account_id,
        ServiceAccountStatus.ACTIVE,
        caller=caller,
        audit_action="service_account.enable",
        authorize=lambda session: authorize_caller(
            caller,
            session=session,
            operation="enable_service_account",
            tenant_id=tenant_id,
            resource="service_account",
            action="enable",
        ),
    )


# --- Membership lifecycle (architecture research: universal multi-tenant
# tenancy, Phase G -- "Invitation / Membership Lifecycle") -----------------


def _transition_membership_status(
    tenant_id: uuid.UUID,
    membership_id: uuid.UUID,
    *,
    allowed_from: frozenset[str],
    to_status: MembershipStatus,
    idempotent_from: frozenset[str],
    caller: Caller,
    audit_action: str,
) -> TenantMembership:
    """Shared transition machinery for `suspend_membership()`/
    `reactivate_membership()`/`revoke_membership()` -- mirrors
    `_set_service_account_status()`'s shape, extended with explicit
    from-state validation (architecture research Phase G: "prefer
    fail-closed behavior where the correct semantics are ambiguous" --
    an out-of-band transition, e.g. reactivating a `REVOKED` membership,
    raises rather than silently applying).

    Authority (ADR-0031): `caller` must hold `(membership, <action>)` at
    `tenant_id` -- `<action>` being the transition's own verb
    (`suspend`/`reactivate`/`revoke`) -- checked before the row is read, in
    the same transaction as the transition and its audit entry.
    """
    from saas_os.core.rbac.administrators import (
        guard_last_administrator,
        lock_tenant_administrators,
    )
    from saas_os.core.rbac.service import authorize_caller

    verb = audit_action.removeprefix("membership.")
    with tenant_session_scope(tenant_id) as session:
        # ADR-0043 (`saas_os/core/rbac/administrators.py`): the tenant's
        # administrator lock, taken before authorization.
        lock_tenant_administrators(session, tenant_id)
        authorize_caller(
            caller,
            session=session,
            operation=f"{verb}_membership",
            tenant_id=tenant_id,
            resource="membership",
            action=verb,
        )
        membership = session.execute(
            select(TenantMembership).where(
                TenantMembership.tenant_id == tenant_id, TenantMembership.id == membership_id
            )
        ).scalar_one_or_none()
        if membership is None:
            raise MembershipNotFoundError(tenant_id, membership_id)
        current_status = membership.status
        if current_status in idempotent_from:
            session.expunge(membership)
            return membership
        if current_status not in allowed_from:
            raise InvalidMembershipTransitionError(membership_id, current_status, to_status.value)
        removing = to_status is not MembershipStatus.ACTIVE
        guard = (
            guard_last_administrator(session, tenant_id, affected_users=[membership.user_id])
            if removing
            else None
        )
        membership.status = to_status.value
        session.flush()
        if guard is not None:
            guard.verify(session, membership_id=membership_id)
        record_in_transaction(
            session,
            caller=caller,
            tenant_id=tenant_id,
            action=audit_action,
            resource_type="tenant_membership",
            resource_id=str(membership_id),
        )
        session.refresh(membership)
        session.expunge(membership)

    return membership


def suspend_membership(
    tenant_id: uuid.UUID, membership_id: uuid.UUID, *, caller: Caller
) -> TenantMembership:
    """Suspend an ACTIVE membership -- the very next `saas_os/core/rbac/authorization.py
    ::can()` call re-reads `status` live, so there is nothing further to
    invalidate (no cache, mirrors `disable_service_account()`). Idempotent
    if already `SUSPENDED`. Raises `InvalidMembershipTransitionError` if
    already `REVOKED` -- a `REVOKED` membership is terminal."""
    require_caller("suspend_membership", caller)
    return _transition_membership_status(
        tenant_id,
        membership_id,
        allowed_from=frozenset({MembershipStatus.ACTIVE.value}),
        to_status=MembershipStatus.SUSPENDED,
        idempotent_from=frozenset({MembershipStatus.SUSPENDED.value}),
        caller=caller,
        audit_action="membership.suspend",
    )


def reactivate_membership(
    tenant_id: uuid.UUID, membership_id: uuid.UUID, *, caller: Caller
) -> TenantMembership:
    """Reactivate a `SUSPENDED` membership back to `ACTIVE`. Deliberately
    does NOT accept a `REVOKED` starting state (architecture research
    Phase G: "do not silently reactivate a revoked membership unless the
    architecture explicitly requires it" -- it does not) -- raises
    `InvalidMembershipTransitionError` instead. Idempotent if already
    `ACTIVE`.

    Lifecycle-fenced (PRIV-03 P2): reactivation is authority-*expanding*,
    so a closed tenant rejects it; `suspend_membership()`/
    `revoke_membership()` are not fenced."""
    require_caller("reactivate_membership", caller)
    require_open_tenant(tenant_id)
    return _transition_membership_status(
        tenant_id,
        membership_id,
        allowed_from=frozenset({MembershipStatus.SUSPENDED.value}),
        to_status=MembershipStatus.ACTIVE,
        idempotent_from=frozenset({MembershipStatus.ACTIVE.value}),
        caller=caller,
        audit_action="membership.reactivate",
    )


def revoke_membership(
    tenant_id: uuid.UUID, membership_id: uuid.UUID, *, caller: Caller
) -> TenantMembership:
    """Revoke a membership -- terminal (mirrors `MembershipStatus.REVOKED`'s
    own docstring: no function in this phase transitions a `REVOKED`
    membership back to any other status). Idempotent if already `REVOKED`.
    Allowed from either non-terminal starting state (`ACTIVE`, `SUSPENDED`)."""
    require_caller("revoke_membership", caller)
    return _transition_membership_status(
        tenant_id,
        membership_id,
        allowed_from=frozenset(
            {
                MembershipStatus.ACTIVE.value,
                MembershipStatus.SUSPENDED.value,
            }
        ),
        to_status=MembershipStatus.REVOKED,
        idempotent_from=frozenset({MembershipStatus.REVOKED.value}),
        caller=caller,
        audit_action="membership.revoke",
    )


# --- Invitations (architecture research: universal multi-tenant tenancy,
# Phase G -- "Invitation / Membership Lifecycle") ---------------------------


def _hash_invitation_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _normalize_email(invited_email: str) -> str:
    """Case-insensitive-domain-and-local-part normalization, matching this
    codebase's only existing convention for a bearer-secret-adjacent
    lookup key (`saas_os/core/identity/models.py::ExternalIdentity`'s own
    `(issuer, subject)` pair is compared byte-for-byte, no normalization
    -- OIDC's own standard). No canonical "email normalization" rule
    exists elsewhere in this codebase to integrate with (`core.users`
    stores no email at all -- this module's own docstring); the safe,
    minimal choice is a plain case-fold plus whitespace trim, applied
    consistently at every read and write site so the same address always
    resolves to the same stored value, deliberately NOT attempting
    provider-specific rules (e.g. Gmail's dot-insensitivity) that would
    require external identity-provider integration this phase does not
    add."""
    normalized = invited_email.strip().casefold()
    # A control character (the API's own `PRINTABLE` rule) or a lone
    # surrogate is refused here, as invalid input: otherwise PostgreSQL or
    # the UTF-8 encoder refuses it later as a `DataError` or a
    # `UnicodeEncodeError` (2026-10-28 database error-text audit).
    if any(ord(c) < 0x20 or ord(c) == 0x7F or 0xD800 <= ord(c) <= 0xDFFF for c in normalized):
        raise InvalidInvitationEmailError("not a valid email address")
    if not normalized or "@" not in normalized or normalized.startswith("@"):
        # Never the value itself: see `DuplicateInvitationError`.
        raise InvalidInvitationEmailError("not a valid email address")
    if len(normalized) > _MAX_INVITED_EMAIL_LENGTH:
        raise InvalidInvitationEmailError(f"exceeds {_MAX_INVITED_EMAIL_LENGTH} characters.")
    return normalized


def create_invitation(
    tenant_id: uuid.UUID,
    invited_email: str,
    *,
    caller: UserCaller,
    expires_at: datetime | None = None,
) -> tuple[Invitation, str]:
    """Create a pending invitation for `invited_email` to join `tenant_id`.
    Returns the persisted record (never carrying the raw token -- only its
    hash) and the raw token; this is the ONLY point the raw value exists.

    **Authorized** (architecture research Phase G section 9: "invitation
    creation ... must be tenant-scoped and authorized"), via the existing
    `saas_os.core.rbac.can()` chokepoint -- the dedicated `(resource="invitation",
    action="create")` capability, registered here idempotently, exactly
    mirroring `saas_os/core/api_keys/service.py::create_service_account_api_key()`'s
    own gating shape. `saas_os.core.rbac` is imported locally, not at module scope,
    to avoid a module-load cycle: `saas_os/core/rbac/authorization.py` itself
    imports `saas_os/core/identity` at module scope (for `get_membership`/`get_user`),
    so a top-level import the other way round would be circular (the same
    deferred-import technique `saas_os/core/notifications/service.py` and
    `saas_os/core/usage/service.py` already use for their own cross-module calls).

    **No privilege escalation is possible through invitation creation**:
    this phase's `Invitation` carries no role or scope of its own --
    accepting one only ever activates a bare `TenantMembership`, never
    assigns a `MembershipRole` (`Invitation`'s own docstring). An inviter
    therefore can never grant the invitee more authority than the inviter
    already has, because acceptance grants no authority at all; assigning
    a role remains the wholly separate, independently-authorized
    `saas_os/core/rbac/service.py::assign_role()` operation.

    `expires_at` defaults to `_DEFAULT_INVITATION_LIFETIME` (7 days) from
    now, capped at `_MAX_INVITATION_LIFETIME` (30 days) -- mirrors
    `saas_os/core/rbac/service.py::create_support_access_request()`'s own
    "bounded, not merely optional" duration discipline.
    """
    require_caller("create_invitation", caller, (UserCaller,))
    inviter_user_id = caller.user_id
    from saas_os.core.rbac import can, register_permission

    require_open_tenant(tenant_id)
    normalized_email = _normalize_email(invited_email)

    now = datetime.now(UTC)
    resolved_expires_at = (
        expires_at if expires_at is not None else now + _DEFAULT_INVITATION_LIFETIME
    )
    if resolved_expires_at - now > _MAX_INVITATION_LIFETIME:
        resolved_expires_at = now + _MAX_INVITATION_LIFETIME

    raw_token = secrets.token_urlsafe(_INVITATION_TOKEN_BYTES)
    token_hash = _hash_invitation_token(raw_token)

    try:
        with tenant_session_scope(tenant_id) as session:
            register_permission("invitation", "create", session=session)
            if not can(
                actor_id=inviter_user_id,
                tenant_id=tenant_id,
                action="create",
                resource="invitation",
                session=session,
            ):
                raise InvitationNotAuthorizedError(inviter_user_id, tenant_id)
            invitation = Invitation(
                tenant_id=tenant_id,
                invited_email=normalized_email,
                token_hash=token_hash,
                inviter_user_id=inviter_user_id,
                expires_at=resolved_expires_at,
            )
            session.add(invitation)
            session.flush()
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action="invitation.create",
                resource_type="invitation",
                resource_id=str(invitation.id),
            )
            session.refresh(invitation)
            session.expunge(invitation)
    except IntegrityError as exc:
        raise DuplicateInvitationError(tenant_id, normalized_email) from exc

    return invitation, raw_token


def get_invitation(tenant_id: uuid.UUID, invitation_id: uuid.UUID) -> Invitation | None:
    """Resolve `invitation_id` within `tenant_id`, or `None` if it does not
    exist there. `core.invitations` is RLS-protected (Privacy Architecture
    Audit finding PRIV-01, migration `cb7120cfa806`) -- `tenant_id` is
    still filtered explicitly in the query itself as defense in depth on
    top of the database-level policy, the same belt-and-suspenders
    convention every other RLS-protected table's own service functions
    already use."""
    with tenant_session_scope(tenant_id) as session:
        invitation = session.execute(
            select(Invitation).where(
                Invitation.tenant_id == tenant_id, Invitation.id == invitation_id
            )
        ).scalar_one_or_none()
        if invitation is not None:
            session.expunge(invitation)
        return invitation


def list_invitations_for_tenant(
    tenant_id: uuid.UUID, *, limit: int | None = None, offset: int = 0
) -> list[Invitation]:
    """The tenant's invitations, oldest first (`created_at`, then `id`).
    `limit`/`offset` page in the database; without `limit`, all of them."""
    _check_page(limit, offset)
    statement = (
        select(Invitation)
        .where(Invitation.tenant_id == tenant_id)
        .order_by(Invitation.created_at, Invitation.id)
        .offset(offset)
    )
    if limit is not None:
        statement = statement.limit(limit)
    with tenant_session_scope(tenant_id) as session:
        invitations = session.execute(statement).scalars().all()
        for invitation in invitations:
            session.expunge(invitation)
        return list(invitations)


def revoke_invitation(
    tenant_id: uuid.UUID, invitation_id: uuid.UUID, *, caller: UserCaller
) -> Invitation:
    """Revoke a pending invitation. **Authorized** exactly like
    `create_invitation()` -- the dedicated `(resource="invitation",
    action="revoke")` capability. Idempotent if already revoked. Raises
    `InvitationAlreadyAcceptedError` if the invitation has already been
    consumed (`ck_invitations_not_accepted_and_revoked`: an accepted
    invitation can never subsequently be revoked)."""
    require_caller("revoke_invitation", caller, (UserCaller,))
    actor_user_id = caller.user_id
    from saas_os.core.rbac import can, register_permission

    with tenant_session_scope(tenant_id) as session:
        register_permission("invitation", "revoke", session=session)
        if not can(
            actor_id=actor_user_id,
            tenant_id=tenant_id,
            action="revoke",
            resource="invitation",
            session=session,
        ):
            raise InvitationNotAuthorizedError(actor_user_id, tenant_id)
        invitation = session.execute(
            select(Invitation).where(
                Invitation.tenant_id == tenant_id, Invitation.id == invitation_id
            )
        ).scalar_one_or_none()
        if invitation is None:
            raise InvitationNotFoundError(tenant_id, invitation_id)
        if invitation.revoked_at is not None:
            session.expunge(invitation)
            return invitation
        if invitation.accepted_at is not None:
            raise InvitationAlreadyAcceptedError(invitation_id)
        invitation.revoked_at = datetime.now(UTC)
        invitation.revoked_by_user_id = actor_user_id
        session.flush()
        record_in_transaction(
            session,
            caller=caller,
            tenant_id=tenant_id,
            action="invitation.revoke",
            resource_type="invitation",
            resource_id=str(invitation.id),
        )
        session.refresh(invitation)
        session.expunge(invitation)

    return invitation


def accept_invitation(
    raw_token: str,
    tenant_id: uuid.UUID,
    *,
    caller: UserCaller,
    accepting_email: str | None = None,
    now: datetime | None = None,
) -> TenantMembership:
    """Redeem `raw_token`, activating (or creating) `accepting_user_id`'s
    `TenantMembership` in `tenant_id`. `now` is a test-only injection
    point; real callers never pass it.

    **`tenant_id` is required, and only ever scopes the database lookup --
    it is never itself a source of authority** (PRIV-01, migration
    `cb7120cfa806`: `core.invitations` is FORCE ROW LEVEL SECURITY
    protected, so a token-hash lookup with no tenant context set sees no
    rows at all -- `saas_os.infra.db.tenant_session_scope()` must therefore be
    established *before* this function can see the invitation row in the
    first place). The caller (the future Phase 8 ingress layer, or a test)
    must already know which tenant a given invitation link belongs to --
    e.g. from the URL the invitation email pointed at -- exactly the same
    shape as any other bearer-secret redemption that also needs a routing
    hint (mirrors `saas_os/core/identity/login_transactions.py::
    consume_login_transaction()`'s own `transaction_id` parameter for the
    identical reason: a hash alone is not enough to find the row to
    validate it against). The token itself remains the sole bearer
    credential for acceptance: a `tenant_id` that does not match the
    token's own invitation buys the caller nothing, since the RLS-scoped
    query naturally sees no row there and this function raises the
    identical `InvitationInvalidError` as an unknown, expired, revoked, or
    already-accepted token -- a caller can never distinguish "wrong
    tenant" from any other failure, and supplying an arbitrary `tenant_id`
    can never expose, nor accept, an invitation that does not genuinely
    belong to it.

    **One-time, expiry-aware, revocation-aware, tenant-bound, and
    replay-resistant** (architecture research Phase G section 5), all
    inside the single `tenant_session_scope(tenant_id)` transaction this
    function performs the membership mutation in, so resolution and
    activation commit atomically together or not at all:

    1. Resolve the token by hash, scoped to `tenant_id` (RLS plus an
       explicit `tenant_id` filter, the same defense-in-depth convention
       `get_invitation()` uses) -- an unknown hash, one belonging to a
       different tenant than `tenant_id`, an already-accepted,
       already-revoked, or expired invitation all raise the identical
       `InvitationInvalidError` (`InvitationInvalidError`'s own docstring:
       never lets a caller probing a token distinguish *why* it failed).
    2. Re-validate and consume the SAME row **under a row lock**
       (`_consume_locked_invitation()`, the transactional phase). The row
       lock (`with_for_update=True`, mirroring
       `saas_os/core/identity/login_transactions.py::consume_login_transaction()`)
       serializes two concurrent acceptance attempts for the same token:
       the loser's re-validation finds `accepted_at` already set and
       raises, never creating a second membership.
    2b. **Tenant lifecycle fence** (PRIV-03 Phase P13, privacy re-audit
       RA-09 finding 1): immediately after the row lock and before any
       validation or membership write, the invitation's own tenant is
       read with `saas_os.core.tenancy.lock_accessible_tenant()` -- the RA-04
       primitive (`core.tenants` row `FOR SHARE`, in this same
       transaction) -- so a tenant that no longer admits tenant principals
       (`SUSPENDED`/`DELETED`/`PURGING`/`PURGED`, or one that no longer
       exists) can never gain a membership through an invitation, and a
       closure cannot commit between this check and the membership write
       (the transition's `FOR UPDATE` waits for this transaction). The
       rejection is surfaced as the very same `InvitationInvalidError` as
       every other failure: a token bearer learns nothing about the
       tenant's lifecycle. `PENDING`/`ACTIVE` pass, exactly as the
       RA-04 policy admits them.
    3. **Cannot produce a duplicate active membership**: `TenantMembership`'s
       own `UniqueConstraint("tenant_id", "user_id")` means there is
       structurally at most one membership row per (tenant, user) ever --
       this function updates that single row's `status`, it never inserts
       a second one for an existing member.
    4. **Fail-closed on an existing inactive membership**: if
       `accepting_user_id` already has a membership in this tenant and its
       status is anything other than `ACTIVE`, this function raises
       `InvalidMembershipTransitionError` rather than silently reactivating
       it (architecture research Phase G: "do not silently reactivate a
       revoked membership unless the architecture explicitly requires
       it"). An already-`ACTIVE` membership is a no-op success (the
       invitation is still consumed).

    **Email binding (ADR-0046).** `core.users` stores no email, so this
    function cannot look one up. When `accepting_email` is given -- the
    email the identity provider verified for the caller, which the HTTP
    route takes from the caller's session -- the invitation is accepted
    only if it equals `invited_email` after the same normalization, and a
    mismatch is the same `InvitationInvalidError` as every other failure
    -- and so is a non-ASCII address on either side, because case
    folding maps distinct non-ASCII addresses onto one --
    raised under the row lock with nothing consumed. When it is `None`,
    no comparison is made (a product's own acceptance path that binds the
    person some other way). The
    accepting user is the explicit, active caller (ADR-0031). Likewise,
    this function does not require `accepting_user_id` to already hold a
    membership in `tenant_id` -- the invitation itself, not tenant
    context, is what authorizes joining (architecture research
    Phase G: an invitation's whole purpose is to let a not-yet-a-member
    user become one).
    """
    from saas_os.core.rbac.service import require_active_user

    require_caller("accept_invitation", caller, (UserCaller,))
    accepting_user_id = caller.user_id
    resolved_now = now if now is not None else datetime.now(UTC)
    token_hash = _hash_invitation_token(raw_token)

    with tenant_session_scope(tenant_id) as session:
        # ADR-0031: the accepting user is the explicit caller, and must be
        # an active user -- an inactive account can never gain a
        # membership. Checked in this acceptance's own transaction.
        require_active_user(
            caller, session=session, operation="accept_invitation", tenant_id=tenant_id
        )
        invitation_id = session.execute(
            select(Invitation.id).where(
                Invitation.tenant_id == tenant_id, Invitation.token_hash == token_hash
            )
        ).scalar_one_or_none()
        if invitation_id is None:
            raise InvitationInvalidError()

        membership = _consume_locked_invitation(
            session,
            tenant_id=tenant_id,
            invitation_id=invitation_id,
            token_hash=token_hash,
            accepting_user_id=accepting_user_id,
            accepting_email=accepting_email,
            now=resolved_now,
        )
        session.flush()
        record_in_transaction(
            session,
            caller=caller,
            tenant_id=tenant_id,
            action="invitation.accept",
            resource_type="invitation",
            resource_id=str(invitation_id),
        )
    return membership


def _consume_locked_invitation(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    invitation_id: uuid.UUID,
    token_hash: str,
    accepting_user_id: uuid.UUID,
    now: datetime,
    accepting_email: str | None = None,
) -> TenantMembership:
    """The transactional phase of `accept_invitation()` (its steps 2-4),
    run inside the caller's `tenant_session_scope(tenant_id)` transaction
    -- never a transaction of its own. Order, and why it matters:

    1. lock the invitation row `FOR UPDATE` (serializes concurrent
       acceptance and revocation);
    2. `lock_accessible_tenant()` -- the tenant lifecycle fence (PRIV-03
       P13 / RA-09 finding 1), `core.tenants` `FOR SHARE` in this same
       transaction, so the membership below can never be written into a
       SUSPENDED/DELETED/PURGING/PURGED (or vanished) tenant and no closure
       can commit between this read and that write;
    3. re-validate the invitation (hash, not accepted, not revoked, not
       expired) and consume it;
    4. create, or no-op on an ACTIVE, `TenantMembership`; fail closed on a
       suspended/revoked one.

    Every rejection in 1-3 is the same `InvitationInvalidError` -- a token
    bearer must not be able to tell a lifecycle-closed tenant from an
    unknown, expired, revoked or consumed token. Kept separate from
    `accept_invitation()` so the locked phase can also be exercised
    directly by tests, inside a real tenant-scoped transaction, once the
    caller already knows `(tenant_id, invitation_id)` -- exactly the shape
    `accept_invitation()` itself calls it with after its own tenant-scoped
    token-hash lookup.
    """
    invitation = session.get(Invitation, invitation_id, with_for_update=True)
    if invitation is None:
        raise InvitationInvalidError()

    try:
        lock_accessible_tenant(session, tenant_id)
    except (TenantNotFoundError, TenantInaccessibleError):
        raise InvitationInvalidError() from None

    if (
        invitation.tenant_id != tenant_id
        or invitation.token_hash != token_hash
        or invitation.accepted_at is not None
        or invitation.revoked_at is not None
        or invitation.expires_at <= now
    ):
        raise InvitationInvalidError()
    # ADR-0046: bound to the verified email when one is given. Checked under
    # the row lock, before anything is consumed; the same error as every
    # other refusal, so a link holder learns nothing about the address.
    # Both sides ASCII only: case folding maps distinct non-ASCII addresses
    # onto one, so a non-ASCII address never matches.
    if accepting_email is not None and (
        not accepting_email.isascii()
        or not invitation.invited_email.isascii()
        or not hmac.compare_digest(
            accepting_email.strip().casefold().encode("ascii"),
            invitation.invited_email.encode("ascii"),
        )
    ):
        raise InvitationInvalidError()

    invitation.accepted_at = now
    invitation.accepted_by_user_id = accepting_user_id

    membership = session.execute(
        select(TenantMembership).where(
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.user_id == accepting_user_id,
        )
    ).scalar_one_or_none()

    if membership is None:
        membership = TenantMembership(
            tenant_id=tenant_id,
            user_id=accepting_user_id,
            status=MembershipStatus.ACTIVE.value,
        )
        session.add(membership)
    elif membership.status != MembershipStatus.ACTIVE.value:
        raise InvalidMembershipTransitionError(
            membership.id, membership.status, MembershipStatus.ACTIVE.value
        )

    session.flush()
    session.refresh(invitation)
    session.refresh(membership)
    session.expunge(invitation)
    session.expunge(membership)
    return membership


# --- PRIV-03 Phase P3: tenant purge ------------------------------------------
#
# Three module-owned steps of `saas_os.core.tenancy.purge_tenant()`. Only
# tenant-owned relationships are removed here; the global identity tables
# (`core.users`, `core.external_identities`, `core.sessions`,
# `core.login_transactions`) are never touched -- a user may belong to
# other tenants, and a purge is about one tenant only. Each step is only
# callable in the purge phase (`TenantNotPurgingError` otherwise), runs
# under `tenant_session_scope()`/RLS with rows locked `FOR UPDATE`, and is
# idempotent.


@dataclass(frozen=True)
class ServiceAccountPurgeResult:
    """`deleted` service accounts are gone; `retained_ids` were kept --
    *disabled* -- because an audit entry names one as its actor
    (`saas_os.core.audit_log.actor_service_account_id`, a `NO ACTION` composite FK
    the runtime role can never clear) or a retained delegation grant names
    it as delegate. A retained account has no API keys and no role
    assignments left (earlier purge steps removed them) and `DISABLED`
    status, so it confers nothing."""

    deleted: int
    retained_ids: frozenset[uuid.UUID]


def purge_tenant_invitations(tenant_id: uuid.UUID) -> int:
    """Delete every invitation `tenant_id` issued -- `invited_email` is
    the one piece of third-party PII a tenant holds, so nothing about it
    is retained (pending, accepted, revoked, or expired alike)."""
    require_purging_tenant(tenant_id)
    deleted = 0
    with tenant_session_scope(tenant_id) as session:
        rows = (
            session.execute(
                select(Invitation)
                .where(Invitation.tenant_id == tenant_id)
                .order_by(Invitation.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for row in rows:
            session.delete(row)
            deleted += 1
    return deleted


def purge_tenant_service_accounts(
    tenant_id: uuid.UUID, *, keep_service_account_ids: frozenset[uuid.UUID] = frozenset()
) -> ServiceAccountPurgeResult:
    """Disable every service account `tenant_id` owns, then delete each
    one that is not retained. Retained = audit-referenced
    (`saas_os.core.audit_log.referenced_service_account_ids()`) plus
    `keep_service_account_ids` (the delegates of audit-retained
    delegation grants, from `saas_os.core.rbac.purge_tenant_authorization()`).
    Must run after API keys and service-account roles are gone (both
    carry composite FKs onto `core.service_accounts`)."""
    require_purging_tenant(tenant_id)
    keep = referenced_service_account_ids(tenant_id) | keep_service_account_ids
    deleted = 0
    retained: set[uuid.UUID] = set()
    with tenant_session_scope(tenant_id) as session:
        accounts = (
            session.execute(
                select(ServiceAccount)
                .where(ServiceAccount.tenant_id == tenant_id)
                .order_by(ServiceAccount.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for account in accounts:
            if account.status != ServiceAccountStatus.DISABLED.value:
                account.status = ServiceAccountStatus.DISABLED.value
            if account.id in keep:
                retained.add(account.id)
                continue
            session.delete(account)
            deleted += 1
    return ServiceAccountPurgeResult(deleted=deleted, retained_ids=frozenset(retained))


def purge_tenant_memberships(tenant_id: uuid.UUID) -> int:
    """Delete every `core.tenant_memberships` row of `tenant_id` -- the
    tenant-owned half of the user<->tenant relationship only; the users
    themselves remain. Must run last among the identity steps: API keys,
    notifications, and membership roles all carry composite FKs onto
    memberships."""
    require_purging_tenant(tenant_id)
    deleted = 0
    with tenant_session_scope(tenant_id) as session:
        rows = (
            session.execute(
                select(TenantMembership)
                .where(TenantMembership.tenant_id == tenant_id)
                .order_by(TenantMembership.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for row in rows:
            session.delete(row)
            deleted += 1
    return deleted
