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

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.identity.errors import (
    DuplicateExternalIdentityError,
    DuplicateInvitationError,
    DuplicateServiceAccountNameError,
    InvalidInvitationEmailError,
    InvalidMembershipTransitionError,
    InvitationAlreadyAcceptedError,
    InvitationInvalidError,
    InvitationNotAuthorizedError,
    InvitationNotFoundError,
    MembershipNotFoundError,
    ServiceAccountNotFoundError,
    UserNotFoundError,
)
from core.identity.models import (
    ExternalIdentity,
    Invitation,
    MembershipStatus,
    ServiceAccount,
    ServiceAccountStatus,
    TenantMembership,
    User,
)
from infra.db import IntegrityError, select, session_scope, tenant_session_scope

# 256 bits of entropy -- the same standard, non-guessable bearer-secret
# size `core/identity/sessions.py`/`core/api_keys/service.py` use.
_INVITATION_TOKEN_BYTES = 32
_DEFAULT_INVITATION_LIFETIME = timedelta(days=7)
_MAX_INVITATION_LIFETIME = timedelta(days=30)
_MAX_INVITED_EMAIL_LENGTH = 320


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


# --- Membership lifecycle (architecture research: universal multi-tenant
# tenancy, Phase G -- "Invitation / Membership Lifecycle") -----------------


def _transition_membership_status(
    tenant_id: uuid.UUID,
    membership_id: uuid.UUID,
    *,
    allowed_from: frozenset[str],
    to_status: MembershipStatus,
    idempotent_from: frozenset[str],
    actor_user_id: uuid.UUID,
    audit_action: str,
) -> TenantMembership:
    """Shared transition machinery for `suspend_membership()`/
    `reactivate_membership()`/`revoke_membership()` -- mirrors
    `_set_service_account_status()`'s shape, extended with explicit
    from-state validation (architecture research Phase G: "prefer
    fail-closed behavior where the correct semantics are ambiguous" --
    an out-of-band transition, e.g. reactivating a `REVOKED` membership,
    raises rather than silently applying).
    """
    with tenant_session_scope(tenant_id) as session:
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
        membership.status = to_status.value
        session.flush()
        session.refresh(membership)
        session.expunge(membership)

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action=audit_action,
        resource_type="tenant_membership",
        resource_id=str(membership_id),
        outcome=AuditOutcome.SUCCESS,
    )
    return membership


def suspend_membership(
    tenant_id: uuid.UUID, membership_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> TenantMembership:
    """Suspend an ACTIVE membership -- the very next `core/rbac/authorization.py
    ::can()` call re-reads `status` live, so there is nothing further to
    invalidate (no cache, mirrors `disable_service_account()`). Idempotent
    if already `SUSPENDED`. Raises `InvalidMembershipTransitionError` if
    already `REVOKED` -- a `REVOKED` membership is terminal."""
    return _transition_membership_status(
        tenant_id,
        membership_id,
        allowed_from=frozenset({MembershipStatus.ACTIVE.value}),
        to_status=MembershipStatus.SUSPENDED,
        idempotent_from=frozenset({MembershipStatus.SUSPENDED.value}),
        actor_user_id=actor_user_id,
        audit_action="membership.suspend",
    )


def reactivate_membership(
    tenant_id: uuid.UUID, membership_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> TenantMembership:
    """Reactivate a `SUSPENDED` membership back to `ACTIVE`. Deliberately
    does NOT accept a `REVOKED` starting state (architecture research
    Phase G: "do not silently reactivate a revoked membership unless the
    architecture explicitly requires it" -- it does not) -- raises
    `InvalidMembershipTransitionError` instead. Idempotent if already
    `ACTIVE`."""
    return _transition_membership_status(
        tenant_id,
        membership_id,
        allowed_from=frozenset({MembershipStatus.SUSPENDED.value}),
        to_status=MembershipStatus.ACTIVE,
        idempotent_from=frozenset({MembershipStatus.ACTIVE.value}),
        actor_user_id=actor_user_id,
        audit_action="membership.reactivate",
    )


def revoke_membership(
    tenant_id: uuid.UUID, membership_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> TenantMembership:
    """Revoke a membership -- terminal (mirrors `MembershipStatus.REVOKED`'s
    own docstring: no function in this phase transitions a `REVOKED`
    membership back to any other status). Idempotent if already `REVOKED`.
    Allowed from either non-terminal starting state (`ACTIVE`, `SUSPENDED`)."""
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
        actor_user_id=actor_user_id,
        audit_action="membership.revoke",
    )


# --- Invitations (architecture research: universal multi-tenant tenancy,
# Phase G -- "Invitation / Membership Lifecycle") ---------------------------


def _hash_invitation_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _normalize_email(invited_email: str) -> str:
    """Case-insensitive-domain-and-local-part normalization, matching this
    codebase's only existing convention for a bearer-secret-adjacent
    lookup key (`core/identity/models.py::ExternalIdentity`'s own
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
    if not normalized or "@" not in normalized or normalized.startswith("@"):
        raise InvalidInvitationEmailError(f"{invited_email!r} is not a valid email address.")
    if len(normalized) > _MAX_INVITED_EMAIL_LENGTH:
        raise InvalidInvitationEmailError(f"exceeds {_MAX_INVITED_EMAIL_LENGTH} characters.")
    return normalized


def create_invitation(
    tenant_id: uuid.UUID,
    inviter_user_id: uuid.UUID,
    invited_email: str,
    *,
    expires_at: datetime | None = None,
) -> tuple[Invitation, str]:
    """Create a pending invitation for `invited_email` to join `tenant_id`.
    Returns the persisted record (never carrying the raw token -- only its
    hash) and the raw token; this is the ONLY point the raw value exists.

    **Authorized** (architecture research Phase G section 9: "invitation
    creation ... must be tenant-scoped and authorized"), via the existing
    `core.rbac.can()` chokepoint -- the dedicated `(resource="invitation",
    action="create")` capability, registered here idempotently, exactly
    mirroring `core/api_keys/service.py::create_service_account_api_key()`'s
    own gating shape. `core.rbac` is imported locally, not at module scope,
    to avoid a module-load cycle: `core/rbac/authorization.py` itself
    imports `core/identity` at module scope (for `get_membership`/`get_user`),
    so a top-level import the other way round would be circular (the same
    deferred-import technique `core/notifications/service.py` and
    `core/usage/service.py` already use for their own cross-module calls).

    **No privilege escalation is possible through invitation creation**:
    this phase's `Invitation` carries no role or scope of its own --
    accepting one only ever activates a bare `TenantMembership`, never
    assigns a `MembershipRole` (`Invitation`'s own docstring). An inviter
    therefore can never grant the invitee more authority than the inviter
    already has, because acceptance grants no authority at all; assigning
    a role remains the wholly separate, independently-authorized
    `core/rbac/service.py::assign_role()` operation.

    `expires_at` defaults to `_DEFAULT_INVITATION_LIFETIME` (7 days) from
    now, capped at `_MAX_INVITATION_LIFETIME` (30 days) -- mirrors
    `core/rbac/service.py::create_support_access_request()`'s own
    "bounded, not merely optional" duration discipline.
    """
    from core.rbac import can, register_permission

    normalized_email = _normalize_email(invited_email)

    register_permission("invitation", "create")
    if not can(
        actor_id=inviter_user_id, tenant_id=tenant_id, action="create", resource="invitation"
    ):
        raise InvitationNotAuthorizedError(inviter_user_id, tenant_id)

    now = datetime.now(UTC)
    resolved_expires_at = (
        expires_at if expires_at is not None else now + _DEFAULT_INVITATION_LIFETIME
    )
    if resolved_expires_at - now > _MAX_INVITATION_LIFETIME:
        resolved_expires_at = now + _MAX_INVITATION_LIFETIME

    raw_token = secrets.token_urlsafe(_INVITATION_TOKEN_BYTES)
    token_hash = _hash_invitation_token(raw_token)

    try:
        with session_scope() as session:
            invitation = Invitation(
                tenant_id=tenant_id,
                invited_email=normalized_email,
                token_hash=token_hash,
                inviter_user_id=inviter_user_id,
                expires_at=resolved_expires_at,
            )
            session.add(invitation)
            session.flush()
            session.refresh(invitation)
            session.expunge(invitation)
    except IntegrityError as exc:
        raise DuplicateInvitationError(tenant_id, normalized_email) from exc

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=inviter_user_id,
        action="invitation.create",
        resource_type="invitation",
        resource_id=str(invitation.id),
        outcome=AuditOutcome.SUCCESS,
    )
    return invitation, raw_token


def get_invitation(tenant_id: uuid.UUID, invitation_id: uuid.UUID) -> Invitation | None:
    """Resolve `invitation_id` within `tenant_id`, or `None` if it does not
    exist there. `core.invitations` is global (not RLS-protected --
    `Invitation`'s own docstring), so `tenant_id` is filtered explicitly in
    the query itself, mirroring `core/api_keys/service.py::get_api_key()`'s
    own reasoning for the identical structural situation."""
    with session_scope() as session:
        invitation = session.execute(
            select(Invitation).where(
                Invitation.tenant_id == tenant_id, Invitation.id == invitation_id
            )
        ).scalar_one_or_none()
        if invitation is not None:
            session.expunge(invitation)
        return invitation


def list_invitations_for_tenant(tenant_id: uuid.UUID) -> list[Invitation]:
    with session_scope() as session:
        invitations = (
            session.execute(select(Invitation).where(Invitation.tenant_id == tenant_id))
            .scalars()
            .all()
        )
        for invitation in invitations:
            session.expunge(invitation)
        return list(invitations)


def revoke_invitation(
    tenant_id: uuid.UUID, invitation_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> Invitation:
    """Revoke a pending invitation. **Authorized** exactly like
    `create_invitation()` -- the dedicated `(resource="invitation",
    action="revoke")` capability. Idempotent if already revoked. Raises
    `InvitationAlreadyAcceptedError` if the invitation has already been
    consumed (`ck_invitations_not_accepted_and_revoked`: an accepted
    invitation can never subsequently be revoked)."""
    from core.rbac import can, register_permission

    register_permission("invitation", "revoke")
    if not can(actor_id=actor_user_id, tenant_id=tenant_id, action="revoke", resource="invitation"):
        raise InvitationNotAuthorizedError(actor_user_id, tenant_id)

    with session_scope() as session:
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
        session.refresh(invitation)
        session.expunge(invitation)

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action="invitation.revoke",
        resource_type="invitation",
        resource_id=str(invitation.id),
        outcome=AuditOutcome.SUCCESS,
    )
    return invitation


def accept_invitation(
    raw_token: str, accepting_user_id: uuid.UUID, *, now: datetime | None = None
) -> TenantMembership:
    """Redeem `raw_token`, activating (or creating) `accepting_user_id`'s
    `TenantMembership` in the invitation's own `tenant_id`. `now` is a
    test-only injection point; real callers never pass it.

    **One-time, expiry-aware, revocation-aware, tenant-bound, and
    replay-resistant** (architecture research Phase G section 5):

    1. Resolve the token by hash (global lookup, `core.invitations` is not
       RLS-protected -- `Invitation`'s own docstring) -- an unknown hash,
       an already-accepted, already-revoked, or expired invitation all
       raise the identical `InvitationInvalidError`
       (`InvitationInvalidError`'s own docstring: never lets a caller
       probing a token distinguish *why* it failed).
    2. Re-validate and consume the SAME row **under a row lock**, inside
       `tenant_session_scope(invitation.tenant_id)` -- the one transaction
       this function performs the membership mutation in, so acceptance
       and membership activation commit atomically together or not at
       all. The row lock (`with_for_update=True`, mirroring
       `core/identity/login_transactions.py::consume_login_transaction()`)
       serializes two concurrent acceptance attempts for the same token:
       the loser's re-validation finds `accepted_at` already set and
       raises, never creating a second membership.
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

    This function does not itself verify that `accepting_user_id`'s own
    identity corresponds to the invitation's `invited_email` -- `core.users`
    stores no email to compare against (`Invitation`'s own docstring);
    that correspondence is Phase 8 ingress-layer's concern, mirroring
    every other "trusts its caller" `core/identity` entity-creation
    function.
    """
    resolved_now = now if now is not None else datetime.now(UTC)
    token_hash = _hash_invitation_token(raw_token)

    with session_scope() as session:
        candidate = session.execute(
            select(Invitation).where(Invitation.token_hash == token_hash)
        ).scalar_one_or_none()
        if candidate is None:
            raise InvitationInvalidError()
        tenant_id = candidate.tenant_id
        invitation_id = candidate.id

    with tenant_session_scope(tenant_id) as session:
        invitation = session.get(Invitation, invitation_id, with_for_update=True)
        if (
            invitation is None
            or invitation.token_hash != token_hash
            or invitation.accepted_at is not None
            or invitation.revoked_at is not None
            or invitation.expires_at <= resolved_now
        ):
            raise InvitationInvalidError()

        invitation.accepted_at = resolved_now
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

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=accepting_user_id,
        action="invitation.accept",
        resource_type="invitation",
        resource_id=str(invitation_id),
        outcome=AuditOutcome.SUCCESS,
    )
    return membership
