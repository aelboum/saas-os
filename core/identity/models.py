"""User, external-identity, session, tenant-membership, and service-account
entities (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2; docs/MULTI-TENANCY.md
section 1; docs/DATA-ARCHITECTURE.md section 1: `core.*`, owned exclusively
by this module; docs/ARCHITECTURE.md section 4's Module Ownership table:
`core/identity` owns "machine identity" -- architecture research Phase E
implements that entry).

Seven tables, three isolation postures:

    core.users               -- global (docs/MULTI-TENANCY.md section 1:
                                 "a user is a global identity ...
                                 independent of any tenant"). Not RLS-scoped,
                                 mirroring core.tenants (core/tenancy/models.py):
                                 resolving *which* user a request belongs to
                                 must be possible before any tenant context
                                 exists.
    core.external_identities -- global. An OIDC (issuer, subject) pair
                                 identifies a platform user directly, before
                                 any tenant is known -- same reasoning as
                                 core.users.
    core.sessions             -- global. A platform session identifies a
                                 user, not a tenant (a user may belong to,
                                 and act across, more than one tenant --
                                 docs/ADR/0005-identity-build-vs-buy.md);
                                 which tenant a given request acts *as* is a
                                 per-request core/rbac concern (Phase 3.3),
                                 not baked into the session record itself.
    core.tenant_memberships   -- tenant-owned. This is the one identity
                                 table that genuinely is tenant-scoped data
                                 (docs/MULTI-TENANCY.md section 4) and is
                                 RLS-protected via infra.db.rls, exactly like
                                 any other tenant-owned table a future
                                 module defines.
    core.service_accounts     -- tenant-owned, RLS-protected (architecture
                                 research Phase E -- "a service account is a
                                 tenant-scoped machine identity ... belongs
                                 to exactly one Tenant ... must not
                                 automatically gain authority over parent or
                                 child tenants"). See `ServiceAccount`'s own
                                 docstring below.
    core.invitations          -- GLOBAL, not RLS-scoped (architecture
                                 research Phase G -- "Invitation / Membership
                                 Lifecycle"). Mirrors `core.sessions`/
                                 `core.api_keys`'s own reasoning exactly: an
                                 invitation is a bearer credential (its
                                 token) that must be resolvable by hash
                                 *before* any tenant context exists -- an
                                 invitee who has never logged in yet has no
                                 tenant, and possibly no `core.users` row at
                                 all. `tenant_id` is a real, required
                                 column, just not an RLS-enforced one (same
                                 structural exception `core/api_keys/models.py
                                 ::ApiKey`'s own docstring documents).

Phase G also adds an explicit lifecycle `status` to `core.tenant_memberships`
itself (`MembershipStatus`, below) -- see `TenantMembership`'s own
docstring.

No permission/role column exists anywhere here -- authorization is
core/rbac's exclusive concern (Phase 3.3; ADR-0005: "core/rbac ... owns all
application-level authorization and permissions"). This module owns
identity data only.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from infra.db import (
    Base,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Mapped,
    String,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    mapped_column,
    text,
)


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A global platform identity. Deliberately minimal for Phase 3.2: no
    email, display name, or other profile field is stored here -- none is
    required by the roadmap's Phase 3.2 scope ("users, sessions, OIDC
    integration"), and email specifically must never become the canonical
    identity key -- `ExternalIdentity.issuer` + `.subject` is that key. A
    profile/email field can be added in a later phase without touching this
    identity boundary.
    """

    __tablename__ = "users"
    __table_args__ = {"schema": "core"}

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class ExternalIdentity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One OIDC (issuer, subject) pair linked to exactly one platform User.
    Standards-based: nothing here is ZITADEL-specific (ADR-0005) -- a future
    second OIDC provider is just another row with a different `issuer`, on
    the same table, linkable to the same or a different User. The unique
    constraint is the real duplicate-identity guard; `core/identity/service.py`
    adds defense-in-depth for the race-condition path.
    """

    __tablename__ = "external_identities"
    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_external_identities_issuer_subject"),
        {"schema": "core"},
    )

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.users.id"), nullable=False)
    issuer: Mapped[str] = mapped_column(String(2048), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)


class Session(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A platform session. `token_hash` is the SHA-256 hex digest of the
    bearer secret -- the raw secret itself is never persisted
    (docs/SECURITY.md; `core/identity/sessions.py` issues/validates it).
    """

    __tablename__ = "sessions"
    __table_args__ = {"schema": "core"}

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LoginTransaction(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One in-flight OIDC Authorization Code login (P2.2), global like
    `core.sessions` -- it exists before any user or tenant is known.

    Server-side record of the three per-login secrets the OIDC flow needs
    to bind a callback to the browser that started it: `state` (CSRF
    binding, compared constant-time and unique), `nonce` (bound into the
    ID token and re-checked by `core.identity.oidc.validate_id_token`),
    and the PKCE `code_verifier` (sent only in the server-side token
    exchange, never in the authorization URL). None of them is ever
    logged. The row's own `id` travels to the browser in a separate,
    HttpOnly cookie, so a callback must present *both* the cookie-bound
    transaction id and the matching `state` query parameter -- a state
    value alone, from an attacker-controlled query string, resolves
    nothing. Rows are single-use: `core.identity.login_transactions.
    consume_login_transaction()` deletes the row under a row lock in the
    same transaction it validates it, so a replayed callback finds
    nothing. Short-lived (`expires_at`); expired rows are refused and
    purgeable.
    """

    __tablename__ = "login_transactions"
    __table_args__ = {"schema": "core"}

    state: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    code_verifier: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class MembershipStatus(enum.StrEnum):
    """A `TenantMembership`'s lifecycle (architecture research Phase G --
    "Invitation / Membership Lifecycle": "prevent stale, revoked, or
    otherwise inactive memberships from continuing to authorize access").
    The smallest state model that correctly represents the existing
    architecture -- four states, mirroring `ServiceAccountStatus`'s own
    plain-`enum.StrEnum`-stored-as-`.value`-with-a-database-CHECK shape,
    not a workflow engine. Three states -- not four: an `INVITED` state was
    considered and deliberately dropped (architecture research Phase G
    pre-checkpoint review) because no code path in this phase ever
    produces it -- `Invitation`'s own docstring explains why a membership
    row cannot exist before acceptance (no resolvable `user_id` for a
    bare email target), so acceptance always creates/activates a
    membership directly as `ACTIVE`, never via an intermediate pending
    membership row. Reintroducing it is a later phase's decision, made
    when a real code path actually needs it -- not speculative
    completeness:

        ACTIVE    -- the default (backward-compatible with every
                     pre-Phase-G membership row and every existing caller
                     of `add_tenant_membership()`, which continues to
                     create memberships directly in this status, unchanged).
                     `core/rbac/authorization.py::can()`'s ordinary
                     membership-role path requires exactly this status
                     before honoring any `MembershipRole` the membership
                     holds -- the sole authoritative gate this phase adds.
        SUSPENDED -- reversible (`reactivate_membership()` returns it to
                     `ACTIVE`) -- mirrors `ServiceAccountStatus.DISABLED`'s
                     own "disabling is not deletion" reasoning. Blocks
                     every membership-role authorization immediately, the
                     very next `can()` call -- no cache to invalidate.
        REVOKED   -- terminal. `revoke_membership()` is one-way: no
                     function in this phase transitions a `REVOKED`
                     membership back to any other status (`reactivate_membership()`
                     explicitly refuses it) -- "do not silently reactivate
                     a revoked membership" (this phase's own approved
                     design; fail-closed where genuinely ambiguous).

    Stored as a `String` column (`TenantMembership.status`, below) with a
    database-level `CHECK` constraint restricting it to exactly these
    three values -- an invalid status is rejected by PostgreSQL itself.
    """

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class TenantMembership(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A user's membership in a tenant -- tenant-owned data, RLS-protected
    (see this module's docstring). No role/permission column: that is
    core/rbac's table to define in Phase 3.3, not this one's.

    The extra `UniqueConstraint("tenant_id", "id", ...)` (redundant with the
    primary key alone, since `id` is already globally unique) exists so
    `core/rbac`'s `membership_roles` join table can declare a *composite*
    foreign key `(tenant_id, membership_id) -> tenant_memberships(tenant_id, id)`
    (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 18) -- Postgres
    requires a unique/PK constraint on exactly the referenced column tuple
    for a composite FK target. This is what makes "a role assignment can
    never reference a membership belonging to a different tenant" a
    database-level guarantee, not just an application-level check.

    `status` (`MembershipStatus`, above -- architecture research Phase G)
    is this row's own explicit lifecycle, independent of whether any
    `MembershipRole` still references it: `core/rbac/authorization.py::can()`
    requires `status == ACTIVE` before it will honor a membership's roles
    at all, so suspending or revoking a membership immediately blocks its
    authorization even though the `MembershipRole` rows themselves are
    left completely untouched (no cascading cleanup, no bulk delete -- the
    single `status` column is the one authoritative switch, exactly the
    "derive authorization from one live column, never a cache" discipline
    `ServiceAccountStatus`/`ApiKey.revoked_at` already established).
    Defaults to `ACTIVE`, preserving every pre-Phase-G membership's
    behavior and `add_tenant_membership()`'s own unchanged, ungated,
    directly-active creation path.
    """

    __tablename__ = "tenant_memberships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_tenant_memberships_tenant_user"),
        UniqueConstraint("tenant_id", "id", name="uq_tenant_memberships_tenant_id_id"),
        CheckConstraint(
            "status IN ('active', 'suspended', 'revoked')",
            name="ck_tenant_memberships_valid_status",
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.users.id"), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=MembershipStatus.ACTIVE.value
    )


class ServiceAccountStatus(enum.StrEnum):
    """A service account's lifecycle -- exactly two states (architecture
    research Phase E: "Implement only: ACTIVE, DISABLED ... Do not
    introduce complex lifecycle workflows"). Mirrors
    `core/tenancy/lifecycle.py::TenantStatus`'s own shape: a plain
    `enum.StrEnum`, stored as its `.value` in a `String` column
    (`ServiceAccount.status` below), with a database-level `CHECK`
    constraint restricting the column to exactly these values -- an
    invalid status is rejected by PostgreSQL itself, not merely by this
    enum's own type system.

        ACTIVE   -- the default. `core/rbac/authorization.py::can()` and
                    `core/api_keys/service.py::validate_api_key()` both
                    require this status before honoring the service
                    account as an actor or a key's owner.
        DISABLED -- immediately blocks every API key owned by this
                    service account from authenticating
                    (`core/api_keys/service.py::validate_api_key()`) and
                    blocks `can()` from ever authorizing this service
                    account as an actor, regardless of what roles,
                    delegations, or the absence of any deny would
                    otherwise allow. Reversible (`enable_service_account()`)
                    -- disabling is not deletion, and no deletion path is
                    added by this phase (`core/identity/service.py`'s own
                    docstring).
    """

    ACTIVE = "active"
    DISABLED = "disabled"


class ServiceAccount(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A tenant-scoped machine identity (architecture research: universal
    multi-tenant tenancy, Phase E -- "Principal + Service Accounts + API
    Key Hardening"). Tenant-owned, RLS-protected -- unlike `User` (global)
    or `TenantMembership` (a `User` may hold many, one per tenant), a
    `ServiceAccount` has a single, fixed `tenant_id` set at creation and
    never reassigned (no "move" operation exists, unlike
    `core.tenancy.move_tenant()`).

    This is what makes "no implicit hierarchy access" true by
    construction, not merely by convention: `core/rbac`'s
    `ServiceAccountRole` (the join table analogous to `MembershipRole`)
    can only ever be created with `tenant_id` equal to this row's own
    `tenant_id` -- enforced by a composite foreign key
    `(tenant_id, service_account_id) -> service_accounts(tenant_id, id)`
    (`core/rbac/models.py`), the same discipline `TenantMembership`'s own
    `UniqueConstraint("tenant_id", "id")` enables for `MembershipRole`.
    An explicit `SUBTREE`-scoped `ServiceAccountRole` assigned at this
    tenant is therefore the ONLY way this service account's authority
    ever reaches beyond its own tenant -- never a parent, never an
    unrelated tenant, and never automatically merely because one is a
    structural ancestor/descendant of the other (`core/tenancy/models.py`
    ::`Tenant.parent_id`'s own docstring: hierarchy never itself creates
    authorization). A `DelegationGrant`/`DenyGrant` naming this service
    account as a principal (`core/rbac/principal.py::PrincipalType
    .SERVICE_ACCOUNT`) is a separate, explicit authorization primitive --
    like a `User` principal, not restricted to this service account's own
    tenant (`DelegationGrant`'s own docstring: "delegation is
    intentionally separate from hierarchy").

    Deliberately not a `User`: a service account is a machine principal,
    identified by `(PrincipalType.SERVICE_ACCOUNT, id)` wherever
    `core/rbac` names or evaluates a principal -- inserting it into
    `core.users` would let it participate in an ordinary human
    `TenantMembership` (a `User` may belong to many tenants), exactly the
    cross-tenant ambiguity this entity exists to avoid. It is also never
    given its own `TenantMembership` row: `core/rbac/models.py
    ::ServiceAccountRole` is the complete, sufficient anchor for its role
    assignments, mirroring `MembershipRole`'s relationship to
    `TenantMembership` without reusing that table (a service account has
    no "membership" to belong to -- its `tenant_id` alone already answers
    "which tenant does this principal belong to").

    `status` (`ServiceAccountStatus`, above) is the only lifecycle this
    phase implements. No deletion path exists here -- disabling is
    immediate, reversible, and sufficient for every requirement this
    phase states; `core/identity/service.py` adds no destructive
    operation for this entity.

    The extra `UniqueConstraint("tenant_id", "id", ...)` exists for the
    identical composite-FK-target reason `TenantMembership`'s own carries
    (this class's own docstring, above) -- required by Postgres as the
    exact tuple a composite foreign key must reference.
    """

    __tablename__ = "service_accounts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_service_accounts_tenant_name"),
        UniqueConstraint("tenant_id", "id", name="uq_service_accounts_tenant_id_id"),
        CheckConstraint(
            "status IN ('active', 'disabled')", name="ck_service_accounts_valid_status"
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ServiceAccountStatus.ACTIVE.value
    )


class Invitation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A tenant-scoped invitation for an email/identity to join a tenant
    (architecture research: universal multi-tenant tenancy, Phase G --
    "Invitation / Membership Lifecycle"). **GLOBAL, not RLS-scoped** --
    see this module's own docstring for why: an invitation's raw token
    must be resolvable by hash before any tenant context exists, exactly
    the same structural constraint `core/api_keys/models.py::ApiKey` and
    `core/identity/models.py::Session` already resolve the identical way.
    `tenant_id` is a real, required column here -- just not an
    RLS-enforced one.

    **No raw token is ever stored.** `token_hash` is the SHA-256 hex
    digest of a `secrets.token_urlsafe`-generated bearer secret
    (`core/identity/service.py::create_invitation()`/`accept_invitation()`),
    mirroring `ApiKey.key_hash`/`Session.token_hash` exactly -- the raw
    value exists only transiently, in the return value of
    `create_invitation()`, and is never logged or reconstructable
    afterward.

    **Why no `TenantMembership` is created at invitation time.** `core.users`
    stores no email (`User`'s own docstring: "email specifically must
    never become the canonical identity key") -- an invited email
    therefore has no resolvable `user_id` until the invitee actually logs
    in and `accept_invitation()` is called with their now-known,
    authenticated `user_id`. `invited_email` here is informational only
    (who this invitation was sent to); Core does not verify that the
    accepting user's own identity corresponds to it -- like every other
    `core/identity` entity-creation function, that check belongs to
    Phase 8's ingress layer, not this module (this class's own module
    docstring; `add_tenant_membership()`'s "trusts its caller" precedent).
    This is also exactly why `MembershipStatus` has no `INVITED` state
    (architecture research Phase G pre-checkpoint review) -- there is no
    membership row to mark pending before a `user_id` exists, so one was
    never introduced.

    **One row is the entire lifecycle**, exactly like `SupportAccessRequest`/
    `DelegationGrant`: no separate status column that could drift from the
    timestamps that are its real source of truth (`InvitationStatus`,
    `core/identity/invitation_status.py`, is a pure read-time projection):

        PENDING  -- `accepted_at IS NULL AND revoked_at IS NULL AND
                     expires_at > now`.
        ACCEPTED -- `accepted_at IS NOT NULL` (terminal -- `ck_invitations
                     _not_accepted_and_revoked` makes this and REVOKED
                     mutually exclusive; a consumed invitation is never
                     reusable, `accept_invitation()`'s own row-locked
                     check).
        REVOKED  -- `revoked_at IS NOT NULL` (terminal).
        EXPIRED  -- `accepted_at IS NULL AND revoked_at IS NULL AND
                     expires_at <= now`.

    Acceptance is **one-time** (the pairing/mutual-exclusion `CHECK`s below
    plus `accept_invitation()`'s row lock), **expiry-aware** and
    **revocation-aware** (both checked before honoring a token), and
    **tenant-bound** (every effect of acceptance -- the resulting
    `TenantMembership` -- is scoped to this row's own `tenant_id`, never
    caller-supplied). `accept_invitation()` merges every failure mode
    (unknown token, expired, revoked, already accepted) into one error,
    mirroring `core/identity/login_transactions.py::consume_login_transaction()`'s
    own reasoning: a bearer secret used in a URL must not let a caller
    probing it distinguish *why* a given token no longer works.

    No `role_id`/scope field: this phase implements membership lifecycle
    only -- an invitation's acceptance activates (or creates, `ACTIVE`) a
    `TenantMembership`, nothing more; assigning a role remains a wholly
    separate, pre-existing `core/rbac` operation, not something this
    entity's minimal model takes on.
    """

    __tablename__ = "invitations"
    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="ck_invitations_valid_time_range"),
        CheckConstraint(
            "(accepted_at IS NULL AND accepted_by_user_id IS NULL) "
            "OR (accepted_at IS NOT NULL AND accepted_by_user_id IS NOT NULL)",
            name="ck_invitations_acceptance_pairing",
        ),
        CheckConstraint(
            "(revoked_at IS NULL AND revoked_by_user_id IS NULL) "
            "OR (revoked_at IS NOT NULL AND revoked_by_user_id IS NOT NULL)",
            name="ck_invitations_revocation_pairing",
        ),
        CheckConstraint(
            "NOT (accepted_at IS NOT NULL AND revoked_at IS NOT NULL)",
            name="ck_invitations_not_accepted_and_revoked",
        ),
        Index("ix_invitations_tenant_email", "tenant_id", "invited_email"),
        # Partial unique index, live (pending) invitations only: at most
        # one concurrently-pending invitation per (tenant, email) --
        # mirrors `uq_support_access_requests_live_unique`'s own reasoning.
        Index(
            "uq_invitations_live_unique",
            "tenant_id",
            "invited_email",
            unique=True,
            postgresql_where=text("accepted_at IS NULL AND revoked_at IS NULL"),
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    invited_email: Mapped[str] = mapped_column(String(320), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    inviter_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.users.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
