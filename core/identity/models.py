"""User, external-identity, session, and tenant-membership entities
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.2; docs/MULTI-TENANCY.md section 1;
docs/DATA-ARCHITECTURE.md section 1: `core.*`, owned exclusively by this
module).

Four tables, three isolation postures:

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

No permission/role column exists anywhere here -- authorization is
core/rbac's exclusive concern (Phase 3.3; ADR-0005: "core/rbac ... owns all
application-level authorization and permissions"). This module owns
identity data only.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from infra.db import (
    Base,
    Boolean,
    DateTime,
    ForeignKey,
    Mapped,
    String,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    mapped_column,
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
    """

    __tablename__ = "tenant_memberships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_tenant_memberships_tenant_user"),
        UniqueConstraint("tenant_id", "id", name="uq_tenant_memberships_tenant_id_id"),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.users.id"), nullable=False)
