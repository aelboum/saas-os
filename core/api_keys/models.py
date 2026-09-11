"""The API key entity (docs/IMPLEMENTATION-ROADMAP.md Phase 4.1;
docs/ARCHITECTURE.md section 4: "API key issuance, scoping, rotation,
revocation").

`core.api_keys` is GLOBAL, like `core.sessions` (`core/identity/models.py`)
-- NOT Row-Level-Security-scoped, and for the identical reason: an API key
is a bearer credential that must be resolvable by its hash *before* the
caller's tenant is known (`validate_api_key()`, `core/api_keys/service.py`).
An untenanted query against an RLS-protected, FORCE-enabled table always
returns zero rows regardless of which row's `tenant_id` would have matched
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.1's own deny-by-default guarantee)
-- so RLS cannot be layered onto the one operation ("what key is this,
and whose is it") that must run before any tenant context exists. This is
not a novel exception: it is the same structural constraint
`core/identity`'s `Session` already resolved the same way, for the same
reason.

Unlike `Session`, an API key genuinely does belong to exactly one tenant
(docs/API-ARCHITECTURE.md: rate limiting is "scoped by tenant and by API
key" -- two coordinates of the same credential, not one credential
floating across many tenants the way a human session can). `tenant_id` is
therefore a real, required column here -- just not an RLS-enforced one.
In its place, a **composite foreign key** -- `(tenant_id, user_id) ->
core.tenant_memberships(tenant_id, user_id)` for a human-owned key, or
(architecture research Phase E) `(tenant_id, service_account_id) ->
core.service_accounts(tenant_id, id)` for a machine-owned key -- is the
database-level integrity guarantee that substitutes for RLS: a key can
only ever exist for a user who is a genuine member of that tenant, or a
service account that genuinely belongs to it, enforced by Postgres
itself, not by application code remembering to check (the same
composite-FK discipline `core/rbac/models.py` established in Phase 3.3
section 18, applied here to the one table that structurally cannot use
RLS instead).

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from infra.db import (
    Base,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Mapped,
    String,
    UUIDPrimaryKeyMixin,
    func,
    mapped_column,
)


class ApiKey(Base, UUIDPrimaryKeyMixin):
    """One API key. `key_hash` is the SHA-256 hex digest of the bearer
    secret -- the raw secret itself is never persisted (docs/IMPLEMENTATION-
    ROADMAP.md Phase 4.1 Security Requirement: "keys are stored hashed,
    never in plaintext"; `core/api_keys/service.py` issues/validates it).
    No `updated_at`: `revoked_at` (and, since architecture research Phase
    E, `expires_at`) are the only fields a key's row is ever expected to
    change after creation, and they say exactly when and whether that
    happened.

    **Owner (architecture research Phase E -- "API Key Hardening").**
    Exactly one of `user_id` (a human's own key, Phase 4.1's original
    shape, unchanged) or `service_account_id` (a machine credential
    owned by a `core/identity.ServiceAccount`) is set -- never both,
    never neither (`ck_api_keys_single_owner` below). Each owner shape
    keeps its own composite foreign key as this table's RLS-equivalent
    integrity guarantee (this class's own docstring, original paragraph,
    generalizes unchanged to the service-account case):
    `(tenant_id, user_id) -> core.tenant_memberships(tenant_id, user_id)`
    for a human key, `(tenant_id, service_account_id) ->
    core.service_accounts(tenant_id, id)` for a machine key -- a
    service-account-owned key can only ever exist for a service account
    that genuinely belongs to `tenant_id`, enforced by Postgres itself.
    Both foreign keys are vacuously satisfied (NULL matches nothing to
    violate) for the owner shape a given row does not use, so no existing
    Phase 4.1 row is affected by this addition.

    `expires_at` (architecture research Phase E): `NULL` means no expiry
    (Phase 4.1's original, unchanged behavior for every pre-Phase-E key);
    once set, `expires_at <= now` makes the key permanently inert to
    `validate_api_key()`, evaluated live on every call, exactly like
    `revoked_at` already is -- no cache, no background sweep job.
    """

    __tablename__ = "api_keys"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["core.tenant_memberships.tenant_id", "core.tenant_memberships.user_id"],
            name="fk_api_keys_tenant_membership",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "service_account_id"],
            ["core.service_accounts.tenant_id", "core.service_accounts.id"],
            name="fk_api_keys_tenant_service_account",
        ),
        CheckConstraint(
            "(user_id IS NOT NULL AND service_account_id IS NULL) "
            "OR (user_id IS NULL AND service_account_id IS NOT NULL)",
            name="ck_api_keys_single_owner",
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    service_account_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
