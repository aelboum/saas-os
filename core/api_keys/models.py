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
In its place, the **composite foreign key** below --
`(tenant_id, user_id) -> core.tenant_memberships(tenant_id, user_id)` --
is the database-level integrity guarantee that substitutes for RLS: a key
can only ever exist for a user who is a genuine member of that tenant,
enforced by Postgres itself, not by application code remembering to check
(the same composite-FK discipline `core/rbac/models.py` established in
Phase 3.3 section 18, applied here to the one table that structurally
cannot use RLS instead).

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from infra.db import (
    Base,
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
    No `updated_at`: `revoked_at` is the one field a key's row is ever
    expected to change after creation, and it says exactly when and
    whether that happened.
    """

    __tablename__ = "api_keys"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["core.tenant_memberships.tenant_id", "core.tenant_memberships.user_id"],
            name="fk_api_keys_tenant_membership",
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(nullable=False)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
