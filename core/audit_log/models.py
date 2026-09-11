"""The append-only audit-log entry entity (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.4; docs/SECURITY.md section 8: "the single append-only store for
every privileged action platform-wide"; docs/DATA-ARCHITECTURE.md section
7: "append-only, immutable ... no update/delete path").

`core.audit_log` is tenant-owned and RLS-protected, exactly like
`core.roles`/`core.tenant_memberships` -- `tenant_id` is required on every
row (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 4: "Every
tenant-scoped audit record must carry tenant_id"). Phase 3.4 does not
implement a separate global/system (tenant-less) audit table or a
tenant-RLS bypass for one: nothing in the roadmap's Phase 3.4 objective
requires it, and a coherent design would need its own read-path carve-out
that the roadmap explicitly warns against inventing without a stated
requirement (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 12: "If
global audit events are not required by Phase 3.4, do not invent them").
An `actor_type="system"` row (see `ActorType` below) still carries a real
`tenant_id` -- it is a platform-internal actor acting *within* a tenant,
not a tenant-less event.

Deliberately does NOT use `infra.db.TimestampMixin`: that mixin's
`updated_at` (with `onupdate=func.now()`) implies a row is expected to
change, which contradicts this table's entire design goal. `created_at`
here is the one and only timestamp, set once at insert and never touched
again -- reinforcing immutability in the schema itself, not just in the
absence of an `update()` function.

**Privileged cross-tenant context (architecture research Phase F --
"Audit + Support Access").** Three additional nullable columns --
`acting_as_tenant_id`, `delegation_grant_id`, `support_access_id` -- let a
record answer "who actually performed this action, for which tenant
context, and through which delegation/support authorization?" without a
new generic Actor table and without changing `ActorType` (still exactly
`USER`/`SYSTEM`, architectural decision #3: "do NOT add a third/fourth
audit actor enum for support"). All three are pure linkage/context:
`record()` never validates them against `core/rbac`'s own tables (this
module still imports nothing from `core.rbac`/`core.identity`/`core.tenancy`,
this docstring's own next paragraph), and none of the three
independently grants anything -- an `AuditLogEntry` has never been, and
still is not, consulted by `core/rbac/authorization.py::can()`. Every
existing row has all three `NULL` and remains perfectly valid; nothing
about the historical schema or historical semantics changes.

    acting_as_tenant_id  -- the tenant context the action was performed
                            *for*, when that differs in kind from "the
                            actor's own ordinary membership" -- e.g. a
                            support-authorized action, or (a future
                            caller's choice) a delegated one. `NULL` for
                            every ordinary same-tenant membership action,
                            exactly like every audit record before this
                            phase.
    delegation_grant_id  -- set only when a real `core.rbac.DelegationGrant`
                            authorized the action -- never fabricated
                            (architecture research Phase F: "do not fake a
                            delegation grant for support access").
    support_access_id    -- set only when a real `core.rbac.SupportAccessRequest`
                            authorized the action -- a separate column
                            rather than overloading `delegation_grant_id`,
                            since a support grant is never a
                            `DelegationGrant` (architecture research Phase
                            F: "add the smallest explicit field required
                            rather than overloading delegation_grant_id").

At most one of `delegation_grant_id`/`support_access_id` is ever set on
the same row (`ck_audit_log_single_authorization_linkage` below) -- a
single action has exactly one authorization story, never two competing
ones.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract). `core/audit_log`
deliberately imports nothing from `core.identity`, `core.tenancy`, or
`core.rbac` -- `tenant_id`/`actor_user_id` are plain UUIDs, validated only
by this table's own foreign keys, so the audit-log write path has no
dependency on any other Core module's service layer succeeding first
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 6: "Audit logging must
remain usable by security-sensitive infrastructure even when authorization
fails").
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from infra.db import (
    JSON,
    Base,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Mapped,
    String,
    UUIDPrimaryKeyMixin,
    func,
    mapped_column,
)


class ActorType(enum.StrEnum):
    """Who performed the audited action. Only the two kinds Phase 3.4
    actually has a grounded use for (docs/IMPLEMENTATION-ROADMAP.md Phase
    3.4 section 6: "Do NOT add actor types merely speculatively"):

    USER   -- a `core.identity` User (human or an AI agent -- ADR-0005
              resolves both to the same identity-context shape, so no
              separate "agent" actor type is needed).
    SYSTEM -- a platform-internal actor with no associated User row (e.g.
              a migration or scheduled process acting within a tenant).

    An "anonymous/unknown" actor (e.g. a failed login with no resolvable
    identity) is deliberately not added here: it would also have no
    resolvable `tenant_id`, and Phase 3.4 does not implement the tenant-less
    event handling that would require (see module docstring). Left for
    whichever future phase actually wires up a login flow to design
    deliberately, not half-built here.
    """

    USER = "user"
    SYSTEM = "system"


class AuditOutcome(enum.StrEnum):
    """docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 3: "did it succeed
    or fail?"; docs/SECURITY.md section 8's own example ("denied by a
    permission check") is why this is three values, not two."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditLogEntry(Base, UUIDPrimaryKeyMixin):
    """One immutable audit record. See module docstring for why this does
    not use `TimestampMixin`, and `core/audit_log/service.py` for why no
    `update`/`delete` function exists anywhere in this module's public API.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        # Pairing invariant enforced at the database level, not just by
        # convention (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 18's
        # "an application check alone is insufficient" discipline, applied
        # here too): a "system" actor never carries a user id, and a "user"
        # actor always does.
        CheckConstraint(
            "(actor_type = 'user' AND actor_user_id IS NOT NULL) "
            "OR (actor_type = 'system' AND actor_user_id IS NULL)",
            name="ck_audit_log_actor_type_user_id_pairing",
        ),
        CheckConstraint("actor_type IN ('user', 'system')", name="ck_audit_log_actor_type"),
        CheckConstraint("outcome IN ('success', 'failure', 'denied')", name="ck_audit_log_outcome"),
        # Defense in depth alongside core/audit_log/metadata.py's
        # application-level size check (docs/IMPLEMENTATION-ROADMAP.md
        # Phase 3.4 section 8: "bounded size") -- a direct-SQL insert that
        # bypassed the Python validation still cannot store an oversized
        # payload.
        CheckConstraint(
            "metadata IS NULL OR octet_length(metadata::text) <= 8192",
            name="ck_audit_log_metadata_size",
        ),
        # architecture research Phase F: a single action has exactly one
        # authorization story -- never both a real delegation and a real
        # support grant at once.
        CheckConstraint(
            "NOT (delegation_grant_id IS NOT NULL AND support_access_id IS NOT NULL)",
            name="ck_audit_log_single_authorization_linkage",
        ),
        # Every expected query pattern (docs/SECURITY.md section 8:
        # "queryable by tenant, actor, and time range"; docs/IMPLEMENTATION-
        # ROADMAP.md Phase 3.4 section 10) is tenant-scoped first -- RLS
        # filters on tenant_id regardless, so every index leads with it.
        # No bare index on `action` alone: nothing in this phase's
        # acceptance criteria calls for "all X actions across every
        # tenant" as a query shape.
        Index("ix_audit_log_tenant_created_at", "tenant_id", "created_at"),
        Index("ix_audit_log_tenant_actor", "tenant_id", "actor_user_id"),
        Index("ix_audit_log_tenant_resource", "tenant_id", "resource_type", "resource_id"),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)

    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )

    # architecture research Phase F -- see module docstring's "Privileged
    # cross-tenant context" section. All three nullable; every pre-Phase-F
    # row has all three NULL.
    acting_as_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=True
    )
    delegation_grant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.delegation_grants.id"), nullable=True
    )
    support_access_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.support_access_requests.id"), nullable=True
    )

    action: Mapped[str] = mapped_column(String(200), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    outcome: Mapped[str] = mapped_column(String(20), nullable=False)

    correlation_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    entry_metadata: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
