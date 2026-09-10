"""Tenant entity (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1;
docs/MULTI-TENANCY.md section 1: "a tenant *is* the customer organization";
docs/DATA-ARCHITECTURE.md section 1: `core.tenants`, owned exclusively by
this module).

`core.tenants` is the FK target every tenant-owned table across the
platform will reference -- it is deliberately *not* itself Row-Level-
Security-scoped: resolving which tenant a session belongs to must be
possible before any tenant context can be set (a chicken-and-egg problem
RLS on the registry table itself would create). Row-level isolation
(`infra.db.tenant_session_scope`, `infra.db.rls`) applies to tenant-*owned*
data, not to the tenant registry itself.

Uses `infra.db.orm`'s shared declarative base and mixins -- this module
never imports `sqlalchemy` directly (`pyproject.toml`'s "Only infra/db may
import SQLAlchemy or psycopg directly" contract).

Tenant hierarchy (architecture research: universal multi-tenant tenancy,
Phase A; ADR-0002 amendment): `Tenant` may optionally participate in a
strict single-parent tree via the nullable, self-referential `parent_id`.
This is *structural data only* -- it records which tenant is the parent of
which, nothing more. It does **not** grant any authorization by itself: a
parent tenant does not automatically gain access to a child's data, a
child does not automatically gain access to a parent's or a sibling's
data, and no RLS policy or `core.rbac` check references it in this phase.
Hierarchy-aware authorization (scoped roles, delegation, the future
`app.authorized_tenant_ids` GUC) is an explicitly deferred future phase --
see ADR-0002's "Future Migration / Extension Path" and
`docs/MULTI-TENANCY.md` section 8.

A tenant with `parent_id IS NULL` is a *root* tenant. Every tenant that
existed before this column was added remains a root tenant after
migration (`ALTER TABLE ... ADD COLUMN parent_id ... NULL` sets every
existing row's `parent_id` to `NULL`, not some inferred value) -- flat
tenancy is exactly the degenerate case of this model where every tenant is
a root with no children, so existing behavior is unchanged for any tenant
that never opts into a parent.

`core.tenant_ancestry` (`TenantAncestry` below) is the precomputed
ancestor/descendant closure this tree maintains -- see that class's
docstring for the invariants it holds. `parent_id` is the tree's source of
truth; `tenant_ancestry` is a derived index kept transactionally in sync
with it by `core/tenancy/service.py`'s `create_tenant()`/`move_tenant()`,
never written to directly by any other caller.
"""

from __future__ import annotations

import uuid

from core.tenancy.lifecycle import TenantStatus
from infra.db import (
    Base,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Mapped,
    String,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class Tenant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint("parent_id IS NULL OR parent_id != id", name="ck_tenants_parent_not_self"),
        {"schema": "core"},
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=TenantStatus.PENDING.value
    )
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=True
    )


class TenantAncestry(Base):
    """The precomputed closure of `Tenant.parent_id`: one row per
    (descendant, ancestor) pair, including a *self* row for every tenant
    (architecture research Phase A: "self ancestry (depth 0)" is the
    chosen invariant -- every tenant is its own ancestor at depth 0). This
    exists so "is tenant X an ancestor of tenant Y" and "what is the whole
    subtree/ancestor chain of tenant X" are O(1) indexed lookups, never a
    recursive CTE walked at read time -- a live recursive query in this
    position is the exact Postgres RLS/query-planner performance trap the
    architecture research flags (recursive-CTE-per-request does not use
    indexes well). No RLS policy reads this table in this phase; if a
    future phase adds hierarchy-aware RLS, it must populate a GUC from
    this table once per transaction (like `tenant_session_scope()`
    already does for `app.tenant_id`), never embed a recursive lookup
    inside a policy expression itself.

    Not itself Row-Level-Security-scoped, for the same reason
    `core.tenants` is not (module docstring above): it is part of the
    tenant *registry*'s own structure, not tenant-*owned* business data.

    Invariants (enforced by `core/tenancy/service.py`'s `create_tenant()`/
    `move_tenant()`, the only writers, plus the DB-level CHECK below):

    - Exactly one row per tenant has `tenant_id == ancestor_id`, and that
      row always has `depth == 0` (the self row).
    - Every other row has `tenant_id != ancestor_id` and `depth >= 1`.
    - `depth` is the number of parent-hops from `tenant_id` up to
      `ancestor_id`.
    - `parent_id` (on `Tenant`) is the single source of truth; this table
      is a derived index recomputed transactionally whenever `parent_id`
      changes. It is never hand-edited outside `core/tenancy/service.py`.
    - A tenant's own ancestry rows never outlive the tenant itself: both
      foreign keys use `ON DELETE CASCADE`, so deleting a `Tenant` row
      always removes its ancestry rows in the same statement, regardless
      of which code path performed the delete.

    Deliberately no surrogate `id`/`UUIDPrimaryKeyMixin` and no
    `TimestampMixin`, unlike every other table in this codebase: unlike a
    grant/assignment table (`core.role_permissions`, `core.membership_roles`)
    recording a distinct real-world event, a closure-table row has no
    identity beyond the `(tenant_id, ancestor_id)` pair it represents --
    a surrogate id would only add an unused column plus a redundant
    uniqueness constraint, and rows are replaced (deleted/reinserted) on
    a move, never updated in place, so a timestamp would never change.
    """

    __tablename__ = "tenant_ancestry"
    __table_args__ = (
        CheckConstraint("depth >= 0", name="ck_tenant_ancestry_depth_non_negative"),
        CheckConstraint(
            "(tenant_id = ancestor_id AND depth = 0) OR (tenant_id != ancestor_id AND depth > 0)",
            name="ck_tenant_ancestry_self_row_iff_depth_zero",
        ),
        Index("ix_tenant_ancestry_ancestor_id", "ancestor_id"),
        {"schema": "core"},
    )

    # ON DELETE CASCADE (not the default RESTRICT/NO ACTION): an ancestry
    # row has no meaning once either tenant it names no longer exists, so
    # deleting a `Tenant` row must always take its own ancestry rows with
    # it, in the same statement, regardless of which code path performed
    # the delete -- `purge_tenant()` or a raw `DELETE FROM core.tenants`.
    # This is deliberately different from `Tenant.parent_id`'s own FK
    # (plain RESTRICT), which is what blocks deleting a tenant that still
    # has a living child (`core/tenancy/service.py::purge_tenant()`'s
    # docstring) -- that invariant must NOT cascade.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id", ondelete="CASCADE"), primary_key=True
    )
    ancestor_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id", ondelete="CASCADE"), primary_key=True
    )
    depth: Mapped[int] = mapped_column(Integer, nullable=False)
