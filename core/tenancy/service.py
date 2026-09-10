"""Tenant CRUD and lifecycle operations (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.1; hierarchy operations added by architecture research: universal
multi-tenant tenancy, Phase A).

Tenant management is itself a platform-level operation, not scoped to "the
current tenant" -- a tenant cannot scope itself into existence, and
resolving a session's tenant requires reading the registry unscoped. Every
function here uses `infra.db.session_scope()` (untenanted), never
`tenant_session_scope()` -- `core.tenants` is not RLS-scoped (see
`core/tenancy/models.py`).

Hierarchy maintenance (`create_tenant()`'s `parent_id`, `move_tenant()`)
follows one rule throughout: `core.tenant_ancestry` is recomputed
transactionally, in the *same* `session_scope()` transaction as the
`Tenant`/`parent_id` write it derives from -- committed together,
rolled back together, by the same commit/rollback `session_scope()`
already performs. There is no separate step, no background job, and no
window in which one is visible without the other (this is what
"closure-table maintenance must never leave a partially updated hierarchy
visible" means concretely here). Concurrent structural changes to the
same tenant(s) are serialized with `infra.db.acquire_tenant_advisory_lock`
-- the same primitive `core/usage/service.py::consume_quota()` already
uses for its own atomic check-and-act sections -- keyed on each tenant
node's id under a shared `_HIERARCHY_LOCK_KEY`, acquired in a fixed
(sorted) order across every writer so two concurrent structural writes
touching overlapping nodes can never deadlock each other.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from core.tenancy.config import get_tenancy_config
from core.tenancy.errors import (
    TenantCycleError,
    TenantHierarchyDepthExceededError,
    TenantNotFoundError,
)
from core.tenancy.lifecycle import TenantStatus, validate_transition
from core.tenancy.models import Tenant, TenantAncestry
from infra.db import Session, acquire_tenant_advisory_lock, select, session_scope

# Advisory-lock key shared by every hierarchy-mutating operation
# (`create_tenant(parent_id=...)`, `move_tenant()`) -- see module
# docstring. A distinct string from any other module's advisory-lock use
# (e.g. `core/usage/service.py`'s quota key) so the two never collide.
_HIERARCHY_LOCK_KEY = "core.tenancy.hierarchy"


def _lock_hierarchy_nodes(session: Session, *tenant_ids: uuid.UUID | None) -> None:
    """Acquire the hierarchy advisory lock on every given tenant id, in a
    fixed (sorted) order -- so two concurrent operations that both need to
    lock the same pair of nodes (e.g. one moving A under B, another moving
    B under A) always request them in the same order and cannot deadlock
    each other. `None` ids (no parent) are skipped."""
    for tenant_id in sorted({t for t in tenant_ids if t is not None}, key=str):
        acquire_tenant_advisory_lock(session, tenant_id, _HIERARCHY_LOCK_KEY)


def find_tenants_by_name(name: str) -> list[Tenant]:
    """Every tenant whose `name` matches exactly, oldest first. `core.tenants`
    has no uniqueness constraint on `name` (a display name, not a slug), so
    this deliberately returns a list rather than pretending a single match
    is guaranteed -- a caller that needs "the" tenant of a given name (the
    first-tenant bootstrap, `api/tenant_bootstrap.py`) must treat more than
    one match as a conflict, never pick silently. Read-only, untenanted
    (the registry itself is not RLS-scoped, module docstring)."""
    with session_scope() as session:
        tenants = (
            session.execute(
                select(Tenant).where(Tenant.name == name).order_by(Tenant.created_at, Tenant.id)
            )
            .scalars()
            .all()
        )
        for tenant in tenants:
            session.expunge(tenant)
        return list(tenants)


def create_tenant(name: str, *, parent_id: uuid.UUID | None = None) -> Tenant:
    """Create a tenant. `parent_id=None` (the default) creates a root
    tenant -- the exact, unchanged behavior every existing caller of
    `create_tenant(name)` already gets. Passing `parent_id` additionally
    makes the new tenant a child of an existing one:

    - `parent_id` must reference a real tenant (`TenantNotFoundError`
      otherwise).
    - the new tenant's resulting depth (parent's depth + 1) must not
      exceed the configured guardrail
      (`TenantHierarchyDepthExceededError` otherwise,
      `core.tenancy.config.TenancyConfig.max_hierarchy_depth`).
    - `core.tenant_ancestry` is populated transactionally alongside the
      new row: a self row (depth 0), plus one row per ancestor the parent
      itself has, each one hop deeper (module docstring) -- so the whole
      operation is atomic, never a `Tenant` insert followed by a separate
      ancestry-population step.

    The hierarchy advisory lock is held on `parent_id` for the whole
    transaction, so a concurrent `move_tenant()` of that same parent
    cannot interleave with reading its ancestry here (module docstring).
    """
    with session_scope() as session:
        parent_ancestry: Sequence[TenantAncestry] = []
        if parent_id is not None:
            _lock_hierarchy_nodes(session, parent_id)
            parent = session.get(Tenant, parent_id)
            if parent is None:
                raise TenantNotFoundError(parent_id)
            parent_ancestry = (
                session.execute(select(TenantAncestry).where(TenantAncestry.tenant_id == parent_id))
                .scalars()
                .all()
            )

        tenant = Tenant(name=name, status=TenantStatus.PENDING.value, parent_id=parent_id)
        session.add(tenant)
        session.flush()

        session.add(TenantAncestry(tenant_id=tenant.id, ancestor_id=tenant.id, depth=0))

        if parent_id is not None:
            resulting_depth = max(row.depth for row in parent_ancestry) + 1
            max_depth = get_tenancy_config().max_hierarchy_depth
            if resulting_depth > max_depth:
                raise TenantHierarchyDepthExceededError(tenant.id, resulting_depth, max_depth)
            for row in parent_ancestry:
                session.add(
                    TenantAncestry(
                        tenant_id=tenant.id, ancestor_id=row.ancestor_id, depth=row.depth + 1
                    )
                )

        session.flush()
        session.refresh(tenant)
        session.expunge(tenant)
        return tenant


def move_tenant(tenant_id: uuid.UUID, new_parent_id: uuid.UUID | None) -> Tenant:
    """Move `tenant_id` -- and its whole subtree -- to become a child of
    `new_parent_id`, or a new root tenant if `new_parent_id` is `None`.

    Moves the *hierarchy relationship only*: `Tenant.parent_id` and
    `core.tenant_ancestry`. Never touches tenant-owned business data --
    every resource's own `tenant_id` is completely unaffected by a move
    (`core/tenancy/models.py` module docstring; ADR-0002). Authorization
    semantics are not expanded by this phase: moving a tenant does not,
    by itself, grant or revoke any RBAC permission for anyone
    (`core/tenancy/models.py` module docstring).

    Fails closed, before any row is written, if:

    - `tenant_id` or `new_parent_id` does not reference a real tenant
      (`TenantNotFoundError`);
    - the move would make `tenant_id` its own ancestor -- directly
      (`new_parent_id == tenant_id`) or transitively (`new_parent_id` is
      one of `tenant_id`'s own descendants) -- (`TenantCycleError`);
    - the resulting depth of any node in the moved subtree would exceed
      the configured guardrail (`TenantHierarchyDepthExceededError`).

    A no-op move (`new_parent_id` already equals the tenant's current
    parent) returns the tenant unchanged without rewriting any ancestry
    row.

    Concurrency: the hierarchy advisory lock is held on both `tenant_id`
    and `new_parent_id` (in sorted order, module docstring) for the whole
    transaction, so two concurrent moves touching overlapping nodes
    serialize instead of racing -- and the entire recompute (deleting the
    subtree's old bridge rows, inserting its new ones, updating
    `parent_id`) happens in that one transaction, so a reader never
    observes a half-moved hierarchy.
    """
    with session_scope() as session:
        _lock_hierarchy_nodes(session, tenant_id, new_parent_id)

        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)

        if new_parent_id is not None:
            new_parent = session.get(Tenant, new_parent_id)
            if new_parent is None:
                raise TenantNotFoundError(new_parent_id)

            # tenant_id is an ancestor of new_parent_id (or IS new_parent_id,
            # via the self row) iff moving tenant_id under new_parent_id
            # would make tenant_id its own ancestor.
            would_cycle = session.execute(
                select(TenantAncestry.tenant_id).where(
                    TenantAncestry.ancestor_id == tenant_id,
                    TenantAncestry.tenant_id == new_parent_id,
                )
            ).first()
            if would_cycle is not None:
                raise TenantCycleError(tenant_id, new_parent_id)

        if tenant.parent_id == new_parent_id:
            session.expunge(tenant)
            return tenant

        subtree = (
            session.execute(select(TenantAncestry).where(TenantAncestry.ancestor_id == tenant_id))
            .scalars()
            .all()
        )
        subtree_relative_depth = {row.tenant_id: row.depth for row in subtree}
        subtree_ids = set(subtree_relative_depth)

        new_parent_ancestry: Sequence[TenantAncestry] = []
        new_parent_depth_from_root = -1
        if new_parent_id is not None:
            new_parent_ancestry = (
                session.execute(
                    select(TenantAncestry).where(TenantAncestry.tenant_id == new_parent_id)
                )
                .scalars()
                .all()
            )
            new_parent_depth_from_root = max(row.depth for row in new_parent_ancestry)

        resulting_max_depth = new_parent_depth_from_root + 1 + max(subtree_relative_depth.values())
        max_depth = get_tenancy_config().max_hierarchy_depth
        if resulting_max_depth > max_depth:
            raise TenantHierarchyDepthExceededError(tenant_id, resulting_max_depth, max_depth)

        # Bridge rows: ancestry linking a subtree node to a *strict*
        # ancestor of tenant_id (an ancestor outside the subtree) -- these
        # are the only rows a move invalidates. Ancestry rows internal to
        # the subtree (between two of its own members) are unaffected: a
        # move changes the subtree's connection to the outside world, not
        # the relationships within it.
        bridge_rows = (
            session.execute(
                select(TenantAncestry).where(
                    TenantAncestry.tenant_id.in_(subtree_ids),
                    TenantAncestry.ancestor_id.notin_(subtree_ids),
                )
            )
            .scalars()
            .all()
        )
        for row in bridge_rows:
            session.delete(row)
        session.flush()

        for parent_ancestor_row in new_parent_ancestry:
            for node_id, dist_from_tenant in subtree_relative_depth.items():
                session.add(
                    TenantAncestry(
                        tenant_id=node_id,
                        ancestor_id=parent_ancestor_row.ancestor_id,
                        depth=parent_ancestor_row.depth + 1 + dist_from_tenant,
                    )
                )

        tenant.parent_id = new_parent_id
        session.flush()
        session.refresh(tenant)
        session.expunge(tenant)
        return tenant


def get_tenant(tenant_id: uuid.UUID) -> Tenant:
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)
        session.expunge(tenant)
        return tenant


def transition_tenant_status(tenant_id: uuid.UUID, target_status: TenantStatus) -> Tenant:
    """Move a tenant to `target_status`, only if that transition is on the
    allowed lifecycle graph (`core.tenancy.lifecycle`) from its *current*,
    freshly-read (not caller-supplied) status -- so a caller cannot bypass
    validation by racing a stale in-memory status past this check.
    """
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)
        current_status = TenantStatus(tenant.status)
        validate_transition(current_status, target_status)
        tenant.status = target_status.value
        session.flush()
        session.refresh(tenant)
        session.expunge(tenant)
        return tenant


def purge_tenant(tenant_id: uuid.UUID) -> None:
    """Hard-delete a tenant (docs/MULTI-TENANCY.md section 6: "purged
    (hard delete, compliance-driven, rare)"). Only permitted from
    `DELETED` -- the same lifecycle graph every other transition uses, so
    a tenant can never be purged without first being soft-deleted.

    A tenant with any living child (another tenant whose `parent_id`
    still points at this one) cannot be purged: `Tenant.parent_id`'s
    plain foreign key has no `ON DELETE CASCADE`, so PostgreSQL itself
    rejects the delete -- this phase deliberately blocks rather than
    silently cascades a hierarchy-wide delete (architecture research
    Part 20: "deleting a tenant with live children must ... block").
    Reparent or purge every child first.

    This tenant's *own* `core.tenant_ancestry` rows (its self row, plus
    one row per ancestor it has, if it is itself a child) do not need to
    be removed here first: `TenantAncestry`'s foreign keys use
    `ON DELETE CASCADE` (`core/tenancy/models.py`) specifically so that
    any delete of a `Tenant` row -- through this function or otherwise --
    always takes its ancestry rows with it in the same statement.
    """
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)
        current_status = TenantStatus(tenant.status)
        validate_transition(current_status, TenantStatus.PURGED)
        session.delete(tenant)
