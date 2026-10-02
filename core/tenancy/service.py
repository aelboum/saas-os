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
visible" means concretely here). Concurrent structural changes are
serialized with `infra.db.acquire_tenant_advisory_lock` -- the same
primitive `core/usage/service.py::consume_quota()` already uses for its
own atomic check-and-act sections -- in two layers: first one fixed,
hierarchy-wide lock (`_lock_hierarchy_globally()`, PRIV-03 Phase P9,
privacy re-audit finding RA-05) that every hierarchy writer takes before
reading any ancestry it validates against, because the cycle and depth
invariants are properties of the whole tree and two writers whose
per-node lock sets are disjoint could otherwise both validate against the
same pre-state and both commit (a real `parent_id` cycle); then the
per-node locks keyed on each tenant node's id under the shared
`_HIERARCHY_LOCK_KEY`, acquired in a fixed (sorted) order. Lifecycle is
part of the same transaction too: `move_tenant()` reads both ends of the
move with `lock_open_tenant()` (`core.tenants` row `FOR SHARE`), so a
closed tenant is never reparented or given a live child, and a closure
cannot commit between that check and the hierarchy write.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.tenancy.config import get_tenancy_config
from core.tenancy.errors import (
    InvalidTenantTransitionError,
    PlatformTenantNotConfiguredError,
    TenantClosedError,
    TenantCycleError,
    TenantHasDescendantsError,
    TenantHierarchyDepthExceededError,
    TenantInaccessibleError,
    TenantNotFoundError,
    TenantNotPurgingError,
    TenantPurgeIncompleteError,
)
from core.tenancy.lifecycle import (
    TenantStatus,
    is_accessible_to_principals,
    is_closed,
    validate_transition,
)
from core.tenancy.models import Tenant, TenantAncestry
from core.tenancy.purge_participants import TenantPurgeParticipantRegistry
from core.tenancy.purge_participants import default_registry as default_purge_participant_registry
from infra.db import (
    Session,
    acquire_tenant_advisory_lock,
    select,
    session_scope,
    tenant_session_scope,
)

# Advisory-lock key shared by every hierarchy-mutating operation
# (`create_tenant(parent_id=...)`, `move_tenant()`) -- see module
# docstring. A distinct string from any other module's advisory-lock use
# (e.g. `core/usage/service.py`'s quota key) so the two never collide.
_HIERARCHY_LOCK_KEY = "core.tenancy.hierarchy"

# The fixed sentinel every hierarchy writer locks first (PRIV-03 Phase P9,
# RA-05): the nil UUID is not a tenant id (`core.tenants.id` is always a
# random UUID4), so `(nil, _HIERARCHY_LOCK_KEY)` names exactly one
# transaction-scoped advisory lock shared by the whole tree -- taken through
# the existing `acquire_tenant_advisory_lock()` primitive, never a new one.
_HIERARCHY_GLOBAL_LOCK_ID = uuid.UUID(int=0)


def _lock_hierarchy_globally(session: Session) -> None:
    """Serialize this transaction against every other hierarchy writer
    (`create_tenant(parent_id=...)`, `move_tenant()`) for its whole
    duration. Must be acquired *before* any `core.tenant_ancestry` read a
    cycle or depth check depends on: the invariants are tree-wide, so a
    writer that only locked its own nodes could validate against a
    pre-state that a concurrent writer touching *other* nodes is about to
    invalidate (the disjoint-lock race the RA-05 audit reproduced). Held
    until COMMIT/ROLLBACK like every `pg_advisory_xact_lock`."""
    acquire_tenant_advisory_lock(session, _HIERARCHY_GLOBAL_LOCK_ID, _HIERARCHY_LOCK_KEY)


def _lock_hierarchy_nodes(session: Session, *tenant_ids: uuid.UUID | None) -> None:
    """Acquire the hierarchy advisory lock on every given tenant id, in a
    fixed (sorted) order -- so two concurrent operations that both need to
    lock the same pair of nodes (e.g. one moving A under B, another moving
    B under A) always request them in the same order and cannot deadlock
    each other. `None` ids (no parent) are skipped. Since PRIV-03 P9 the
    hierarchy-wide lock (`_lock_hierarchy_globally()`) is the correctness
    mechanism and is always taken first; these per-node locks remain as
    the documented, finer-grained marker of which nodes a writer touches."""
    for tenant_id in sorted({t for t in tenant_ids if t is not None}, key=str):
        acquire_tenant_advisory_lock(session, tenant_id, _HIERARCHY_LOCK_KEY)


def get_ancestor_ids(tenant_id: uuid.UUID) -> frozenset[uuid.UUID]:
    """Every ancestor of `tenant_id`, INCLUDING `tenant_id` itself (the
    self-ancestry row every tenant has, `TenantAncestry`) -- read directly
    from the precomputed closure table, never a recursive query. This is
    the published read `core/rbac`'s scoped-role authorization
    (architecture research Phase B, `core/rbac/authorization.py::can()`)
    evaluates a `SUBTREE`-scoped role against, so that module never reads
    `core.tenant_ancestry` directly (docs/DATA-ARCHITECTURE.md section 3:
    cross-module reads go through the owning module's published
    interface, not another module's ORM table).

    Read-only, untenanted (`core.tenant_ancestry` is not RLS-scoped, see
    `core/tenancy/models.py`). Returns an empty `frozenset` for a
    `tenant_id` with no ancestry rows (an unknown tenant) rather than
    raising -- a caller that needs existence validated calls `get_tenant()`
    first (`can()` already does, before this).
    """
    with session_scope() as session:
        ancestor_ids = (
            session.execute(
                select(TenantAncestry.ancestor_id).where(TenantAncestry.tenant_id == tenant_id)
            )
            .scalars()
            .all()
        )
        return frozenset(ancestor_ids)


def lock_ancestor_ids(session: Session, tenant_id: uuid.UUID) -> frozenset[uuid.UUID]:
    """`get_ancestor_ids()`, read inside the caller's own transaction with
    the `core.tenant_ancestry` rows held `FOR SHARE` (Foundation Authority
    & Evidence, ADR-0031). These row locks alone do NOT serialize a
    re-parenting: moving a root ancestor inserts new ancestry rows for
    `tenant_id` and deletes none. What serializes it is `move_tenant()`
    locking every moved subtree tenant's `core.tenants` row `FOR NO KEY
    UPDATE` before touching ancestry, against the `FOR SHARE` lock
    `can()` holds on its target tenant from the start of the decision:
    either the move committed first and this read (a later statement)
    sees the new chain, or the move waits until the decision's
    transaction (the protected mutation's own) commits. The row locks here
    additionally make a move that deletes these rows wait.
    `core.tenant_ancestry` is not RLS-scoped, so this works inside a
    tenant-scoped transaction too."""
    ancestor_ids = (
        session.execute(
            select(TenantAncestry.ancestor_id)
            .where(TenantAncestry.tenant_id == tenant_id)
            .with_for_update(read=True)
        )
        .scalars()
        .all()
    )
    return frozenset(ancestor_ids)


def get_ancestor_chain(tenant_id: uuid.UUID) -> list[uuid.UUID]:
    """Every STRICT ancestor of `tenant_id` (excluding `tenant_id` itself),
    ordered nearest-first (`depth` ascending) -- architecture research
    Phase H's own requirement: "billing-owner resolution" needs the
    *nearest applicable ancestor*, which `get_ancestor_ids()`'s unordered
    `frozenset` cannot express (that function's own consumer,
    `core/rbac/authorization.py::can()`, never needed an order -- any
    ancestor with a matching `SUBTREE` grant is enough). One indexed
    `ORDER BY depth` query over the precomputed closure table, never a
    recursive query (module docstring; `TenantAncestry`'s own docstring).

    Read-only, untenanted, mirroring `get_ancestor_ids()` exactly. Returns
    an empty list for a root tenant (no ancestors) or an unknown
    `tenant_id` (no ancestry rows) -- a caller that needs existence
    validated calls `get_tenant()` first.
    """
    with session_scope() as session:
        ancestor_ids = (
            session.execute(
                select(TenantAncestry.ancestor_id)
                .where(TenantAncestry.tenant_id == tenant_id, TenantAncestry.depth > 0)
                .order_by(TenantAncestry.depth.asc())
            )
            .scalars()
            .all()
        )
        return list(ancestor_ids)


def get_descendant_ids(tenant_id: uuid.UUID) -> frozenset[uuid.UUID]:
    """Every descendant of `tenant_id`, INCLUDING `tenant_id` itself (the
    self-ancestry row every tenant has) -- the reverse-direction read of
    `get_ancestor_ids()`, over the identical closure table (architecture
    research Phase H: "introduce hierarchy-aware usage aggregation using
    TenantAncestry"). One indexed query
    (`ix_tenant_ancestry_ancestor_id`), never a recursive one.

    Read-only, untenanted, unordered (mirrors `get_ancestor_ids()`'s own
    shape). Structural data only -- this function grants no authorization
    and implies no reporting-visibility permission by itself; a caller
    that exposes descendant data to an end user remains responsible for
    its own authorization check (this module's own docstring: hierarchy
    "does not grant any authorization by itself").
    """
    with session_scope() as session:
        descendant_ids = (
            session.execute(
                select(TenantAncestry.tenant_id).where(TenantAncestry.ancestor_id == tenant_id)
            )
            .scalars()
            .all()
        )
        return frozenset(descendant_ids)


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
      otherwise) whose lifecycle is still open (`TenantClosedError`
      otherwise, PRIV-03 Phase P2): a new child can never be attached
      beneath a `DELETED`/`PURGING`/`PURGED` parent -- which is also what
      keeps "a tenant with descendants cannot be purged" a stable
      invariant while a parent is being wound down, rather than a race.
    - the new tenant's resulting depth (parent's depth + 1) must not
      exceed the configured guardrail
      (`TenantHierarchyDepthExceededError` otherwise,
      `core.tenancy.config.TenancyConfig.max_hierarchy_depth`).
    - `core.tenant_ancestry` is populated transactionally alongside the
      new row: a self row (depth 0), plus one row per ancestor the parent
      itself has, each one hop deeper (module docstring) -- so the whole
      operation is atomic, never a `Tenant` insert followed by a separate
      ancestry-population step.

    The hierarchy-wide advisory lock (PRIV-03 P9, RA-05) and then the
    per-node lock on `parent_id` are held for the whole transaction, so no
    concurrent `move_tenant()` -- of this parent *or of any of its
    ancestors* -- can interleave with reading the parent's ancestry here
    (module docstring): the child's closure rows are always derived from
    a hierarchy no other writer is changing underneath it.
    """
    with session_scope() as session:
        parent_ancestry: Sequence[TenantAncestry] = []
        if parent_id is not None:
            _lock_hierarchy_globally(session)
            _lock_hierarchy_nodes(session, parent_id)
            parent = session.get(Tenant, parent_id)
            if parent is None:
                raise TenantNotFoundError(parent_id)
            parent_status = TenantStatus(parent.status)
            if is_closed(parent_status):
                raise TenantClosedError(parent_id, parent_status)
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
    - `tenant_id` or `new_parent_id` is closed -- `DELETED`/`PURGING`/
      `PURGED` (`TenantClosedError`, PRIV-03 Phase P9, privacy re-audit
      finding RA-05): a closed tenant's hierarchy is part of its retained
      tombstone and is never reparented, and a closed tenant never gains
      a live child (which would also defeat `purge_tenant()`'s "no live
      child" precondition). `PENDING`/`ACTIVE`/`SUSPENDED` are open, the
      unchanged P2 mutation policy (`core.tenancy.lifecycle.CLOSED_STATUSES`);
    - the move would make `tenant_id` its own ancestor -- directly
      (`new_parent_id == tenant_id`) or transitively (`new_parent_id` is
      one of `tenant_id`'s own descendants) -- (`TenantCycleError`);
    - the resulting depth of any node in the moved subtree would exceed
      the configured guardrail (`TenantHierarchyDepthExceededError`).

    A no-op move (`new_parent_id` already equals the tenant's current
    parent) returns the tenant unchanged without rewriting any ancestry
    row (still lifecycle-checked: a closed tenant is never touched, even
    to be told it is already where it is).

    Concurrency (lock order, all inside this one transaction): first the
    hierarchy-wide advisory lock (`_lock_hierarchy_globally()`), so every
    hierarchy writer -- another move of *any* node, a `create_tenant()`
    under *any* parent -- serializes with this one and the cycle/depth
    checks below always run against a hierarchy nobody else is changing;
    then the per-node advisory locks on `tenant_id` and `new_parent_id`
    (sorted order, module docstring); then both tenant rows `FOR SHARE`
    via `lock_open_tenant()`, so `transition_tenant_status()`/
    `purge_tenant()` (`FOR UPDATE`) either committed a closure before this
    read -- refused -- or wait until this move commits: a closure can
    never land between the lifecycle check and the hierarchy write. Then,
    before any ancestry row changes, every `core.tenants` row in the moved
    subtree `FOR NO KEY UPDATE` (`_lock_subtree_tenant_rows()`), which
    serializes the move against every in-flight `core.rbac.can()` decision
    for a tenant whose ancestor chain it changes -- including when the
    moved tenant is a root and the move only inserts ancestry rows. The
    entire recompute (deleting the subtree's old bridge rows, inserting
    its new ones, updating `parent_id`) happens in that one transaction,
    so a reader never observes a half-moved hierarchy.
    """
    with session_scope() as session:
        _lock_hierarchy_globally(session)
        _lock_hierarchy_nodes(session, tenant_id, new_parent_id)

        tenant = lock_open_tenant(session, tenant_id)

        if new_parent_id is not None:
            lock_open_tenant(session, new_parent_id)

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
        _lock_subtree_tenant_rows(session, subtree_relative_depth)

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


def _lock_subtree_tenant_rows(
    session: Session, subtree_relative_depth: dict[uuid.UUID, int]
) -> None:
    """Lock every `core.tenants` row in the subtree being moved `FOR NO KEY
    UPDATE` (Foundation Authority & Evidence, ADR-0031), before any ancestry
    row is deleted or inserted and before `parent_id` changes.

    Every `core.rbac.can()` decision takes its *target* tenant's row
    `FOR SHARE` first and holds it until its transaction (a protected
    mutation's own) ends, and a move changes the effective ancestor chain of
    exactly the tenants in its subtree. So this lock serializes a
    re-parenting against every in-flight decision whose ancestry it would
    change: a decision that locked first makes the move wait until it
    commits; a move that locked first makes the decision's target lock wait
    until the move commits, after which its ancestry reads (new statements,
    READ COMMITTED) see the new chain. This includes moving a *root*
    ancestor, where the move only inserts ancestry rows and deletes none, so
    the `core.tenant_ancestry` row locks a decision holds
    (`lock_ancestor_ids()`) cannot by themselves make it wait.

    Order: deepest first, then by id. A decision locks its target, then
    (possibly) that target's ancestors -- all shallower than the target --
    so a move blocked on a decision's target never already holds one of
    that decision's ancestors: the order cannot form a cycle with any
    decision. One statement per row keeps the acquisition order exact."""
    for node_id in sorted(
        subtree_relative_depth, key=lambda n: (-subtree_relative_depth[n], str(n))
    ):
        session.execute(
            select(Tenant.id).where(Tenant.id == node_id).with_for_update(key_share=True)
        )


def get_tenant(tenant_id: uuid.UUID) -> Tenant:
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)
        session.expunge(tenant)
        return tenant


def require_open_tenant(tenant_id: uuid.UUID) -> Tenant:
    """The lifecycle fence every Core mutation entry point calls before
    writing a *new* tenant-owned row or making an authority-expanding
    change (PRIV-03 Phase P2): `get_tenant()`'s existing existence check
    (`TenantNotFoundError`), plus `TenantClosedError` when the tenant's
    freshly-read status is one of `core.tenancy.lifecycle.CLOSED_STATUSES`
    (`DELETED`/`PURGING`/`PURGED`). Same call shape as the `get_tenant()`
    pre-check `core/rbac/service.py` already performed at its own create
    sites, so it drops in where that was. Read-only paths and
    authority-reducing mutations (revoke/disable/suspend/remove/cancel)
    never call this -- a closed tenant must remain windable-down."""
    tenant = get_tenant(tenant_id)
    status = TenantStatus(tenant.status)
    if is_closed(status):
        raise TenantClosedError(tenant_id, status)
    return tenant


def get_platform_tenant_id() -> uuid.UUID:
    """The deployment's designated platform tenant id (`PLATFORM_TENANT_ID`,
    `core/tenancy/config.py`; docs/ADR/0029-commercial-parties-and-
    billing-relationships.md, Decision 0.2). Configuration only -- no
    database read. Raises `PlatformTenantNotConfiguredError` when no
    platform tenant is designated; never falls back to any other tenant.
    """
    platform_tenant_id = get_tenancy_config().platform_tenant_id
    if platform_tenant_id is None:
        raise PlatformTenantNotConfiguredError()
    return platform_tenant_id


def require_platform_tenant() -> Tenant:
    """`get_platform_tenant_id()` plus `require_open_tenant()` on it: the
    designated platform tenant must actually exist (`TenantNotFoundError`
    otherwise -- a stale or mistyped `PLATFORM_TENANT_ID` fails closed) and
    must not be closed (`TenantClosedError`). The platform tenant is an
    ordinary tenant; this function grants it no authority of any kind --
    authorization over it is evaluated by `core.rbac.can()` exactly as for
    every other tenant."""
    return require_open_tenant(get_platform_tenant_id())


def lock_open_tenant(session: Session, tenant_id: uuid.UUID) -> Tenant:
    """The *in-transaction* lifecycle fence (PRIV-03 Phase P5): the same
    check as `require_open_tenant()`, but performed inside the caller's own
    transaction with the `core.tenants` row read `FOR SHARE`. Because
    `transition_tenant_status()` and `purge_tenant()` take that row
    `FOR UPDATE`, a mutation that calls this first is serialized against
    any concurrent lifecycle transition: either the transition commits
    first and this raises `TenantClosedError`, or this call holds the
    share lock and the transition waits until the mutation commits -- a
    row can never be created for a tenant that is, in the same instant,
    becoming closed (the create-vs-PURGING race `require_open_tenant()`'s
    unlocked pre-check leaves open). Concurrent mutations on the same
    tenant share the lock and do not block each other. `core.tenants` is
    not RLS-scoped, so this works inside a `tenant_session_scope()` too.

    Used by the AI Control Plane's creators and state transitions; Core's
    own P2 creators keep the unlocked pre-check (their rows are emptied by
    the purge, so a stray row is harmless there -- AI artifacts are
    retained, so for them the window itself must be closed)."""
    tenant = session.get(Tenant, tenant_id, with_for_update={"read": True})
    if tenant is None:
        raise TenantNotFoundError(tenant_id)
    status = TenantStatus(tenant.status)
    if is_closed(status):
        raise TenantClosedError(tenant_id, status)
    return tenant


def lock_accessible_tenant(session: Session, tenant_id: uuid.UUID) -> Tenant:
    """The in-transaction *tenant-principal* lifecycle fence (PRIV-03 Phase
    P8, privacy re-audit finding RA-04): the same `core.tenants` row read
    `FOR SHARE` inside the caller's own transaction as `lock_open_tenant()`,
    but against the wider `PRINCIPAL_INACCESSIBLE_STATUSES` set -- raises
    `TenantInaccessibleError` for `SUSPENDED`, `DELETED`, `PURGING` and
    `PURGED`, `TenantNotFoundError` for a missing tenant, and otherwise
    returns the row (`PENDING`/`ACTIVE`). Used by the authorization
    chokepoints (`core/rbac/authorization.py::can()` and its allow paths)
    so a decision about a tenant's own principals is serialized against
    `transition_tenant_status()`/`purge_tenant()` (`FOR UPDATE`): either a
    transition into an inaccessible state committed first and this read
    sees it, or the share lock is held first and the transition waits
    until the decision commits -- a closure can never commit *between* the
    lifecycle check and the authorization result. Concurrent decisions
    share the lock and never block each other. Not a mutation guard:
    `require_open_tenant()`/`lock_open_tenant()` remain the fences for
    tenant-owned writes, and they keep treating `SUSPENDED` as open."""
    tenant = session.get(Tenant, tenant_id, with_for_update={"read": True})
    if tenant is None:
        raise TenantNotFoundError(tenant_id)
    status = TenantStatus(tenant.status)
    if not is_accessible_to_principals(status):
        raise TenantInaccessibleError(tenant_id, status)
    return tenant


@contextmanager
def tenant_job_session(tenant_id: uuid.UUID) -> Iterator[Session]:
    """F-09 (platform readiness audit): the shared, reusable tenant-
    lifecycle fence a *background-job handler* processing `tenant_id`-
    owned data must apply -- the same two-phase pattern
    `core/webhooks/service.py::_deliver_webhook()` implemented ad hoc
    before this existed (PRIV-03 Phase P7, privacy re-audit RA-03), now
    factored into one call so a future tenant-aware job handler cannot
    silently omit it.

    Composes `require_open_tenant()` and `lock_open_tenant()` -- both
    unchanged, called exactly as `_deliver_webhook()` already called them
    -- never reimplements their locking; this function's only job is
    getting the *order* and *scope* right, every time:

    1. An unlocked pre-check (`require_open_tenant()`) *before* opening
       any session -- the fast, common-case rejection, before any I/O for
       the job's own tenant-owned data.
    2. `tenant_session_scope(tenant_id)` opened.
    3. `lock_open_tenant()` re-checked *inside* that same transaction,
       `core.tenants` read `FOR SHARE` -- serialized against a concurrent
       `transition_tenant_status()`/`purge_tenant()`'s own `FOR UPDATE`,
       closing the window a job's own queue latency, retries, and worker
       downtime leave open between "tenant was open when this job was
       enqueued" and "tenant might have since closed."

    Raises `TenantClosedError`/`TenantNotFoundError` from either phase --
    exactly as if the caller had called `require_open_tenant()`/
    `lock_open_tenant()` itself. Deliberately does *not* catch either: what
    "fenced out" should mean (drop silently and log, retry, re-raise) is a
    per-handler decision this shared primitive has no business making for
    every tenant-aware job in the system (avoiding exactly the "global job
    policy applied incorrectly to a non-tenant job" this phase's own
    scope explicitly warns against) -- callers keep their own
    `except TenantClosedError: ...` around this context manager, the same
    shape `_deliver_webhook()` already used.

    Only ever call this from a job handler that is itself tenant-owned
    (carries a real `tenant_id` in its `TenantJobPayload`) -- this
    function has no meaning for, and must never be applied to, a platform-
    level/cross-tenant job.

    Deliberately placed in `core.tenancy` (Core), not `infra.jobs`
    (Infrastructure): this fence needs `Tenant`'s own lifecycle state and
    `lock_open_tenant()`'s own row lock, both Core concepts
    `infra.jobs` structurally must not depend on (`docs/ARCHITECTURE.md`
    section 2 -- "Infrastructure does not depend on Core", an enforced
    import-linter contract, `tests/architecture/test_layer_boundaries.py`)
    -- `infra.jobs.TenantJobPayload` stays exactly as tenant-agnostic as
    it already was (a bare `tenant_id: str`, no tenancy semantics), and
    this fence lives with the Core module that already owns every
    primitive it composes.
    """
    require_open_tenant(tenant_id)
    with tenant_session_scope(tenant_id) as session:
        lock_open_tenant(session, tenant_id)
        yield session


# --- Lifecycle audit evidence (PRIV-03 Phase P4) ---------------------------
#
# Four events, one per genuine lifecycle boundary, written through the
# existing `core.audit_log.record()` -- never a second event mechanism:
#
#   tenant.delete_requested  -- `transition_tenant_status(..., DELETED)` committed
#   tenant.purge_started     -- `purge_tenant()` holds the tenant in PURGING and
#                               is about to run the purge sequence
#   tenant.purge_completed   -- the PURGING -> PURGED tombstone write committed
#   tenant.purge_failed      -- a purge attempt raised; the tenant stays PURGING
#
# Ordering is the atomicity model: `record()` opens its own transaction (it
# takes no session), so an event can only be written *after* the lifecycle
# transition it describes has committed, never before and never inside it.
# That makes false evidence impossible (no "completed" without a committed
# PURGED; no "started" without a committed PURGING) at the price of a narrow
# window in which a crash between the commit and the audit write loses the
# event -- a missing record, never a misleading one. Metadata is fixed-shape
# and opaque: lifecycle statuses, pass/row *counts*, an exception *class
# name*, and a bounded failure class -- never a tenant name, an email, a
# credential, an exception message, or row contents.

_ACTION_DELETE_REQUESTED = "tenant.delete_requested"
_ACTION_PURGE_STARTED = "tenant.purge_started"
_ACTION_PURGE_COMPLETED = "tenant.purge_completed"
_ACTION_PURGE_FAILED = "tenant.purge_failed"
_LIFECYCLE_RESOURCE_TYPE = "tenant"

# The only failure classifications a `tenant.purge_failed` event may carry
# -- a closed vocabulary, so the audit record can never become a channel
# for arbitrary text.
_FAILURE_STEP_ERROR = "step_error"
_FAILURE_INCOMPLETE = "incomplete_after_passes"
_FAILURE_TRANSITION_REJECTED = "transition_rejected"
# RA-12-2: a registered core.tenancy.purge_participants.TenantPurgeParticipant
# raised. Distinct from _FAILURE_STEP_ERROR (a Core-owned PURGE_STEPS
# failure) so the audit trail can tell "Core's own purge broke" apart from
# "a Product's own purge participant broke" without ever naming the
# Product or echoing its exception's message.
_FAILURE_PARTICIPANT_ERROR = "participant_error"
# RA-12-7: the Redis dead-letter cleanup step (below) raised -- e.g. Redis
# unreachable/timed out. Distinct from every other class above so the
# audit trail can tell "Redis was unavailable" apart from a Core/Product
# data failure without ever echoing the underlying exception's message.
_FAILURE_REDIS_CLEANUP_ERROR = "redis_cleanup_error"
_STEP_FINAL_TRANSITION = "final_transition"
# RA-12-7: named so a failure during the Redis dead-letter cleanup step is
# classified by step like every other named step, run once, after every
# PURGE_STEPS pass and every registered participant has already
# succeeded, immediately before the final PURGED transition.
_STEP_REDIS_DEAD_LETTERS = "redis_dead_letters"
# RA-12-2: progress["step"] is set to this prefix plus the participant's
# own `name` immediately before calling it, so a failure names exactly
# which registered participant broke (bounded: `name` is a short, reviewed
# identifier a Product itself provides, never customer content -- see
# `TenantPurgeParticipant.name`'s own docstring).
_PARTICIPANT_STEP_PREFIX = "participant:"
# PRIV-03 P6 (RA-02): the pre-pass support-access revocation, named so a
# failure there is classified by step like every PURGE_STEPS entry.
_STEP_SUPPORT_ACCESS = "support_access"


def _purge_completed_metadata(
    *,
    passes: int,
    deleted: dict[str, int],
    retained_service_accounts: int,
    retained_delegation_grants: int,
    participants_run: int,
    dead_letter_entries_purged: int,
) -> dict[str, object]:
    """The fixed-shape metadata of a `tenant.purge_completed` event: the
    lifecycle transition, the pass count, one `deleted_<step>` *count* per
    `PURGE_STEPS` entry, the sizes of the retained sets, (RA-12-2) how
    many registered `TenantPurgeParticipant`s ran, and (RA-12-7) how many
    `arq:dead-letter` entries this call removed -- never their names,
    which Product registered them, or a dead-letter entry's own contents.
    Flat on purpose -- `core.audit_log.metadata.validate_metadata()`
    rejects any nested key that looks like a credential (the step name
    `authorization` would), and this shape is asserted against that
    contract by tests/core/tenancy/test_lifecycle_audit_metadata_unit.py.
    Counts only: never row contents, never the retained ids."""
    metadata: dict[str, object] = {
        "from_status": TenantStatus.PURGING.value,
        "to_status": TenantStatus.PURGED.value,
        "passes": passes,
        "deleted_total": sum(deleted.values()),
        "retained_service_accounts": retained_service_accounts,
        "retained_delegation_grants": retained_delegation_grants,
        "participants_run": participants_run,
        "dead_letter_entries_purged": dead_letter_entries_purged,
    }
    for step in PURGE_STEPS:
        metadata[f"deleted_{step}"] = deleted.get(step, 0)
    return metadata


def _record_lifecycle_event(
    tenant_id: uuid.UUID,
    *,
    action: str,
    outcome: AuditOutcome,
    actor_user_id: uuid.UUID | None,
    metadata: dict[str, object],
) -> None:
    """Existing actor model, unchanged: a caller that has a real user
    passes it (`ActorType.USER`); a purge invoked with no actor is recorded
    as the existing `ActorType.SYSTEM` -- "a platform-internal actor acting
    within a tenant", exactly how `core/feature_flags`, `core/billing` and
    `core/webhooks` already attribute their own actor-less mutations. No
    new identity is manufactured and no authority is implied by it."""
    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=_LIFECYCLE_RESOURCE_TYPE,
        resource_id=str(tenant_id),
        outcome=outcome,
        metadata=metadata,
    )


def transition_tenant_status(
    tenant_id: uuid.UUID, target_status: TenantStatus, *, actor_user_id: uuid.UUID | None = None
) -> Tenant:
    """Move a tenant to `target_status`, only if that transition is on the
    allowed lifecycle graph (`core.tenancy.lifecycle`) from its *current*,
    freshly-read (not caller-supplied) status -- so a caller cannot bypass
    validation by racing a stale in-memory status past this check.

    PRIV-03 Phase P4: a committed transition into `DELETED` -- the entry
    into the deletion workflow -- is followed by one
    `tenant.delete_requested` audit event (opaque tenant id only, plus the
    from/to statuses the transaction itself observed). `actor_user_id` is
    the optional real actor to attribute it to; absent, the existing
    `SYSTEM` actor is used (see `_record_lifecycle_event`). No other
    transition is audited by this function.

    The row is read `FOR UPDATE` (PRIV-03 Phase P2), so two concurrent
    transitions of the same tenant serialize on the row: the second one
    re-reads the status the first one committed and is validated against
    *that*, never against a stale pre-commit read -- the same row-lock
    discipline `core/identity/service.py::accept_invitation()` already
    uses. This is what makes `PURGING`/`PURGED` a reliable fence rather
    than a best-effort one: once a transition into a closed state commits,
    no in-flight transition can overwrite it with a stale `ACTIVE`.
    """
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id, with_for_update=True)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)
        current_status = TenantStatus(tenant.status)
        validate_transition(current_status, target_status)
        tenant.status = target_status.value
        session.flush()
        session.refresh(tenant)
        session.expunge(tenant)

    # After commit only (module comment above): the event describes a
    # transition that has already happened, derived from the values this
    # transaction validated -- never from the caller.
    if target_status is TenantStatus.DELETED:
        _record_lifecycle_event(
            tenant_id,
            action=_ACTION_DELETE_REQUESTED,
            outcome=AuditOutcome.SUCCESS,
            actor_user_id=actor_user_id,
            metadata={"from_status": current_status.value, "to_status": target_status.value},
        )
    return tenant


def set_tenant_billing_inheritance(tenant_id: uuid.UUID, inherits_billing: bool) -> Tenant:
    """Set `tenant_id`'s own `Tenant.inherits_billing` flag (architecture
    research Phase H). Deliberately ungated and unaudited, mirroring
    `transition_tenant_status()`'s own precedent immediately above --
    every `core/tenancy` mutation trusts its caller (Phase 8's ingress
    layer authorizes), and no sibling tenancy mutation in this module logs
    to `core.audit_log` either. Idempotent: setting the same value twice
    is a no-op write, not an error.

    Structural configuration only -- flipping this flag changes nothing
    about `tenant_id`'s own authorization, membership, or role state; it
    only changes what `core/billing/service.py::resolve_billing_owner()`
    computes on its next call (never cached -- that function's own
    docstring). A currently-invalid combination (e.g. setting `True` on a
    root tenant with no parent) is accepted here without error: validity
    is `resolve_billing_owner()`'s concern, evaluated fresh against the
    hierarchy at resolution time, because the hierarchy itself (not just
    this flag) can change independently later (`move_tenant()`) and must
    re-validate on every call regardless of when this flag was last set.
    """
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)
        if tenant.inherits_billing != inherits_billing:
            tenant.inherits_billing = inherits_billing
            session.flush()
        session.refresh(tenant)
        session.expunge(tenant)
        return tenant


def require_purging_tenant(tenant_id: uuid.UUID) -> Tenant:
    """The guard every module-owned `purge_tenant_*()` step calls first
    (PRIV-03 Phase P3): the tenant must exist (`TenantNotFoundError`) and
    be in the purge phase -- `PURGING`, or the terminal `PURGED` (where a
    late-running or retried step finds nothing left and is a harmless
    no-op). Any other status raises `TenantNotPurgingError`: the per-module
    purge steps are destructive and must never run against an open or a
    merely soft-deleted tenant, so the lifecycle is checked at *every*
    step, not just once at the orchestrator's entry."""
    tenant = get_tenant(tenant_id)
    status = TenantStatus(tenant.status)
    if status not in (TenantStatus.PURGING, TenantStatus.PURGED):
        raise TenantNotPurgingError(tenant_id, status)
    return tenant


@dataclass(frozen=True)
class TenantPurgeResult:
    """Outcome of one `purge_tenant()` call. `deleted` is keyed by step
    name in `PURGE_STEPS` order and reports rows removed in the *first*
    pass (later passes are verification passes that must remove nothing).
    `retained_*` name the rows deliberately kept as revoked/disabled
    evidence linkage. `already_purged` is `True` when the tenant was
    already `PURGED` on entry and nothing was done."""

    tenant_id: uuid.UUID
    deleted: dict[str, int]
    retained_delegation_grant_ids: frozenset[uuid.UUID]
    retained_service_account_ids: frozenset[uuid.UUID]
    passes: int
    already_purged: bool = False
    # PRIV-03 P6 (RA-02): support-access grants this call revoked before
    # purging -- rows retained as evidence, authority ended.
    revoked_support_access_ids: frozenset[uuid.UUID] = frozenset()
    # RA-12-2: the `name` of every registered TenantPurgeParticipant that
    # ran successfully during this call, in registration order -- never
    # anything about what a participant actually deleted.
    participant_names: tuple[str, ...] = ()
    # RA-12-7: how many `arq:dead-letter` entries naming this tenant were
    # removed by this call's Redis cleanup step -- a bounded count only,
    # never an entry's own contents. Not part of `deleted` above, which is
    # reserved for PostgreSQL `PURGE_STEPS` counts.
    dead_letter_entries_purged: int = 0

    @property
    def total_deleted(self) -> int:
        return sum(self.deleted.values())


# The fixed purge sequence (PRIV-03 Phase P3) -- derived from the schema's
# own foreign keys at Alembic head f3a9c85e1b64, not discovered at runtime.
# Each name is a module-owned operation; the order is the only order in
# which every `NO ACTION` FK among tenant-owned tables is satisfied:
#
#   api_keys              -> (tenant_id,user_id)->memberships, (tenant_id,sa)->service_accounts
#   notifications         -> (tenant_id,recipient)->memberships
#   webhooks              replay_records -> subscriptions
#   authorization         membership_roles/role_permissions/service_account_roles
#                         -> roles, memberships, service_accounts; deny + delegation
#                         grants; then roles
#   invitations           (PII: invited_email)
#   service_accounts      after api_keys + service_account_roles + delegation grants
#   memberships           after api_keys + notifications + membership_roles
#   feature_flag_overrides
#   idempotency_records
#
# Retained, never deleted here: core.audit_log, core.billing_subscriptions,
# core.support_access_requests (PRIV-03 P6: every live grant is *revoked*
# before the first pass -- `revoke_tenant_support_access()` -- so retained
# evidence lends no authority; still not a purge step), core.tenant_ancestry,
# the tenant row itself (tombstone). Global, never touched: users, external_identities, sessions,
# login_transactions, permissions, billing_plans, feature_flags. Deferred to
# later phases: core.usage_events (no rollup/retention decision exists yet),
# control_plane.* / self_learning.* (P5 owns AI drain and disposition).
PURGE_STEPS: tuple[str, ...] = (
    "api_keys",
    "notifications",
    "webhooks",
    "authorization",
    "invitations",
    "service_accounts",
    "memberships",
    "feature_flag_overrides",
    "idempotency_records",
)

# Pass 1 purges; every later pass is a verification pass that must remove
# nothing. A second pass removing rows means something re-created data
# mid-purge (impossible past the P2 fence, so it is treated as a fault);
# a third is the last chance before failing closed.
_MAX_PURGE_PASSES = 3


def _run_purge_pass(
    tenant_id: uuid.UUID, progress: dict[str, str]
) -> tuple[dict[str, int], frozenset[uuid.UUID], frozenset[uuid.UUID]]:
    """One full pass over `PURGE_STEPS`, in order. `progress["step"]` is
    set to each step's name immediately before it runs, so a failure can
    be classified by step (P4 `tenant.purge_failed`) without wrapping or
    re-raising the step's own exception. Module imports are
    deferred to call time on purpose: every one of these modules imports
    `core.tenancy` at module scope (for `require_open_tenant`), so a
    module-scope import here would be a load-time cycle -- the same
    deferred-import technique `core/identity/service.py::create_invitation()`
    already documents."""
    from core.api_keys.service import purge_tenant_api_keys
    from core.feature_flags.service import purge_tenant_feature_flag_overrides
    from core.idempotency.service import purge_tenant_idempotency_records
    from core.identity.service import (
        purge_tenant_invitations,
        purge_tenant_memberships,
        purge_tenant_service_accounts,
    )
    from core.notifications.service import purge_tenant_notifications
    from core.rbac.service import purge_tenant_authorization
    from core.webhooks.service import purge_tenant_webhooks

    deleted: dict[str, int] = {}
    progress["step"] = "api_keys"
    deleted["api_keys"] = purge_tenant_api_keys(tenant_id)
    progress["step"] = "notifications"
    deleted["notifications"] = purge_tenant_notifications(tenant_id)
    progress["step"] = "webhooks"
    deleted["webhooks"] = purge_tenant_webhooks(tenant_id)
    progress["step"] = "authorization"
    authorization = purge_tenant_authorization(tenant_id)
    deleted["authorization"] = authorization.total_deleted
    progress["step"] = "invitations"
    deleted["invitations"] = purge_tenant_invitations(tenant_id)
    progress["step"] = "service_accounts"
    service_accounts = purge_tenant_service_accounts(
        tenant_id,
        keep_service_account_ids=authorization.retained_delegate_service_account_ids,
    )
    deleted["service_accounts"] = service_accounts.deleted
    progress["step"] = "memberships"
    deleted["memberships"] = purge_tenant_memberships(tenant_id)
    progress["step"] = "feature_flag_overrides"
    deleted["feature_flag_overrides"] = purge_tenant_feature_flag_overrides(tenant_id)
    progress["step"] = "idempotency_records"
    deleted["idempotency_records"] = purge_tenant_idempotency_records(tenant_id)
    assert tuple(deleted) == PURGE_STEPS  # the sequence is the contract
    return (
        deleted,
        authorization.retained_delegation_grant_ids,
        service_accounts.retained_ids,
    )


def _tombstone_name(tenant_id: uuid.UUID) -> str:
    """The minimal-tombstone policy for `Tenant.name` (PRIV-03 Phase P3):
    the column is `NOT NULL`, so the customer-supplied name is replaced
    with a fixed, non-identifying placeholder derived only from the
    tenant's own opaque id. Nothing else on the row identifies the
    customer: `status`/`id` are needed for lifecycle identification and
    referential integrity, `parent_id`/`tenant_ancestry` are structural
    (left intact -- never reparented), `inherits_billing` is a boolean
    flag. `created_at`/`updated_at` are timestamps, not identity."""
    return f"purged-{tenant_id}"


def purge_tenant(
    tenant_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None = None,
    registry: TenantPurgeParticipantRegistry | None = None,
) -> TenantPurgeResult:
    """Purge `tenant_id` into its permanent `PURGED` tombstone (PRIV-03
    Phase P3 -- the approved tombstone-based erasure architecture; this
    replaces the pre-P3 physical `DELETE` of the tenant row).

    Exactly one tenant, never its descendants, never anything across a
    tenant boundary: every step runs under `tenant_session_scope(tenant_id)`
    and existing `FORCE ROW LEVEL SECURITY` (the one non-RLS table,
    `core.api_keys`, is filtered by its explicit `tenant_id` predicate) --
    no privileged bypass, no dynamic SQL, no FK discovery; the sequence is
    the fixed `PURGE_STEPS` constant, each a module-owned operation.

    Lifecycle contract (verified against the freshly-read, row-locked
    status, never a caller-supplied one):

    - `DELETED`  -> moved to `PURGING` here (the approved graph's only
                    entry into the purge phase), then purged.
    - `PURGING`  -> a retry after a crash/partial completion; continues.
    - `PURGED`   -> already done; returns `already_purged=True`, no-op.
    - anything else (`PENDING`/`ACTIVE`/`SUSPENDED`) ->
      `InvalidTenantTransitionError` -- an open tenant is never purged.

    A tenant with any child still pointing at it (`Tenant.parent_id`)
    fails closed with `TenantHasDescendantsError` *before* entering
    `PURGING` -- purge never recurses and never reparents.

    Transaction / idempotency model: the entry check, each module step,
    and the final tombstone write are separate transactions. Every step
    deletes only what it finds (rows locked `FOR UPDATE`) and returns 0 on
    repeat, so a crash anywhere -- before the first step, between steps,
    after a step, or just before the final transition -- leaves the tenant
    `PURGING` with strictly less data, and the next call resumes. The
    `PURGED` transition is written only after a full pass removes nothing
    (verification: the final state is checked, not assumed from control
    flow); if rows still remain after `_MAX_PURGE_PASSES`, the tenant stays
    `PURGING` and `TenantPurgeIncompleteError` is raised.

    Concurrency: two concurrent calls serialize on the tenant row
    (`FOR UPDATE`) at entry and at the final transition, and on each
    table's rows within a step; the P2 fence guarantees no new tenant-owned
    row can appear once `PURGING` is reached, so the data set only ever
    shrinks. Whichever call reaches the final transition first writes
    `PURGED`; the other observes `PURGED` and returns.

    Retained (never deleted): `core.audit_log`, `core.billing_subscriptions`,
    `core.support_access_requests`, `core.tenant_ancestry`, and the tenant
    row. Audit-referenced delegation grants / service accounts are kept
    revoked / disabled. Global identity rows (`core.users`, ...) are never
    touched. Deferred: `core.usage_events`, AI Control Plane tables.

    Audit evidence (PRIV-03 Phase P4; module comment above
    `_record_lifecycle_event`): once this call holds the tenant in
    `PURGING` (committed) it writes `tenant.purge_started`; a committed
    `PURGED` write is followed by `tenant.purge_completed`; any exception
    after `purge_started` -- a step error, rows remaining after every
    pass, or a rejected final transition -- is followed by
    `tenant.purge_failed` (bounded failure class, failing step, exception
    class name, passes completed -- never the exception's text) and then
    re-raised, the tenant staying `PURGING`. Every attempt, including each
    retry, leaves its own started/failed/completed records: the history is
    the evidence. A call that finds the tenant already `PURGED` records
    nothing (nothing happened), and a concurrent loser that finds `PURGED`
    at the final transition records no completion of its own -- exactly
    one `purge_completed` per genuine tombstone write. `actor_user_id` is
    optional; absent, the existing `SYSTEM` actor is used.

    RA-12-2: after every `PURGE_STEPS` pass converges (this function's own
    Core-owned data), every `TenantPurgeParticipant` registered in
    `registry` (default: `core.tenancy.purge_participants.default_registry()`
    -- the process-wide registry a Product's own composition root registers
    into) runs once, in registration order, still inside the same
    `PURGING` window and the same failure/retry model as every Core step:
    a participant failure is classified `"participant_error"`, names the
    participant (never the Product or the exception's own message) as
    `failed_step`, and prevents the `PURGED` transition exactly like a
    Core step failure does. `registry` is an override for test isolation
    only; real callers never need to pass it.

    RA-12-7: once every participant has also succeeded, this tenant's own
    entries are atomically removed from the shared, cross-tenant
    `arq:dead-letter` list (`infra.jobs.dead_letter.purge_tenant_dead_letters_sync()`)
    -- the last step before the final `PURGED` transition. Failure (e.g.
    Redis unreachable) is classified `"redis_cleanup_error"` and fails
    closed exactly like every step above; the count removed is reported
    in `TenantPurgeResult.dead_letter_entries_purged`, never the entries'
    own contents. This does **not** eliminate every possible Redis
    reference to this tenant: a job already queued before the tenant
    closed can still be picked up by a worker afterward, correctly do
    nothing (the existing execution-time lifecycle fencing every
    tenant-associated job handler already has), and still write a *new*
    dead-letter entry naming this tenant -- Redis and PostgreSQL share no
    transaction, so no placement of this step can close that window
    entirely. That residual exposure is bounded by ARQ's own job-key TTL
    (~24h, `infra/jobs/queue.py`'s own docstring) and is an explicitly
    accepted limitation, not a defect of this step -- see
    `docs/MULTI-TENANCY.md` section 6's RA-12-7 addendum. Queued job
    payloads (`arq:job:<id>`) are deliberately never scanned or cancelled
    by this function.
    """
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id, with_for_update=True)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)
        status = TenantStatus(tenant.status)
        if status is TenantStatus.PURGED:
            return TenantPurgeResult(
                tenant_id=tenant_id,
                deleted=dict.fromkeys(PURGE_STEPS, 0),
                retained_delegation_grant_ids=frozenset(),
                retained_service_account_ids=frozenset(),
                passes=0,
                already_purged=True,
            )
        # Only *live* children block: a child that is itself already a
        # PURGED tombstone keeps its `parent_id` (hierarchy is never
        # rewritten), so counting it would make a parent un-purgeable
        # forever once its children were purged leaf-first.
        children = frozenset(
            session.execute(
                select(Tenant.id).where(
                    Tenant.parent_id == tenant_id,
                    Tenant.status != TenantStatus.PURGED.value,
                )
            ).scalars()
        )
        if children:
            raise TenantHasDescendantsError(tenant_id, children)
        entry_status = status
        if status is not TenantStatus.PURGING:
            validate_transition(status, TenantStatus.PURGING)
            tenant.status = TenantStatus.PURGING.value
            session.flush()

    # Committed: the tenant is PURGING. Evidence of this attempt starting.
    _record_lifecycle_event(
        tenant_id,
        action=_ACTION_PURGE_STARTED,
        outcome=AuditOutcome.SUCCESS,
        actor_user_id=actor_user_id,
        metadata={
            "from_status": entry_status.value,
            "to_status": TenantStatus.PURGING.value,
            "resumed": entry_status is TenantStatus.PURGING,
        },
    )

    first_pass: dict[str, int] | None = None
    retained_grants: frozenset[uuid.UUID] = frozenset()
    retained_accounts: frozenset[uuid.UUID] = frozenset()
    revoked_support_access: frozenset[uuid.UUID] = frozenset()
    participant_names: list[str] = []
    dead_letter_entries_purged = 0
    passes = 0
    progress: dict[str, str] = {"step": _STEP_SUPPORT_ACCESS}
    transitioned = False
    core_passes_complete = False
    try:
        # PRIV-03 P6 (RA-02): end every support-access grant's *authority*
        # before any data is removed and before the tenant can reach
        # PURGED -- the rows themselves are retained evidence
        # (SECURITY_RETAIN), never a PURGE_STEPS entry, so this is not a
        # pass and deletes nothing; it is idempotent and serialized on the
        # rows like every step (`core/rbac/service.py`). Deferred import
        # for the same load-time-cycle reason `_run_purge_pass()` documents.
        from core.authority import SystemAuthority, SystemCaller, UserCaller
        from core.rbac.service import revoke_tenant_support_access

        # ADR-0031: `revoke_tenant_support_access()` takes an explicit typed
        # caller. `purge_tenant()`'s own `actor_user_id` contract is
        # unchanged here (Lifecycle Completion owns it); its documented
        # "no actor" case is mapped to the explicit purge authority.
        revoked_support_access = revoke_tenant_support_access(
            tenant_id,
            caller=UserCaller(actor_user_id)
            if actor_user_id is not None
            else SystemCaller(SystemAuthority.TENANT_PURGE),
        )

        for attempt in range(1, _MAX_PURGE_PASSES + 1):
            passes = attempt
            deleted, retained_grants, retained_accounts = _run_purge_pass(tenant_id, progress)
            if first_pass is None:
                first_pass = deleted
            if sum(deleted.values()) == 0:
                break
        else:
            raise TenantPurgeIncompleteError(
                tenant_id, {name: count for name, count in deleted.items() if count}
            )
        core_passes_complete = True

        # RA-12-2: Core's own data is fully wound down. Every registered
        # Product participant runs once, in registration order, still
        # under the same PURGING fence -- see this function's own
        # docstring and TenantPurgeParticipant's own contract.
        active_registry = registry if registry is not None else default_purge_participant_registry()
        for participant in active_registry.list():
            progress["step"] = f"{_PARTICIPANT_STEP_PREFIX}{participant.name}"
            participant.purge_tenant_data(tenant_id)
            participant_names.append(participant.name)

        # RA-12-7: Core's own PostgreSQL data and every registered
        # participant have both fully converged -- remove this tenant's
        # own entries from the shared `arq:dead-letter` list before the
        # tenant can reach PURGED. Deferred import: `infra.jobs` does not
        # import `core` (its own package docstring), so this is not a
        # load-time cycle, but every cross-module call in this function
        # is deferred at its point of use for consistency (see
        # `revoke_tenant_support_access` above). Failure here is fail-
        # closed exactly like every other step -- see the `except` block
        # below and `docs/MULTI-TENANCY.md` section 6's RA-12-7 addendum
        # for why this does not, and cannot, guarantee zero Redis
        # references after PURGED (the accepted, bounded residual window
        # a still-queued job's own ~24h ARQ TTL leaves open).
        progress["step"] = _STEP_REDIS_DEAD_LETTERS
        from infra.jobs.dead_letter import purge_tenant_dead_letters_sync

        dead_letter_entries_purged = purge_tenant_dead_letters_sync(str(tenant_id))

        progress["step"] = _STEP_FINAL_TRANSITION
        with session_scope() as session:
            tenant = session.get(Tenant, tenant_id, with_for_update=True)
            if tenant is None:
                raise TenantNotFoundError(tenant_id)
            status = TenantStatus(tenant.status)
            if status is not TenantStatus.PURGED:
                validate_transition(status, TenantStatus.PURGED)  # only PURGING may reach here
                tenant.name = _tombstone_name(tenant_id)
                tenant.status = TenantStatus.PURGED.value
                session.flush()
                transitioned = True
    except Exception as exc:
        # This attempt did not complete: the tenant is still PURGING (or a
        # concurrent purge finished it). Bounded metadata only -- never
        # `str(exc)`, which could echo anything a failing layer embedded.
        if isinstance(exc, TenantPurgeIncompleteError):
            failure_class = _FAILURE_INCOMPLETE
        elif isinstance(exc, InvalidTenantTransitionError):
            failure_class = _FAILURE_TRANSITION_REJECTED
        elif progress["step"].startswith(_PARTICIPANT_STEP_PREFIX):
            # RA-12-2: a registered Product purge participant raised.
            failure_class = _FAILURE_PARTICIPANT_ERROR
        elif progress["step"] == _STEP_REDIS_DEAD_LETTERS:
            # RA-12-7: the Redis dead-letter cleanup step raised (e.g.
            # Redis unreachable/timed out) -- fail closed like every other
            # step; the tenant stays PURGING and a retry re-runs it.
            failure_class = _FAILURE_REDIS_CLEANUP_ERROR
        else:
            failure_class = _FAILURE_STEP_ERROR
        # Core's own PURGE_STEPS passes had already fully converged (0 rows
        # left) before either the participant loop or the final transition
        # could run, so a failure at either point still means every pass
        # completed -- only a mid-loop Core step failure means the pass
        # that was running did not.
        failed_after_core_passes = (
            progress["step"] == _STEP_FINAL_TRANSITION or core_passes_complete
        )
        _record_lifecycle_event(
            tenant_id,
            action=_ACTION_PURGE_FAILED,
            outcome=AuditOutcome.FAILURE,
            actor_user_id=actor_user_id,
            metadata={
                "failure_class": failure_class,
                "failed_step": progress["step"],
                "error_type": type(exc).__name__,
                "passes_completed": passes if failed_after_core_passes else passes - 1,
            },
        )
        raise

    if transitioned:
        # Committed: the tombstone write happened in *this* call. Counts and
        # sizes only -- never the rows or the retained ids themselves.
        _record_lifecycle_event(
            tenant_id,
            action=_ACTION_PURGE_COMPLETED,
            outcome=AuditOutcome.SUCCESS,
            actor_user_id=actor_user_id,
            metadata=_purge_completed_metadata(
                passes=passes,
                deleted=first_pass if first_pass is not None else dict.fromkeys(PURGE_STEPS, 0),
                retained_service_accounts=len(retained_accounts),
                retained_delegation_grants=len(retained_grants),
                participants_run=len(participant_names),
                dead_letter_entries_purged=dead_letter_entries_purged,
            ),
        )

    return TenantPurgeResult(
        tenant_id=tenant_id,
        deleted=first_pass if first_pass is not None else dict.fromkeys(PURGE_STEPS, 0),
        retained_delegation_grant_ids=retained_grants,
        retained_service_account_ids=retained_accounts,
        passes=passes,
        revoked_support_access_ids=revoked_support_access,
        participant_names=tuple(participant_names),
        dead_letter_entries_purged=dead_letter_entries_purged,
    )
