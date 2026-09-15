"""PRIV-03 Phase P9 -- `move_tenant()` lifecycle fence and hierarchy-writer
serialization (privacy re-audit finding RA-05), against real PostgreSQL.

The RA-05 audit established, on the pre-fix code, that `move_tenant()`
was lifecycle-blind (every source x destination lifecycle combination
moved, including a PURGED tombstone and a live tenant *under* a PURGED
tombstone), that two concurrent moves whose per-node advisory-lock sets
are disjoint could both pass the cycle check and commit a real
`parent_id` cycle, and that a move could attach a live child to a tenant
between `purge_tenant()`'s children check and its final PURGED write.

These tests pin the corrected behavior:

- both ends of a move are read with `lock_open_tenant()` inside the move
  transaction -- DELETED/PURGING/PURGED on either side is refused, the
  tombstone's hierarchy is never rewritten, and a closure serializes
  against an in-flight move instead of landing in the middle of it;
- every hierarchy writer takes one hierarchy-wide advisory lock before
  reading the ancestry it validates against, so moves (and parent-aware
  creates) serialize and the closure table can never become cyclic or
  torn;
- PENDING/ACTIVE/SUSPENDED remain open for moves -- the unchanged P2
  mutation policy, deliberately distinct from RA-04's principal policy.

Marked `integration`, mirroring `tests/core/tenancy/test_tenant_hierarchy_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/tenancy/test_tenant_hierarchy_lifecycle_integration.py
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Iterator

import core.tenancy.service as tenancy_service
import pytest
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

# Loads the `core.users` / `core.support_access_requests` mappers that
# `core.audit_log`'s model references by name, so a DELETED transition's
# audit write works when this file runs on its own.
import core.rbac  # noqa: F401
from core.tenancy import (
    Tenant,
    TenantClosedError,
    TenantCycleError,
    TenantHasDescendantsError,
    TenantStatus,
    create_tenant,
    get_descendant_ids,
    get_tenant,
    move_tenant,
    purge_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

_OPEN = [TenantStatus.PENDING, TenantStatus.ACTIVE, TenantStatus.SUSPENDED]
_CLOSED = [TenantStatus.DELETED, TenantStatus.PURGING, TenantStatus.PURGED]


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe_engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.tenant_ancestry LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.tenant_ancestry not reachable: {exc}")
    finally:
        probe_engine.dispose()


@pytest.fixture
def admin() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


class Tree:
    """Creates tenants in a chosen lifecycle state and removes every one of
    them afterwards (parents unlinked first: `parent_id` is a RESTRICT FK,
    and a closed tenant's audit rows need the privileged role)."""

    def __init__(self, admin: sessionmaker[Session]) -> None:
        self._admin = admin
        self.ids: list[uuid.UUID] = []

    def make(
        self, status: TenantStatus = TenantStatus.ACTIVE, *, parent: uuid.UUID | None = None
    ) -> uuid.UUID:
        tenant = create_tenant(f"priv03-p9-{uuid.uuid4().hex[:8]}", parent_id=parent)
        self.ids.append(tenant.id)
        if status is not TenantStatus.PENDING:
            transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
        if status is TenantStatus.SUSPENDED:
            transition_tenant_status(tenant.id, TenantStatus.SUSPENDED)
        elif status in _CLOSED:
            transition_tenant_status(tenant.id, TenantStatus.DELETED)
            if status is TenantStatus.PURGING:
                transition_tenant_status(tenant.id, TenantStatus.PURGING)
            elif status is TenantStatus.PURGED:
                purge_tenant(tenant.id)
        return tenant.id

    def teardown(self) -> None:
        ids = [str(t) for t in self.ids]
        with session_scope(session_factory=self._admin) as session:
            session.execute(
                text("UPDATE core.tenants SET parent_id = NULL WHERE id = ANY(:ids)"), {"ids": ids}
            )
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = ANY(:ids)"), {"ids": ids}
            )
            session.execute(
                text(
                    "DELETE FROM core.tenant_ancestry "
                    "WHERE tenant_id = ANY(:ids) OR ancestor_id = ANY(:ids)"
                ),
                {"ids": ids},
            )
            session.execute(text("DELETE FROM core.tenants WHERE id = ANY(:ids)"), {"ids": ids})


@pytest.fixture
def tree(admin: sessionmaker[Session]) -> Iterator[Tree]:
    built = Tree(admin)
    try:
        yield built
    finally:
        built.teardown()


def _ancestry(tenant_id: uuid.UUID) -> dict[uuid.UUID, int]:
    with session_scope() as session:
        rows = session.execute(
            text("SELECT ancestor_id, depth FROM core.tenant_ancestry WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        ).all()
    return {row[0]: row[1] for row in rows}


def _parent_of(tenant_id: uuid.UUID) -> uuid.UUID | None:
    return get_tenant(tenant_id).parent_id


def _assert_closure_consistent(tenant_ids: list[uuid.UUID]) -> None:
    """The closure table must equal what walking `parent_id` yields, and
    every walk must reach a root within `len(tenant_ids)` hops -- i.e. no
    cycle, no missing and no stale ancestry row."""
    for tenant_id in tenant_ids:
        expected: dict[uuid.UUID, int] = {tenant_id: 0}
        current, depth = tenant_id, 0
        while True:
            parent = _parent_of(current)
            if parent is None:
                break
            depth += 1
            assert depth <= len(tenant_ids), f"parent_id chain from {tenant_id} reaches no root"
            assert parent not in expected, f"parent_id cycle through {parent}"
            expected[parent] = depth
            current = parent
        assert _ancestry(tenant_id) == expected, f"closure rows for {tenant_id} are inconsistent"


def _run(target: Callable[[], object]) -> tuple[threading.Thread, dict[str, object]]:
    outcome: dict[str, object] = {}

    def _body() -> None:
        try:
            outcome["result"] = target()
        except BaseException as exc:  # noqa: BLE001 -- asserted by the caller
            outcome["error"] = exc

    thread = threading.Thread(target=_body)
    thread.start()
    return thread, outcome


# --- Lifecycle fence: open <-> open still moves ---------------------------------


@pytest.mark.parametrize(
    ("source", "destination"),
    [
        (TenantStatus.PENDING, TenantStatus.ACTIVE),
        (TenantStatus.ACTIVE, TenantStatus.PENDING),
        (TenantStatus.ACTIVE, TenantStatus.SUSPENDED),
        (TenantStatus.SUSPENDED, TenantStatus.ACTIVE),
        (TenantStatus.ACTIVE, TenantStatus.ACTIVE),
    ],
)
def test_open_tenants_still_move_between_open_parents(
    source: TenantStatus, destination: TenantStatus, tree: Tree
) -> None:
    old_parent = tree.make()
    src = tree.make(source, parent=old_parent)
    dst = tree.make(destination)

    moved = move_tenant(src, dst)

    assert moved.parent_id == dst
    assert _ancestry(src) == {src: 0, dst: 1}
    assert get_tenant(src).status == source.value
    assert get_tenant(dst).status == destination.value
    _assert_closure_consistent([old_parent, src, dst])


@pytest.mark.parametrize("source", _OPEN)
def test_open_tenant_can_still_become_a_root(source: TenantStatus, tree: Tree) -> None:
    parent = tree.make()
    src = tree.make(source, parent=parent)
    assert move_tenant(src, None).parent_id is None
    assert _ancestry(src) == {src: 0}


# --- Lifecycle fence: closed on either side is refused, nothing changes ---------


@pytest.mark.parametrize("destination", _CLOSED)
def test_open_tenant_cannot_be_moved_under_a_closed_destination(
    destination: TenantStatus, tree: Tree
) -> None:
    old_parent = tree.make()
    src = tree.make(parent=old_parent)
    dst = tree.make(destination)
    before = _ancestry(src)

    with pytest.raises(TenantClosedError) as excinfo:
        move_tenant(src, dst)

    assert excinfo.value.tenant_id == dst
    assert excinfo.value.status is destination
    assert _parent_of(src) == old_parent
    assert _ancestry(src) == before
    assert get_descendant_ids(dst) == {dst}


@pytest.mark.parametrize("source", _CLOSED)
def test_closed_tenant_cannot_be_moved_to_another_parent(source: TenantStatus, tree: Tree) -> None:
    old_parent = tree.make()
    src = tree.make(source, parent=old_parent)
    dst = tree.make()
    before = _ancestry(src)

    with pytest.raises(TenantClosedError) as excinfo:
        move_tenant(src, dst)

    assert excinfo.value.tenant_id == src
    assert _parent_of(src) == old_parent
    assert _ancestry(src) == before
    assert src not in get_descendant_ids(dst)


@pytest.mark.parametrize("source", _CLOSED)
def test_closed_tenant_cannot_be_moved_to_root(source: TenantStatus, tree: Tree) -> None:
    old_parent = tree.make()
    src = tree.make(source, parent=old_parent)
    before = _ancestry(src)

    with pytest.raises(TenantClosedError):
        move_tenant(src, None)

    assert _parent_of(src) == old_parent
    assert _ancestry(src) == before


def test_tombstone_hierarchy_is_immutable(tree: Tree) -> None:
    """A PURGED tombstone keeps its retained structure exactly: it cannot
    be reparented (not even as a no-op to its current parent), cannot be
    made a root, and cannot receive a live child -- so the retained
    ancestry rows stay byte-for-byte what the purge left behind and
    `purge_tenant()`'s "no live child" precondition cannot be undone
    after the fact."""
    parent = tree.make()
    tombstone = tree.make(TenantStatus.PURGED, parent=parent)
    other = tree.make()
    live = tree.make()
    retained = _ancestry(tombstone)
    assert retained == {tombstone: 0, parent: 1}
    assert get_tenant(tombstone).status == TenantStatus.PURGED.value

    with pytest.raises(TenantClosedError):
        move_tenant(tombstone, other)
    with pytest.raises(TenantClosedError):
        move_tenant(tombstone, None)
    with pytest.raises(TenantClosedError):
        move_tenant(tombstone, parent)  # the no-op shape is refused too
    with pytest.raises(TenantClosedError):
        move_tenant(live, tombstone)

    assert _ancestry(tombstone) == retained
    assert _parent_of(tombstone) == parent
    assert get_descendant_ids(tombstone) == {tombstone}
    assert _parent_of(live) is None
    assert purge_tenant(tombstone).already_purged is True


# --- Hierarchy-writer serialization ---------------------------------------------


def _pause_first_writer_after_global_lock(
    monkeypatch: pytest.MonkeyPatch, paused: threading.Event, release: threading.Event
) -> None:
    """Patch the per-node lock step (which every writer reaches only after
    the hierarchy-wide lock) so the *first* writer to get there pauses;
    any other writer is then provably blocked in the database on the
    hierarchy-wide lock, before it has read any ancestry."""
    real = tenancy_service._lock_hierarchy_nodes
    first = threading.Lock()
    state = {"paused_once": False}

    def _locked_then_paused(session: Session, *tenant_ids: uuid.UUID | None) -> None:
        real(session, *tenant_ids)
        with first:
            should_pause = not state["paused_once"]
            state["paused_once"] = True
        if should_pause:
            paused.set()
            assert release.wait(timeout=30)

    monkeypatch.setattr(tenancy_service, "_lock_hierarchy_nodes", _locked_then_paused)


def test_concurrent_moves_with_disjoint_node_locks_serialize_and_cannot_form_a_cycle(
    tree: Tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The RA-05 race: trees A -> E and B -> D; `move(A, D)` and `move(B, E)`
    lock disjoint node sets, so on the pre-fix code both validated against
    the same pre-state and both committed -- a `parent_id` cycle
    A -> D -> B -> E -> A. Now the second writer blocks on the
    hierarchy-wide lock until the first commits, re-validates against the
    committed tree, and is refused as a cycle; the tree stays acyclic and
    the closure table consistent."""
    a = tree.make()
    e = tree.make(parent=a)
    b = tree.make()
    d = tree.make(parent=b)
    paused, release = threading.Event(), threading.Event()
    _pause_first_writer_after_global_lock(monkeypatch, paused, release)

    first, first_outcome = _run(lambda: move_tenant(a, d))
    assert paused.wait(timeout=30), "the first move never reached its per-node locks"
    second, second_outcome = _run(lambda: move_tenant(b, e))
    second.join(timeout=2)
    assert second.is_alive(), "the second move must block on the hierarchy-wide lock"
    assert _parent_of(b) is None and _parent_of(a) is None  # nothing committed yet

    release.set()
    first.join(timeout=30)
    second.join(timeout=30)
    assert not first.is_alive() and not second.is_alive()

    assert "error" not in first_outcome, first_outcome
    assert isinstance(second_outcome.get("error"), TenantCycleError), second_outcome
    assert _parent_of(a) == d
    assert _parent_of(b) is None
    assert _ancestry(a) == {a: 0, d: 1, b: 2}
    assert _ancestry(e) == {e: 0, a: 1, d: 2, b: 3}
    _assert_closure_consistent([a, b, d, e])


def test_concurrent_create_under_a_descendant_and_move_of_its_ancestor_stay_consistent(
    tree: Tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G -> P; concurrently `move(G, N)` and `create_tenant(parent=P)`. Their
    per-node lock sets ({G, N} vs {P}) are disjoint, so pre-fix the new
    child could be derived from P's *old* ancestry while G's subtree was
    being re-anchored -- stale bridge rows. Now the create waits for the
    move and derives the child from the committed tree."""
    g = tree.make()
    p = tree.make(parent=g)
    n = tree.make()
    paused, release = threading.Event(), threading.Event()
    _pause_first_writer_after_global_lock(monkeypatch, paused, release)

    mover, move_outcome = _run(lambda: move_tenant(g, n))
    assert paused.wait(timeout=30)
    created: list[uuid.UUID] = []

    def _create() -> uuid.UUID:
        child = create_tenant(f"priv03-p9-child-{uuid.uuid4().hex[:8]}", parent_id=p)
        created.append(child.id)
        return child.id

    creator, create_outcome = _run(_create)
    creator.join(timeout=2)
    assert creator.is_alive(), "the create must block on the hierarchy-wide lock"

    release.set()
    mover.join(timeout=30)
    creator.join(timeout=30)
    tree.ids.extend(created)
    assert "error" not in move_outcome, move_outcome
    assert "error" not in create_outcome, create_outcome
    child = created[0]
    assert _ancestry(child) == {child: 0, p: 1, g: 2, n: 3}
    _assert_closure_consistent([g, p, n, child])


# --- Purge / closure vs move ------------------------------------------------------


def test_move_into_a_tenant_being_purged_is_refused_and_the_purge_completes(
    tree: Tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pre-fix, a move into P after `purge_tenant()`'s children check and
    before its final PURGED write succeeded, leaving a tombstone with a
    live child. The lifecycle lock refuses the move (P is already PURGING,
    a closed state, when the purge pauses) and the purge finishes with no
    child attached."""
    p = tree.make(TenantStatus.DELETED)
    x = tree.make()
    in_purge, release = threading.Event(), threading.Event()
    real_pass = tenancy_service._run_purge_pass

    def _paused_pass(tenant_id: uuid.UUID, progress: dict[str, str]):
        in_purge.set()
        assert release.wait(timeout=30)
        return real_pass(tenant_id, progress)

    monkeypatch.setattr(tenancy_service, "_run_purge_pass", _paused_pass)
    purger, purge_outcome = _run(lambda: purge_tenant(p))
    assert in_purge.wait(timeout=30)
    assert get_tenant(p).status == TenantStatus.PURGING.value

    with pytest.raises(TenantClosedError):
        move_tenant(x, p)

    release.set()
    purger.join(timeout=30)
    assert "error" not in purge_outcome, purge_outcome
    assert get_tenant(p).status == TenantStatus.PURGED.value
    assert _parent_of(x) is None
    assert get_descendant_ids(p) == {p}


def _pause_move_after_locking_new_parent(
    monkeypatch: pytest.MonkeyPatch,
    new_parent_id: uuid.UUID,
    paused: threading.Event,
    release: threading.Event,
) -> None:
    real = tenancy_service.lock_open_tenant

    def _locked_then_paused(session: Session, tenant_id: uuid.UUID) -> Tenant:
        tenant = real(session, tenant_id)
        if tenant_id == new_parent_id:
            paused.set()
            assert release.wait(timeout=30)
        return tenant

    monkeypatch.setattr(tenancy_service, "lock_open_tenant", _locked_then_paused)


def test_closure_cannot_commit_between_the_lifecycle_check_and_the_hierarchy_write(
    tree: Tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Move first: the move holds P's row FOR SHARE from its lifecycle check
    to its commit, so `transition_tenant_status(P, DELETED)` (FOR UPDATE)
    blocks until the move lands. The move was decided while P was open and
    commits; the closure then commits *after* it -- and the resulting
    DELETED-with-live-child state is exactly what `purge_tenant()`'s own
    precondition still refuses to purge."""
    p = tree.make()
    x = tree.make()
    paused, release = threading.Event(), threading.Event()
    _pause_move_after_locking_new_parent(monkeypatch, p, paused, release)

    mover, move_outcome = _run(lambda: move_tenant(x, p))
    assert paused.wait(timeout=30), "the move never locked its destination"
    closer, close_outcome = _run(lambda: transition_tenant_status(p, TenantStatus.DELETED))
    closer.join(timeout=2)
    assert closer.is_alive(), "the closure must block on the move's share lock"
    assert get_tenant(p).status == TenantStatus.ACTIVE.value

    release.set()
    mover.join(timeout=30)
    closer.join(timeout=30)
    assert "error" not in move_outcome, move_outcome
    assert "error" not in close_outcome, close_outcome
    assert _parent_of(x) == p
    assert get_tenant(p).status == TenantStatus.DELETED.value
    with pytest.raises(TenantHasDescendantsError):
        purge_tenant(p)


def test_move_blocks_behind_an_in_flight_closure_and_then_fails_closed(tree: Tree) -> None:
    """Closure first: a transaction already holds P's row FOR UPDATE with
    DELETED pending; the move blocks on its FOR SHARE read and, once the
    closure commits, sees DELETED and is refused -- never a live child
    under a tenant that was closing in the same instant."""
    p = tree.make()
    x = tree.make()
    ready, release = threading.Event(), threading.Event()

    def _hold_then_close() -> None:
        with session_scope() as session:
            row = session.get(Tenant, p, with_for_update=True)
            assert row is not None
            ready.set()
            assert release.wait(timeout=30)
            row.status = TenantStatus.DELETED.value
            session.flush()

    holder, _ = _run(_hold_then_close)
    assert ready.wait(timeout=30)
    mover, move_outcome = _run(lambda: move_tenant(x, p))
    mover.join(timeout=2)
    assert mover.is_alive(), "the move must block on the row the closure holds"

    release.set()
    holder.join(timeout=30)
    mover.join(timeout=30)
    assert isinstance(move_outcome.get("error"), TenantClosedError), move_outcome
    assert _parent_of(x) is None
    assert get_tenant(p).status == TenantStatus.DELETED.value
    assert get_descendant_ids(p) == {p}
