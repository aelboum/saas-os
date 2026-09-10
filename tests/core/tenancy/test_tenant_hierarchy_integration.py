"""Tenant hierarchy foundation integration tests against a real PostgreSQL
instance (architecture research: universal multi-tenant tenancy, Phase A).

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/tenancy/test_tenancy_integration.py` and
`tests/core/tenancy/test_tenant_isolation_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/tenancy/test_tenant_hierarchy_integration.py

This file covers two different kinds of claim, deliberately kept apart:

- Structural correctness of `core.tenant_ancestry` itself (creation,
  multi-level hierarchy, moves, cycle prevention, concurrency) -- using
  `core.tenancy`'s own service functions and reading the ancestry table
  directly, exactly like `test_tenancy_integration.py` does for plain
  CRUD.
- Proof that hierarchy grants **no** authorization by itself -- reusing
  `test_tenant_isolation_integration.py`'s own scratch-table-plus-RLS
  pattern, so these assertions exercise the real `app.tenant_id` RLS
  policy, not a mock.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.rls import tenant_rls_statements
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError
from sqlalchemy.orm import Session, sessionmaker

from core.tenancy import (
    TenantCycleError,
    TenantHierarchyDepthExceededError,
    TenantNotFoundError,
    TenantStatus,
    create_tenant,
    get_tenancy_config,
    get_tenant,
    move_tenant,
    purge_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

_APP_ROLE = os.environ.get("APP_DB_USER", "saas_os_app")


@pytest.fixture(autouse=True)
def _require_reachable_database_with_hierarchy_schema() -> Iterator[None]:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    get_tenancy_config.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.tenant_ancestry LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.tenant_ancestry does not exist yet -- run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")

    yield
    get_tenancy_config.cache_clear()


def _unique_name() -> str:
    return f"phase-a-tenant-{uuid.uuid4().hex[:8]}"


def _ancestry_rows(tenant_id: uuid.UUID) -> dict[uuid.UUID, int]:
    """`{ancestor_id: depth}` for every ancestor of `tenant_id`, read
    directly (untenanted -- `core.tenant_ancestry` is not RLS-scoped)."""
    with session_scope() as session:
        rows = session.execute(
            text("SELECT ancestor_id, depth FROM core.tenant_ancestry WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        ).all()
        return {row[0]: row[1] for row in rows}


def _descendant_ids(tenant_id: uuid.UUID) -> set[uuid.UUID]:
    with session_scope() as session:
        rows = session.execute(
            text("SELECT tenant_id FROM core.tenant_ancestry WHERE ancestor_id = :a"),
            {"a": str(tenant_id)},
        ).all()
        return {row[0] for row in rows}


def _delete_tenant_row(tenant_id: uuid.UUID) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t OR ancestor_id = :t"),
            {"t": str(tenant_id)},
        )
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_id)})


# --- Root and child creation -------------------------------------------------


def test_root_tenant_creation_gets_only_a_self_ancestry_row() -> None:
    root = create_tenant(_unique_name())
    try:
        assert root.parent_id is None
        assert _ancestry_rows(root.id) == {root.id: 0}
    finally:
        _delete_tenant_row(root.id)


def test_child_tenant_creation_links_to_parent_and_its_ancestors() -> None:
    root = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=root.id)
    try:
        assert child.parent_id == root.id
        assert _ancestry_rows(child.id) == {child.id: 0, root.id: 1}
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(root.id)


def test_direct_parent_relationship_is_recorded_at_depth_one() -> None:
    root = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=root.id)
    try:
        assert _ancestry_rows(child.id)[root.id] == 1
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(root.id)


def test_multi_level_hierarchy_ancestry_is_correct() -> None:
    grandparent = create_tenant(_unique_name())
    parent = create_tenant(_unique_name(), parent_id=grandparent.id)
    child = create_tenant(_unique_name(), parent_id=parent.id)
    try:
        assert _ancestry_rows(child.id) == {child.id: 0, parent.id: 1, grandparent.id: 2}
        assert _ancestry_rows(parent.id) == {parent.id: 0, grandparent.id: 1}
        assert _ancestry_rows(grandparent.id) == {grandparent.id: 0}
        # Reverse direction: closure table answers descendant queries too.
        assert _descendant_ids(grandparent.id) == {grandparent.id, parent.id, child.id}
        assert _descendant_ids(parent.id) == {parent.id, child.id}
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(parent.id)
        _delete_tenant_row(grandparent.id)


def test_closure_table_correctness_for_a_branching_tree() -> None:
    root = create_tenant(_unique_name())
    child_a = create_tenant(_unique_name(), parent_id=root.id)
    child_b = create_tenant(_unique_name(), parent_id=root.id)
    grandchild = create_tenant(_unique_name(), parent_id=child_a.id)
    try:
        assert _descendant_ids(root.id) == {root.id, child_a.id, child_b.id, grandchild.id}
        # Siblings share no ancestor/descendant relationship with each other.
        assert child_b.id not in _ancestry_rows(child_a.id)
        assert child_a.id not in _ancestry_rows(child_b.id)
        assert grandchild.id not in _descendant_ids(child_b.id)
    finally:
        _delete_tenant_row(grandchild.id)
        _delete_tenant_row(child_b.id)
        _delete_tenant_row(child_a.id)
        _delete_tenant_row(root.id)


def test_self_ancestry_invariant_holds_for_every_tenant() -> None:
    root = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=root.id)
    try:
        assert _ancestry_rows(root.id)[root.id] == 0
        assert _ancestry_rows(child.id)[child.id] == 0
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(root.id)


def test_create_tenant_with_unknown_parent_raises_and_writes_nothing() -> None:
    bogus_parent = uuid.uuid4()
    with pytest.raises(TenantNotFoundError):
        create_tenant(_unique_name(), parent_id=bogus_parent)


# --- Moving ------------------------------------------------------------------


def test_moving_a_root_beneath_another_root() -> None:
    root_a = create_tenant(_unique_name())
    root_b = create_tenant(_unique_name())
    try:
        moved = move_tenant(root_a.id, root_b.id)
        assert moved.parent_id == root_b.id
        assert _ancestry_rows(root_a.id) == {root_a.id: 0, root_b.id: 1}
    finally:
        _delete_tenant_row(root_a.id)
        _delete_tenant_row(root_b.id)


def test_moving_a_subtree_preserves_internal_relationships() -> None:
    old_parent = create_tenant(_unique_name())
    new_parent = create_tenant(_unique_name())
    subtree_root = create_tenant(_unique_name(), parent_id=old_parent.id)
    subtree_leaf = create_tenant(_unique_name(), parent_id=subtree_root.id)
    try:
        move_tenant(subtree_root.id, new_parent.id)

        # The internal subtree_root -> subtree_leaf relationship survives
        # the move unchanged (depth 1 apart, same as before).
        assert _ancestry_rows(subtree_leaf.id)[subtree_root.id] == 1
        # The subtree is now anchored under new_parent, not old_parent.
        assert _ancestry_rows(subtree_root.id) == {subtree_root.id: 0, new_parent.id: 1}
        assert _ancestry_rows(subtree_leaf.id) == {
            subtree_leaf.id: 0,
            subtree_root.id: 1,
            new_parent.id: 2,
        }
        assert old_parent.id not in _ancestry_rows(subtree_root.id)
        assert old_parent.id not in _ancestry_rows(subtree_leaf.id)
        assert subtree_root.id not in _descendant_ids(old_parent.id)
        assert subtree_leaf.id not in _descendant_ids(old_parent.id)
    finally:
        _delete_tenant_row(subtree_leaf.id)
        _delete_tenant_row(subtree_root.id)
        _delete_tenant_row(new_parent.id)
        _delete_tenant_row(old_parent.id)


def _current_parent_id(tenant_id: uuid.UUID) -> uuid.UUID | None:
    with session_scope() as session:
        return session.execute(
            text("SELECT parent_id FROM core.tenants WHERE id = :id"), {"id": str(tenant_id)}
        ).scalar_one()


def test_moving_a_tenant_beneath_its_own_descendant_fails_closed() -> None:
    parent = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=parent.id)
    try:
        before = _ancestry_rows(parent.id), _ancestry_rows(child.id)
        with pytest.raises(TenantCycleError):
            move_tenant(parent.id, child.id)
        # Rejected before any row was written -- ancestry and parent_id
        # are both untouched.
        assert (_ancestry_rows(parent.id), _ancestry_rows(child.id)) == before
        assert _current_parent_id(parent.id) is None
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(parent.id)


def test_moving_a_tenant_beneath_itself_fails_closed() -> None:
    root = create_tenant(_unique_name())
    try:
        with pytest.raises(TenantCycleError):
            move_tenant(root.id, root.id)
        assert _ancestry_rows(root.id) == {root.id: 0}
    finally:
        _delete_tenant_row(root.id)


def test_no_op_move_does_not_rewrite_ancestry() -> None:
    root = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=root.id)
    try:
        before = _ancestry_rows(child.id)
        moved = move_tenant(child.id, root.id)  # already child's parent
        assert moved.parent_id == root.id
        assert _ancestry_rows(child.id) == before
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(root.id)


def test_moving_to_root_clears_all_ancestors() -> None:
    root = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=root.id)
    try:
        moved = move_tenant(child.id, None)
        assert moved.parent_id is None
        assert _ancestry_rows(child.id) == {child.id: 0}
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(root.id)


# --- Depth guardrail ----------------------------------------------------------


def test_depth_guardrail_blocks_hierarchy_deeper_than_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TENANT_MAX_HIERARCHY_DEPTH", "1")
    get_tenancy_config.cache_clear()

    root = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=root.id)  # depth 1, at the limit
    try:
        with pytest.raises(TenantHierarchyDepthExceededError):
            create_tenant(_unique_name(), parent_id=child.id)  # would be depth 2
        # Nothing was written by the rejected attempt.
        assert _descendant_ids(root.id) == {root.id, child.id}
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(root.id)
        monkeypatch.delenv("TENANT_MAX_HIERARCHY_DEPTH", raising=False)
        get_tenancy_config.cache_clear()


# --- Backward compatibility: existing flat-tenancy behavior is unchanged ----


def test_existing_flat_tenant_behaves_exactly_as_before() -> None:
    """`create_tenant(name)` -- the pre-Phase-A call shape, no `parent_id`
    keyword at all -- must still work identically: a root tenant with
    only a self ancestry row, `purge_tenant()` still succeeds afterward
    (the fix that made `purge_tenant()` also clean up its own ancestry
    row is exactly what keeps this pre-existing lifecycle working now
    that every tenant has at least one `core.tenant_ancestry` row)."""
    tenant = create_tenant(_unique_name())
    assert tenant.parent_id is None
    assert _ancestry_rows(tenant.id) == {tenant.id: 0}

    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    transition_tenant_status(tenant.id, TenantStatus.DELETED)
    purge_tenant(tenant.id)

    with pytest.raises(TenantNotFoundError):
        get_tenant(tenant.id)
    assert _ancestry_rows(tenant.id) == {}


def test_purge_blocked_by_foreign_key_while_a_child_still_exists() -> None:
    """Deleting a tenant with a living child is blocked, not cascaded
    (architecture research Part 20) -- `Tenant.parent_id` has no
    `ON DELETE CASCADE`, so PostgreSQL itself rejects it."""
    parent = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=parent.id)
    try:
        transition_tenant_status(parent.id, TenantStatus.ACTIVE)
        transition_tenant_status(parent.id, TenantStatus.DELETED)
        with pytest.raises(IntegrityError):
            purge_tenant(parent.id)
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(parent.id)


# --- Transactional atomicity --------------------------------------------------


def test_transaction_rollback_leaves_no_partial_ancestry_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected `create_tenant(parent_id=...)` (depth guardrail firing
    partway through, after the `Tenant` row and its self-ancestry row
    have already been added to the session but before commit) must leave
    *nothing* behind -- not the tenant row, not its self-ancestry row.
    Proves `session_scope()`'s rollback covers the whole operation, not
    just the `Tenant` insert."""
    monkeypatch.setenv("TENANT_MAX_HIERARCHY_DEPTH", "1")
    get_tenancy_config.cache_clear()

    root = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=root.id)
    try:
        with pytest.raises(TenantHierarchyDepthExceededError):
            create_tenant(_unique_name(), parent_id=child.id)

        with session_scope() as session:
            leftover_tenants = session.execute(
                text("SELECT COUNT(*) FROM core.tenants WHERE parent_id = :p"),
                {"p": str(child.id)},
            ).scalar_one()
            leftover_ancestry = session.execute(
                text(
                    "SELECT COUNT(*) FROM core.tenant_ancestry a "
                    "JOIN core.tenants t ON t.id = a.tenant_id "
                    "WHERE t.parent_id = :p"
                ),
                {"p": str(child.id)},
            ).scalar_one()
        assert leftover_tenants == 0
        assert leftover_ancestry == 0
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(root.id)
        monkeypatch.delenv("TENANT_MAX_HIERARCHY_DEPTH", raising=False)
        get_tenancy_config.cache_clear()


# --- Concurrency: the actual advisory-lock serialization mechanism ---------


def test_concurrent_children_created_under_the_same_parent_are_all_correct() -> None:
    """Several real threads, each issuing a real, separate `create_tenant(
    parent_id=...)` call against the same parent concurrently -- the
    hierarchy advisory lock (module docstring, `core/tenancy/service.py`)
    must serialize their reads of the parent's ancestry so every child
    ends up with fully correct ancestry, never a torn/partial read."""
    grandparent = create_tenant(_unique_name())
    parent = create_tenant(_unique_name(), parent_id=grandparent.id)
    children: list[uuid.UUID] = []
    try:
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(
                pool.map(lambda _: create_tenant(_unique_name(), parent_id=parent.id), range(5))
            )
        children = [t.id for t in results]

        assert _descendant_ids(parent.id) == {parent.id, *children}
        for child_id in children:
            assert _ancestry_rows(child_id) == {
                child_id: 0,
                parent.id: 1,
                grandparent.id: 2,
            }
    finally:
        for child_id in children:
            _delete_tenant_row(child_id)
        _delete_tenant_row(parent.id)
        _delete_tenant_row(grandparent.id)


def test_concurrent_moves_to_the_same_new_parent_both_end_up_correct() -> None:
    """Two real threads concurrently move two different subtrees to
    become children of the same new parent -- the hierarchy advisory
    lock, held on both `tenant_id` and `new_parent_id` in sorted order
    (module docstring), must serialize the two moves so both closure
    recomputes land correctly rather than racing each other."""
    new_parent = create_tenant(_unique_name())
    old_parent_a = create_tenant(_unique_name())
    old_parent_b = create_tenant(_unique_name())
    subtree_a = create_tenant(_unique_name(), parent_id=old_parent_a.id)
    subtree_b = create_tenant(_unique_name(), parent_id=old_parent_b.id)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(
                pool.map(
                    lambda args: move_tenant(*args),
                    [(subtree_a.id, new_parent.id), (subtree_b.id, new_parent.id)],
                )
            )

        assert _ancestry_rows(subtree_a.id) == {subtree_a.id: 0, new_parent.id: 1}
        assert _ancestry_rows(subtree_b.id) == {subtree_b.id: 0, new_parent.id: 1}
        assert _descendant_ids(new_parent.id) == {new_parent.id, subtree_a.id, subtree_b.id}
    finally:
        _delete_tenant_row(subtree_a.id)
        _delete_tenant_row(subtree_b.id)
        _delete_tenant_row(new_parent.id)
        _delete_tenant_row(old_parent_a.id)
        _delete_tenant_row(old_parent_b.id)


# --- Hierarchy grants no authorization: real RLS, real scratch table -------


@pytest.fixture
def admin_session_factory() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def scratch_table(admin_session_factory: sessionmaker[Session]) -> Iterator[str]:
    table = f"phase_a_hierarchy_probe_{uuid.uuid4().hex[:8]}"
    with session_scope(session_factory=admin_session_factory) as session:
        session.execute(
            text(f"CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL, data TEXT)")
        )
        session.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO "{_APP_ROLE}"'))
        for statement in tenant_rls_statements(table):
            session.execute(text(statement))
    try:
        yield table
    finally:
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(text(f"DROP TABLE IF EXISTS {table}"))


def _insert(table: str, tenant_id: uuid.UUID, data: str) -> None:
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text(f"INSERT INTO {table} (id, tenant_id, data) VALUES (:id, :tid, :d)"),
            {"id": str(uuid.uuid4()), "tid": str(tenant_id), "d": data},
        )


def _visible_data(table: str, tenant_id: uuid.UUID) -> list[str]:
    with tenant_session_scope(tenant_id) as session:
        rows = session.execute(text(f"SELECT data FROM {table} ORDER BY data")).all()
        return [r[0] for r in rows]


def test_parent_tenant_is_not_implicitly_authorized_for_child_data(scratch_table: str) -> None:
    parent = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=parent.id)
    try:
        _insert(scratch_table, child.id, "child-data")
        # Parenthood is real (child.id is a genuine descendant of parent.id)...
        assert child.id in _descendant_ids(parent.id)
        # ...but the existing single-GUC RLS policy is completely
        # unchanged by this phase: the parent's own tenant context still
        # sees only rows literally tagged with parent.id.
        assert _visible_data(scratch_table, parent.id) == []
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(parent.id)


def test_child_tenant_is_not_implicitly_authorized_for_parent_data(scratch_table: str) -> None:
    parent = create_tenant(_unique_name())
    child = create_tenant(_unique_name(), parent_id=parent.id)
    try:
        _insert(scratch_table, parent.id, "parent-data")
        assert _visible_data(scratch_table, child.id) == []
    finally:
        _delete_tenant_row(child.id)
        _delete_tenant_row(parent.id)


def test_sibling_tenants_do_not_become_implicitly_authorized(scratch_table: str) -> None:
    parent = create_tenant(_unique_name())
    sibling_a = create_tenant(_unique_name(), parent_id=parent.id)
    sibling_b = create_tenant(_unique_name(), parent_id=parent.id)
    try:
        _insert(scratch_table, sibling_a.id, "a-data")
        _insert(scratch_table, sibling_b.id, "b-data")
        assert sibling_a.id not in _ancestry_rows(sibling_b.id)
        assert _visible_data(scratch_table, sibling_a.id) == ["a-data"]
        assert _visible_data(scratch_table, sibling_b.id) == ["b-data"]
    finally:
        _delete_tenant_row(sibling_b.id)
        _delete_tenant_row(sibling_a.id)
        _delete_tenant_row(parent.id)
