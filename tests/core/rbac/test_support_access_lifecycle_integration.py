"""PRIV-03 Phase P6 -- support-access authority ends with the tenant
(privacy re-audit finding RA-02), against a real PostgreSQL instance.

The re-audit proved that an approved support grant kept authorizing
`can()` on a DELETED, PURGING and even PURGED tenant: purge retained the
row (correctly -- it is security evidence) but never revoked it, and the
support authorization path never looked at the tenant's lifecycle. These
tests pin the remediation from both sides:

- authority: `can()` through a support grant is refused for every closed
  state (`DELETED`/`PURGING`/`PURGED`), for the target tenant and for a
  `SUBTREE` grant held at a closed ancestor, while an OPEN tenant (and
  `SUSPENDED`, which stays open per P2/P5) keeps working;
- evidence: purge sets `revoked_at` on every live grant, keeps the row,
  leaves never-approved requests untouched, records one existing
  `support_access.revoke` audit entry per grant (SYSTEM actor when the
  purge has no actor, the purge actor otherwise), and does so
  idempotently, under concurrency, and without touching another tenant.

Every persisted-state assertion goes through the privileged migrations
role so RLS cannot hide anything; every action under test runs as the
ordinary application role. Marked `integration`, mirroring
`tests/core/rbac/test_support_access_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_support_access_lifecycle_integration.py
"""

from __future__ import annotations

import contextlib
import threading
import traceback
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import core.rbac.authorization as authz
import pytest
from core.identity.service import add_tenant_membership, create_user
from core.rbac.service import (
    approve_support_access,
    assign_first_role_for_new_tenant,
    create_role,
    create_support_access_request,
    get_support_access_request,
    grant_permission,
    register_permission,
    revoke_tenant_support_access,
)
from core.rbac.support_status import SupportAccessStatus, compute_support_access_status
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import Session, sessionmaker

from core.rbac import RoleScope, can
from core.tenancy import (
    Tenant,
    TenantNotPurgingError,
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

_RESOURCE, _ACTION = "widget", "read"  # an ordinary business permission
_CLOSED = [TenantStatus.DELETED, TenantStatus.PURGING, TenantStatus.PURGED]


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.support_access_requests LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL/core.support_access_requests not reachable: {exc}")
    finally:
        probe_engine.dispose()


@pytest.fixture
def admin() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


def _unique(prefix: str) -> str:
    return f"priv03-p6-{prefix}-{uuid.uuid4().hex[:8]}"


@dataclass
class Rig:
    tenant_id: uuid.UUID
    admin_id: uuid.UUID
    support_id: uuid.UUID
    request_id: uuid.UUID
    user_ids: list[uuid.UUID] = field(default_factory=list)


def _build_rig(
    *,
    parent_id: uuid.UUID | None = None,
    scope_mode: RoleScope = RoleScope.SELF,
    approve: bool = True,
) -> Rig:
    """An ACTIVE tenant with an admin holding the support-management
    capability, a support engineer, and (by default) an approved,
    currently-active support grant."""
    tenant = create_tenant(_unique("tenant"), parent_id=parent_id)
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    admin_user = create_user()
    support_user = create_user()
    membership = add_tenant_membership(tenant.id, admin_user.id)
    role = create_role(tenant.id, "support-admin")
    for action in ("approve", "deny", "revoke"):
        permission = register_permission("support_access_request", action)
        grant_permission(tenant.id, role.id, permission.id)
    assign_first_role_for_new_tenant(tenant.id, membership.id, role.id, scope=RoleScope.SELF)
    request = create_support_access_request(
        requester_user_id=support_user.id,
        tenant_id=tenant.id,
        reason="P6 lifecycle probe",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
        scope_mode=scope_mode,
    )
    if approve:
        approve_support_access(
            approver_user_id=admin_user.id, tenant_id=tenant.id, request_id=request.id
        )
    return Rig(
        tenant_id=tenant.id,
        admin_id=admin_user.id,
        support_id=support_user.id,
        request_id=request.id,
        user_ids=[admin_user.id, support_user.id],
    )


_CLEANUP_ORDER = (
    "core.audit_log",
    "core.membership_roles",
    "core.role_permissions",
    "core.roles",
    "core.tenant_memberships",
    "core.support_access_requests",
    "core.tenant_ancestry",
)


def _teardown(admin: sessionmaker[Session], rigs: list[Rig]) -> None:
    with session_scope(session_factory=admin) as session:
        for rig in rigs:
            for table in _CLEANUP_ORDER:
                session.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
                    {"t": str(rig.tenant_id)},
                )
        # Children before parents (the FK is RESTRICT on parent_id).
        for rig in reversed(rigs):
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(rig.tenant_id)}
            )
        for rig in rigs:
            for uid in rig.user_ids:
                session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(uid)})


def _support_can(rig: Rig, tenant_id: uuid.UUID | None = None) -> bool:
    return can(
        actor_id=rig.support_id,
        tenant_id=tenant_id or rig.tenant_id,
        action=_ACTION,
        resource=_RESOURCE,
    )


def _row(
    admin: sessionmaker[Session], request_id: uuid.UUID
) -> tuple[bool, datetime | None, uuid.UUID | None]:
    with session_scope(session_factory=admin) as session:
        row = session.execute(
            text(
                "SELECT approved_at IS NOT NULL, revoked_at, revoked_by_user_id "
                "FROM core.support_access_requests WHERE id = :id"
            ),
            {"id": str(request_id)},
        ).one()
    return bool(row[0]), row[1], row[2]


def _revoke_audit_rows(
    admin: sessionmaker[Session], rig: Rig
) -> list[tuple[str, uuid.UUID | None, dict]]:
    with session_scope(session_factory=admin) as session:
        rows = session.execute(
            text(
                "SELECT actor_type, actor_user_id, metadata FROM core.audit_log "
                "WHERE tenant_id = :t AND action = 'support_access.revoke' "
                "AND support_access_id = :r ORDER BY created_at"
            ),
            {"t": str(rig.tenant_id), "r": str(rig.request_id)},
        ).all()
    return [(r[0], r[1], r[2] or {}) for r in rows]


def _close(tenant_id: uuid.UUID, status: TenantStatus) -> None:
    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    if status is TenantStatus.PURGING:
        transition_tenant_status(tenant_id, TenantStatus.PURGING)
    elif status is TenantStatus.PURGED:
        purge_tenant(tenant_id)


@pytest.fixture
def rig(admin: sessionmaker[Session]) -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown(admin, [built])


# --- 1. OPEN tenants keep working ----------------------------------------------


def test_approved_grant_authorizes_while_open_and_while_suspended(rig: Rig) -> None:
    assert _support_can(rig) is True
    transition_tenant_status(rig.tenant_id, TenantStatus.SUSPENDED)  # open, per P2/P5
    assert _support_can(rig) is True
    transition_tenant_status(rig.tenant_id, TenantStatus.ACTIVE)
    assert _support_can(rig) is True


# --- 2/3/4. Every closed state refuses support authority ----------------------


@pytest.mark.parametrize("status", _CLOSED)
def test_closed_tenant_refuses_support_authority(status: TenantStatus, rig: Rig) -> None:
    assert _support_can(rig) is True  # sanity: the grant is genuinely live
    _close(rig.tenant_id, status)
    assert get_tenant(rig.tenant_id).status == status.value
    assert _support_can(rig) is False


def test_subtree_grant_at_a_closed_ancestor_does_not_reach_a_live_child(
    admin: sessionmaker[Session],
) -> None:
    parent = _build_rig(scope_mode=RoleScope.SUBTREE)
    child = _build_rig(parent_id=parent.tenant_id, approve=False)
    try:
        assert _support_can(parent, child.tenant_id) is True  # SUBTREE reaches the child
        transition_tenant_status(parent.tenant_id, TenantStatus.DELETED)
        assert _support_can(parent, child.tenant_id) is False
        assert _support_can(parent) is False
        assert get_tenant(child.tenant_id).status == TenantStatus.ACTIVE.value
    finally:
        _teardown(admin, [parent, child])


# --- 5/6. Purge: evidence retained, authority revoked, audited ----------------


def test_purge_revokes_the_grant_keeps_the_row_and_audits_as_system(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    result = purge_tenant(rig.tenant_id)
    assert get_tenant(rig.tenant_id).status == TenantStatus.PURGED.value
    assert result.revoked_support_access_ids == {rig.request_id}

    approved, revoked_at, revoked_by = _row(admin, rig.request_id)
    assert approved and revoked_at is not None and revoked_by is None  # platform revocation
    assert (
        compute_support_access_status(get_support_access_request(rig.tenant_id, rig.request_id))
        is SupportAccessStatus.REVOKED
    )
    assert _support_can(rig) is False

    audit = _revoke_audit_rows(admin, rig)
    assert audit == [("system", None, {"reason": "tenant_purge"})]


def test_purge_with_an_actor_attributes_the_revocation_to_that_actor(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    purge_tenant(rig.tenant_id, actor_user_id=rig.admin_id)
    _, revoked_at, revoked_by = _row(admin, rig.request_id)
    assert revoked_at is not None and revoked_by == rig.admin_id
    assert _revoke_audit_rows(admin, rig) == [("user", rig.admin_id, {"reason": "tenant_purge"})]


def test_never_approved_request_is_left_untouched_by_purge(admin: sessionmaker[Session]) -> None:
    pending = _build_rig(approve=False)
    try:
        transition_tenant_status(pending.tenant_id, TenantStatus.DELETED)
        result = purge_tenant(pending.tenant_id)
        assert result.revoked_support_access_ids == frozenset()
        approved, revoked_at, _ = _row(admin, pending.request_id)
        assert not approved and revoked_at is None
        assert _revoke_audit_rows(admin, pending) == []
        assert _support_can(pending) is False
    finally:
        _teardown(admin, [pending])


def test_revocation_refuses_an_open_tenant(admin: sessionmaker[Session]) -> None:
    open_rig = _build_rig()
    try:
        with pytest.raises(TenantNotPurgingError):
            revoke_tenant_support_access(open_rig.tenant_id)
        assert _support_can(open_rig) is True
    finally:
        _teardown(admin, [open_rig])


# --- 7. Concurrent purge -------------------------------------------------------


def test_concurrent_purges_revoke_exactly_once(rig: Rig, admin: sessionmaker[Session]) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    outcomes: dict[str, object] = {}

    def _run(name: str) -> None:
        try:
            outcomes[name] = purge_tenant(rig.tenant_id)
        except Exception as exc:  # noqa: BLE001 -- asserted below
            outcomes[name] = exc

    threads = [threading.Thread(target=_run, args=(n,)) for n in ("p1", "p2")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not any(isinstance(v, Exception) for v in outcomes.values()), outcomes
    assert get_tenant(rig.tenant_id).status == TenantStatus.PURGED.value
    revoked_sets = [r.revoked_support_access_ids for r in outcomes.values()]  # type: ignore[union-attr]
    assert sorted(revoked_sets, key=len) == [frozenset(), {rig.request_id}]  # exactly one winner
    _, revoked_at, _ = _row(admin, rig.request_id)
    assert revoked_at is not None
    assert len(_revoke_audit_rows(admin, rig)) == 1
    assert _support_can(rig) is False


# --- 8. Cross-tenant isolation -------------------------------------------------


def test_purging_tenant_a_leaves_tenant_b_grant_live(admin: sessionmaker[Session]) -> None:
    a, b = _build_rig(), _build_rig()
    try:
        transition_tenant_status(a.tenant_id, TenantStatus.DELETED)
        result = purge_tenant(a.tenant_id)
        assert result.revoked_support_access_ids == {a.request_id}
        _, b_revoked_at, _ = _row(admin, b.request_id)
        assert b_revoked_at is None
        assert _support_can(b) is True
        assert _support_can(a) is False
        assert _revoke_audit_rows(admin, b) == []
    finally:
        _teardown(admin, [a, b])


# --- 9. Idempotent retry -------------------------------------------------------


def test_purge_retry_and_direct_revocation_retry_are_idempotent(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    first = purge_tenant(rig.tenant_id)
    assert first.revoked_support_access_ids == {rig.request_id}
    _, revoked_at_first, _ = _row(admin, rig.request_id)

    second = purge_tenant(rig.tenant_id)  # already PURGED: no-op
    assert second.already_purged and second.revoked_support_access_ids == frozenset()
    assert revoke_tenant_support_access(rig.tenant_id) == frozenset()  # PURGED: nothing left
    _, revoked_at_again, _ = _row(admin, rig.request_id)
    assert revoked_at_again == revoked_at_first  # never rewritten
    assert len(_revoke_audit_rows(admin, rig)) == 1


# --- 10. Concurrency / TOCTOU: authorization vs. tenant closure ----------------
#
# The support path reads the tenant's lifecycle with `lock_open_tenant()`
# (`core.tenants` row FOR SHARE) *inside the same transaction* as the grant
# query, so it serializes against `transition_tenant_status()`/`purge_tenant()`
# (FOR UPDATE). These tests force each interleaving with real row locks and
# thread events; none of them relies on timing luck.


def _in_support_path() -> bool:
    return any(frame.name == "_tenant_grants_support_access" for frame in traceback.extract_stack())


@contextlib.contextmanager
def _pause_before_grant_transaction(
    tenant_id: uuid.UUID, paused: threading.Event, release: threading.Event
) -> Iterator[None]:
    """Patch the support path's `tenant_session_scope` so that, for
    `tenant_id` only, it signals `paused` and waits for `release` *before*
    opening the transaction that takes the lifecycle lock and queries the
    grant -- i.e. exactly where an unlocked, separately committed status
    pre-read would already have concluded "open"."""
    real_scope = authz.tenant_session_scope

    @contextlib.contextmanager
    def paused_scope(tid: uuid.UUID, **kwargs: object) -> Iterator[Session]:
        if tid == tenant_id and _in_support_path():
            paused.set()
            assert release.wait(timeout=30)
        with real_scope(tid, **kwargs) as session:  # type: ignore[arg-type]
            yield session

    authz.tenant_session_scope = paused_scope  # type: ignore[assignment]
    try:
        yield
    finally:
        authz.tenant_session_scope = real_scope


@contextlib.contextmanager
def _pause_after_lifecycle_lock(
    tenant_id: uuid.UUID, paused: threading.Event, release: threading.Event
) -> Iterator[None]:
    """Patch `lock_open_tenant` as the support path sees it: acquire the
    real FOR SHARE lock, then hold the transaction open (signal `paused`,
    wait for `release`) -- an authorization that reached the lifecycle
    lock first and is still deciding."""
    real_lock = authz.lock_open_tenant

    def locked_then_paused(session: Session, tid: uuid.UUID):  # type: ignore[no-untyped-def]
        tenant = real_lock(session, tid)
        if tid == tenant_id:
            paused.set()
            assert release.wait(timeout=30)
        return tenant

    authz.lock_open_tenant = locked_then_paused  # type: ignore[assignment]
    try:
        yield
    finally:
        authz.lock_open_tenant = real_lock


def _hold_tenant_row_then_write(
    tenant_id: uuid.UUID, status: TenantStatus, ready: threading.Event, release: threading.Event
) -> None:
    """A lifecycle transition in progress: hold the tenant row FOR UPDATE
    (the lock `transition_tenant_status()`/`purge_tenant()` take), let the
    racing caller start, then write `status` and commit."""
    with session_scope() as session:
        row = session.get(Tenant, tenant_id, with_for_update=True)
        assert row is not None
        ready.set()
        assert release.wait(timeout=30)
        row.status = status.value
        session.flush()


def _can_in_thread(rig: Rig, tenant_id: uuid.UUID | None = None) -> tuple[threading.Thread, dict]:
    outcome: dict[str, object] = {}

    def _run() -> None:
        try:
            outcome["allow"] = _support_can(rig, tenant_id)
        except BaseException as exc:  # noqa: BLE001 -- surfaced by the assertions
            outcome["error"] = exc

    thread = threading.Thread(target=_run)
    thread.start()
    return thread, outcome


def test_race_closure_cannot_commit_between_status_read_and_grant_query(rig: Rig) -> None:
    """The critical TOCTOU ordering:

        can(A) is about to read lifecycle + grant
                |          transition(A, DELETED) commits
        can(A) continues
                `-- must NOT return ALLOW

    The pause sits before the support path's transaction, so the closure
    commits first. An implementation that pre-reads the status in a
    separate, already-committed transaction returns True here (proven
    against the unfixed P6 code); the locked in-transaction read sees the
    committed DELETED and denies."""
    paused, release = threading.Event(), threading.Event()
    with _pause_before_grant_transaction(rig.tenant_id, paused, release):
        thread, outcome = _can_in_thread(rig)
        assert paused.wait(timeout=30), "can() never reached the support path"
        transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)  # commits during the pause
        assert get_tenant(rig.tenant_id).status == TenantStatus.DELETED.value
        release.set()
        thread.join(timeout=30)
    assert "error" not in outcome, outcome
    assert outcome["allow"] is False


def test_race_authorization_holding_the_lifecycle_lock_completes_before_closure(rig: Rig) -> None:
    """Interleaving A: the authorization acquires the lifecycle lock first.
    The closure must wait until that decision commits; the decision itself
    (made while the tenant was genuinely open) may succeed. Afterwards the
    closure lands and every later authorization is denied."""
    paused, release = threading.Event(), threading.Event()
    with _pause_after_lifecycle_lock(rig.tenant_id, paused, release):
        auth_thread, outcome = _can_in_thread(rig)
        assert paused.wait(timeout=30)
        closer = threading.Thread(
            target=transition_tenant_status, args=(rig.tenant_id, TenantStatus.DELETED)
        )
        closer.start()
        closer.join(timeout=2)
        assert closer.is_alive(), "the closure must block on the authorization's share lock"
        assert get_tenant(rig.tenant_id).status == TenantStatus.ACTIVE.value
        release.set()
        auth_thread.join(timeout=30)
        closer.join(timeout=30)
    assert outcome["allow"] is True  # decided while open, before the closure committed
    assert get_tenant(rig.tenant_id).status == TenantStatus.DELETED.value
    assert _support_can(rig) is False


def test_race_purge_holding_the_lifecycle_lock_blocks_authorization_until_commit(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    """Interleaving B: the purge holds the tenant row first (PURGING about
    to commit). The authorization blocks on the share lock, then observes
    the committed PURGING and denies -- before the grant row is even
    revoked. The purge then completes and revokes it."""
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)  # graph: only DELETED -> PURGING
    ready, release = threading.Event(), threading.Event()
    holder = threading.Thread(
        target=_hold_tenant_row_then_write,
        args=(rig.tenant_id, TenantStatus.PURGING, ready, release),
    )
    holder.start()
    assert ready.wait(timeout=30)
    thread, outcome = _can_in_thread(rig)
    thread.join(timeout=2)
    assert thread.is_alive(), "the authorization must block on the row the transition holds"
    release.set()
    holder.join(timeout=30)
    thread.join(timeout=30)
    assert outcome["allow"] is False
    _, revoked_at, _ = _row(admin, rig.request_id)
    assert revoked_at is None  # denied purely by lifecycle; the row is still unrevoked
    purge_tenant(rig.tenant_id)
    assert get_tenant(rig.tenant_id).status == TenantStatus.PURGED.value
    _, revoked_at, _ = _row(admin, rig.request_id)
    assert revoked_at is not None


def test_purged_tenant_denies_repeated_concurrent_authorization(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    purge_tenant(rig.tenant_id)
    _, revoked_at, _ = _row(admin, rig.request_id)
    assert get_tenant(rig.tenant_id).status == TenantStatus.PURGED.value and revoked_at is not None
    threads = [_can_in_thread(rig) for _ in range(24)]
    for thread, _ in threads:
        thread.join(timeout=60)
    outcomes = [outcome for _, outcome in threads]
    assert all("error" not in o for o in outcomes), outcomes
    assert [o["allow"] for o in outcomes] == [False] * 24


def test_race_subtree_grant_at_a_closing_ancestor_cannot_reach_the_child(
    admin: sessionmaker[Session],
) -> None:
    """A SUBTREE grant on parent A reaches child B only while A is open.
    Both interleavings against A's closure, evaluated for B: the lifecycle
    lock is taken on the *candidate* (the ancestor holding the grant), so
    a closing ancestor serializes with a descendant's authorization."""
    parent = _build_rig(scope_mode=RoleScope.SUBTREE)
    child = _build_rig(parent_id=parent.tenant_id, approve=False)
    try:
        assert _support_can(parent, child.tenant_id) is True

        # Critical ordering: A's closure commits while B's check is paused
        # just before A's grant transaction.
        paused, release = threading.Event(), threading.Event()
        with _pause_before_grant_transaction(parent.tenant_id, paused, release):
            thread, outcome = _can_in_thread(parent, child.tenant_id)
            assert paused.wait(timeout=30)
            transition_tenant_status(parent.tenant_id, TenantStatus.DELETED)
            release.set()
            thread.join(timeout=30)
        assert outcome["allow"] is False

        # Purge-first: A's row held FOR UPDATE (PURGING pending); B's check
        # blocks on it, then denies. (A has a live child, so this models the
        # PURGING write itself, not a full purge_tenant() run.)
        ready, release2 = threading.Event(), threading.Event()
        holder = threading.Thread(
            target=_hold_tenant_row_then_write,
            args=(parent.tenant_id, TenantStatus.PURGING, ready, release2),
        )
        holder.start()
        assert ready.wait(timeout=30)
        thread, outcome = _can_in_thread(parent, child.tenant_id)
        thread.join(timeout=2)
        assert thread.is_alive()
        release2.set()
        holder.join(timeout=30)
        thread.join(timeout=30)
        assert outcome["allow"] is False
        assert get_tenant(child.tenant_id).status == TenantStatus.ACTIVE.value
    finally:
        _teardown(admin, [parent, child])


def test_tenant_b_authorizes_normally_while_tenant_a_is_locked_for_closure(
    admin: sessionmaker[Session],
) -> None:
    """No global or cross-tenant serialization: with A's tenant row held
    FOR UPDATE by an in-flight closure, B's support authorization completes
    promptly and succeeds; A's is denied once the closure wins."""
    a, b = _build_rig(), _build_rig()
    try:
        ready, release = threading.Event(), threading.Event()
        holder = threading.Thread(
            target=_hold_tenant_row_then_write,
            args=(a.tenant_id, TenantStatus.DELETED, ready, release),
        )
        holder.start()
        assert ready.wait(timeout=30)
        b_thread, b_outcome = _can_in_thread(b)
        b_thread.join(timeout=5)
        assert not b_thread.is_alive(), "B must not wait on A's lifecycle lock"
        assert b_outcome["allow"] is True
        a_thread, a_outcome = _can_in_thread(a)
        a_thread.join(timeout=2)
        assert a_thread.is_alive()
        release.set()
        holder.join(timeout=30)
        a_thread.join(timeout=30)
        assert a_outcome["allow"] is False
        assert _support_can(b) is True
    finally:
        _teardown(admin, [a, b])
