"""Foundation Authority & Evidence -- the authorization decision and the
protected mutation share ONE transaction (ADR-0031 MEDIUM remediation).

Before this fix `authorize_caller()`/`can()` ran in their own, already
committed transactions, and the mutation opened a fresh one afterwards. A
revocation could therefore commit *between* the decision and the write:

    A: can() -> True (committed, locks released)
    B: revoke the authority A relied on; COMMIT
    A: mutate + audit using authority that no longer exists; COMMIT

Now every protected mutation passes its own session to `can()`, which
evaluates the decision inside that transaction and holds the authoritative
rows (`FOR SHARE`) until the mutation commits; a deny -- an insert, with no
row to lock -- takes the denied principal's row exclusively instead.

Each test below forces one ordering with real PostgreSQL row locks, two
connections, and thread events -- never a sleep or a timing guess. A pause
gate stops one transaction at a chosen point (after its write is flushed,
before its audit entry and COMMIT); the test then waits until PostgreSQL
itself reports the other backend blocked by that one (`pg_blocking_pids`).

- **Mutation first**: the revocation waits for the authorized mutation to
  commit; the mutation and its audit entry land; the revocation then lands
  and the actor is no longer authorized. (Against the pre-fix code the
  revocation never blocks -- `_wait_until_blocked_by()` fails.)
- **Revocation first**: the mutation's authorization waits for the
  revocation to commit, then observes it: the mutation is refused, nothing
  is written, and no success audit entry exists.

Covered families: role (via role-assignment removal and via permission
revocation), membership, explicit deny (a concurrent deny against the actor
-- the phantom-insert case), delegation, support access, API key,
service account (a service-account actor being disabled), user
deactivation (`User.is_active`), and tenant re-parenting (`move_tenant()`
of the target's ancestor under a tenant holding a `SUBTREE` deny against
the actor -- both a root ancestor, where the move only *inserts* ancestry
rows, and a non-root control).

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import Session

import saas_os.core.api_keys.service as api_keys_service
import saas_os.core.identity.service as identity_service
import saas_os.core.rbac.authorization as authz
import saas_os.core.rbac.service as rbac_service
import saas_os.core.tenancy.service as tenancy_service
from saas_os.core.api_keys import create_service_account_api_key, list_api_keys
from saas_os.core.api_keys.errors import ApiKeyNotAuthorizedError
from saas_os.core.authority import ServiceAccountCaller, SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity.service import (
    add_tenant_membership,
    create_service_account,
    create_user,
    disable_service_account,
    get_membership,
    list_service_accounts,
    suspend_membership,
)
from saas_os.core.rbac import PrincipalType, can
from saas_os.core.rbac.errors import (
    AuthorityNotAuthorizedError,
    DenyNotAuthorizedError,
    SupportAccessNotAuthorizedError,
)
from saas_os.core.rbac.models import MembershipRole
from saas_os.core.rbac.scope import RoleScope
from saas_os.core.rbac.service import (
    approve_support_access,
    assign_first_role_for_new_tenant,
    assign_service_account_role,
    create_delegation,
    create_deny,
    create_role,
    create_support_access_request,
    get_support_access_request,
    grant_permission,
    list_denies_for_principal,
    list_roles,
    register_permission,
    remove_role,
    revoke_delegation,
    revoke_permission,
)
from saas_os.core.tenancy import create_tenant, move_tenant
from saas_os.infra.db import tenant_session_scope
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine
from saas_os.infra.db.session import build_session_factory, session_scope

pytestmark = pytest.mark.integration

PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_TENANT_TABLES = (
    "audit_log",
    "api_keys",
    "service_account_roles",
    "membership_roles",
    "role_permissions",
    "delegation_grants",
    "deny_grants",
    "support_access_requests",
    "invitations",
    "roles",
    "service_accounts",
    "tenant_memberships",
    "tenant_ancestry",
)


@pytest.fixture(autouse=True)
def _require_database() -> None:
    get_database_config.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.roles LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable/migrated: {exc}")
    finally:
        engine.dispose()


@pytest.fixture
def admin() -> Iterator[Engine]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield engine
    finally:
        engine.dispose()


def _admin_execute(engine: Engine, sql: str, params: Mapping[str, object]) -> list[tuple[Any, ...]]:
    with session_scope(session_factory=build_session_factory(engine)) as session:
        result = session.execute(text(sql), params)
        return [tuple(row) for row in result] if sql.lstrip().upper().startswith("SELECT") else []


# --- World: tenants and principals, provisioned with explicit authority ------


@dataclass(frozen=True)
class Principal:
    caller: UserCaller
    membership_id: uuid.UUID
    role_id: uuid.UUID

    @property
    def user_id(self) -> uuid.UUID:
        return self.caller.user_id


@dataclass
class World:
    admin: Engine
    tenants: list[uuid.UUID] = field(default_factory=list)
    users: list[uuid.UUID] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)

    def tenant(self) -> uuid.UUID:
        tenant_id = create_tenant(f"race-{uuid.uuid4().hex[:10]}").id
        self.tenants.append(tenant_id)
        return tenant_id

    def user(self) -> uuid.UUID:
        user_id = create_user().id
        self.users.append(user_id)
        return user_id

    def resource(self) -> str:
        name = f"raceprobe-{uuid.uuid4().hex[:8]}"
        self.resources.append(name)
        return name

    def principal(self, tenant_id: uuid.UUID, *capabilities: tuple[str, str]) -> Principal:
        user_id = self.user()
        membership = add_tenant_membership(tenant_id, user_id, caller=PROVISIONING)
        role = create_role(tenant_id, f"role-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        for resource, action in capabilities:
            permission = register_permission(resource, action)
            grant_permission(tenant_id, role.id, permission.id, caller=PROVISIONING)
        assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=PROVISIONING)
        return Principal(UserCaller(user_id), membership.id, role.id)

    def service_account(
        self, tenant_id: uuid.UUID, *capabilities: tuple[str, str]
    ) -> ServiceAccountCaller:
        account = create_service_account(
            tenant_id, f"sa-{uuid.uuid4().hex[:8]}", caller=PROVISIONING
        )
        granter = self.principal(tenant_id, ("service_account_role", "create"), *capabilities)
        role = create_role(tenant_id, f"sa-role-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        for resource, action in capabilities:
            permission = register_permission(resource, action)
            grant_permission(tenant_id, role.id, permission.id, caller=PROVISIONING)
        assign_service_account_role(
            caller=granter.caller,
            tenant_id=tenant_id,
            service_account_id=account.id,
            role_id=role.id,
        )
        return ServiceAccountCaller(account.id, tenant_id)

    def cleanup(self) -> None:
        for tenant_id in reversed(self.tenants):
            for table in _TENANT_TABLES:
                _admin_execute(
                    self.admin,
                    f"DELETE FROM core.{table} WHERE tenant_id = :t",  # noqa: S608 -- fixed names
                    {"t": str(tenant_id)},
                )
            _admin_execute(
                self.admin, "DELETE FROM core.tenants WHERE id = :t", {"t": str(tenant_id)}
            )
        for user_id in self.users:
            params = {"u": str(user_id)}
            _admin_execute(
                self.admin, "DELETE FROM core.audit_log WHERE actor_user_id = :u", params
            )
            _admin_execute(self.admin, "DELETE FROM core.sessions WHERE user_id = :u", params)
            _admin_execute(self.admin, "DELETE FROM core.users WHERE id = :u", params)
        for resource in self.resources:
            _admin_execute(
                self.admin, "DELETE FROM core.permissions WHERE resource = :r", {"r": resource}
            )


@pytest.fixture
def world(admin: Engine) -> Iterator[World]:
    w = World(admin)
    try:
        yield w
    finally:
        w.cleanup()


# --- The pause gate ------------------------------------------------------------


class Gate:
    """Stops the transaction running on thread `thread_name` the first time
    it reaches `checkpoint()` -- with every lock it has taken so far still
    held -- and records that transaction's backend pid."""

    def __init__(self, thread_name: str) -> None:
        self.thread_name = thread_name
        self.paused = threading.Event()
        self.release = threading.Event()
        self.pid: int | None = None
        self._fired = False

    def checkpoint(self, session: Session) -> None:
        if threading.current_thread().name != self.thread_name or self._fired:
            return
        self._fired = True
        self.pid = session.execute(text("SELECT pg_backend_pid()")).scalar_one()
        self.paused.set()
        assert self.release.wait(timeout=60), "gate never released"


_ACTIVE_GATE: list[Gate] = []


def _checkpoint(session: Session) -> None:
    for gate in _ACTIVE_GATE:
        gate.checkpoint(session)


@pytest.fixture
def gate_at_audit(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[str], Gate]]:
    """Install a gate at `record_in_transaction()` -- i.e. after the
    operation's write has been flushed in its transaction, before its audit
    entry and COMMIT -- in every service module the scenarios use. A
    `move_tenant()` writes no audit entry; its gate is right after it has
    locked the moved subtree's tenant rows, before any ancestry write and
    COMMIT."""

    def install(thread_name: str) -> Gate:
        gate = Gate(thread_name)
        _ACTIVE_GATE.append(gate)
        for module in (rbac_service, identity_service, api_keys_service):
            real = module.record_in_transaction

            def gated(session: Session, *args: Any, _real: Any = real, **kwargs: Any) -> Any:
                _checkpoint(session)
                return _real(session, *args, **kwargs)

            monkeypatch.setattr(module, "record_in_transaction", gated)
        real_lock = tenancy_service._lock_subtree_tenant_rows

        def gated_lock(session: Session, *args: Any, **kwargs: Any) -> None:
            real_lock(session, *args, **kwargs)
            _checkpoint(session)

        monkeypatch.setattr(tenancy_service, "_lock_subtree_tenant_rows", gated_lock)
        return gate

    yield install
    _ACTIVE_GATE.clear()


def _start(fn: Callable[[], object], name: str) -> tuple[threading.Thread, dict[str, Any]]:
    outcome: dict[str, Any] = {}

    def _run() -> None:
        try:
            outcome["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 -- surfaced by the assertions
            outcome["error"] = exc

    thread = threading.Thread(target=_run, name=name)
    thread.start()
    return thread, outcome


def _wait_until_blocked_by(admin: Engine, blocker_pid: int | None) -> None:
    """Wait (bounded) until PostgreSQL reports some backend waiting on a
    lock held by `blocker_pid`. A fresh transaction per probe:
    `pg_stat_activity` is snapshotted per transaction."""
    assert blocker_pid is not None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with admin.connect() as conn:
            blocked = conn.execute(
                text("SELECT pid FROM pg_stat_activity WHERE :p = ANY(pg_blocking_pids(pid))"),
                {"p": blocker_pid},
            ).all()
        if blocked:
            return
        threading.Event().wait(0.02)
    raise AssertionError(f"no backend ever blocked on pid {blocker_pid}'s locks")


def _audit_count(admin: Engine, tenant_id: uuid.UUID, action: str, actor_id: uuid.UUID) -> int:
    rows = _admin_execute(
        admin,
        "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t AND action = :a "
        "AND (actor_user_id = :x OR actor_service_account_id = :x)",
        {"t": str(tenant_id), "a": action, "x": str(actor_id)},
    )
    return int(rows[0][0])


# --- Scenarios -----------------------------------------------------------------


@dataclass
class Race:
    tenant_id: uuid.UUID
    actor_id: uuid.UUID
    mutate: Callable[[], object]
    mutation_audit: str
    mutated: Callable[[], bool]
    denied_error: type[Exception]
    revoke: Callable[[], object]
    still_authorized: Callable[[], bool]


def _user_can(tenant_id: uuid.UUID, user_id: uuid.UUID, resource: str, action: str) -> bool:
    return can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)


def _role_race(w: World, *, revoke_by: str) -> Race:
    tenant_id = w.tenant()
    actor = w.principal(tenant_id, ("role", "create"))
    name = f"race-role-{uuid.uuid4().hex[:8]}"
    if revoke_by == "remove_role":
        revoker = w.principal(tenant_id, ("membership_role", "delete"))

        def revoke() -> object:
            return remove_role(tenant_id, actor.membership_id, actor.role_id, caller=revoker.caller)

    else:
        revoker = w.principal(tenant_id, ("role_permission", "revoke"))
        permission = register_permission("role", "create")

        def revoke() -> object:
            return revoke_permission(tenant_id, actor.role_id, permission.id, caller=revoker.caller)

    return Race(
        tenant_id=tenant_id,
        actor_id=actor.user_id,
        mutate=lambda: create_role(tenant_id, name, caller=actor.caller),
        mutation_audit="role.create",
        mutated=lambda: name in {role.name for role in list_roles(tenant_id)},
        denied_error=AuthorityNotAuthorizedError,
        revoke=revoke,
        still_authorized=lambda: _user_can(tenant_id, actor.user_id, "role", "create"),
    )


def _membership_race(w: World) -> Race:
    tenant_id = w.tenant()
    actor = w.principal(tenant_id, ("membership", "suspend"))
    target = w.principal(tenant_id)
    revoker = w.principal(tenant_id, ("membership", "suspend"))
    return Race(
        tenant_id=tenant_id,
        actor_id=actor.user_id,
        mutate=lambda: suspend_membership(tenant_id, target.membership_id, caller=actor.caller),
        mutation_audit="membership.suspend",
        mutated=lambda: (
            getattr(get_membership(tenant_id, target.user_id), "status", None) == "suspended"
        ),
        denied_error=AuthorityNotAuthorizedError,
        revoke=lambda: suspend_membership(tenant_id, actor.membership_id, caller=revoker.caller),
        still_authorized=lambda: _user_can(tenant_id, actor.user_id, "membership", "suspend"),
    )


def _deny_race(w: World) -> Race:
    """The revocation is itself a *new* deny against the actor -- an insert,
    so there is no pre-existing row the actor's decision could have locked;
    the principal-row lock is what serializes it."""
    tenant_id = w.tenant()
    actor = w.principal(tenant_id, ("deny_grant", "create"))
    revoker = w.principal(tenant_id, ("deny_grant", "create"))
    target_user_id = w.user()
    probe = register_permission(w.resource(), "read")
    deny_create = register_permission("deny_grant", "create")
    return Race(
        tenant_id=tenant_id,
        actor_id=actor.user_id,
        mutate=lambda: create_deny(
            caller=actor.caller,
            principal_user_id=target_user_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=probe.id,
        ),
        mutation_audit="deny.create",
        mutated=lambda: len(list_denies_for_principal(tenant_id, target_user_id)) == 1,
        denied_error=DenyNotAuthorizedError,
        revoke=lambda: create_deny(
            caller=revoker.caller,
            principal_user_id=actor.user_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=deny_create.id,
        ),
        still_authorized=lambda: _user_can(tenant_id, actor.user_id, "deny_grant", "create"),
    )


def _delegation_race(w: World) -> Race:
    tenant_id = w.tenant()
    delegator = w.principal(tenant_id, ("role", "create"), ("delegation_grant", "create"))
    actor = UserCaller(w.user())  # no membership: authority is the delegation alone
    grant = create_delegation(
        caller=delegator.caller,
        delegate_user_id=actor.user_id,
        tenant_id=tenant_id,
        scope_mode=RoleScope.SELF,
        permission_id=register_permission("role", "create").id,
    )
    name = f"race-role-{uuid.uuid4().hex[:8]}"
    return Race(
        tenant_id=tenant_id,
        actor_id=actor.user_id,
        mutate=lambda: create_role(tenant_id, name, caller=actor),
        mutation_audit="role.create",
        mutated=lambda: name in {role.name for role in list_roles(tenant_id)},
        denied_error=AuthorityNotAuthorizedError,
        revoke=lambda: revoke_delegation(
            caller=delegator.caller, tenant_id=tenant_id, delegation_grant_id=grant.id
        ),
        still_authorized=lambda: _user_can(tenant_id, actor.user_id, "role", "create"),
    )


def _support_access_race(w: World) -> Race:
    tenant_id = w.tenant()
    approver = w.principal(tenant_id, ("support_access_request", "approve"))
    revoker = w.principal(tenant_id, ("membership_role", "delete"))
    request = create_support_access_request(
        caller=UserCaller(w.user()),
        tenant_id=tenant_id,
        reason="race regression",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    return Race(
        tenant_id=tenant_id,
        actor_id=approver.user_id,
        mutate=lambda: approve_support_access(
            caller=approver.caller, tenant_id=tenant_id, request_id=request.id
        ),
        mutation_audit="support_access.approve",
        mutated=lambda: get_support_access_request(tenant_id, request.id).approved_at is not None,
        denied_error=SupportAccessNotAuthorizedError,
        revoke=lambda: remove_role(
            tenant_id, approver.membership_id, approver.role_id, caller=revoker.caller
        ),
        still_authorized=lambda: _user_can(
            tenant_id, approver.user_id, "support_access_request", "approve"
        ),
    )


def _api_key_race(w: World) -> Race:
    tenant_id = w.tenant()
    actor = w.principal(tenant_id, ("api_key", "create"))
    revoker = w.principal(tenant_id, ("membership_role", "delete"))
    account = create_service_account(tenant_id, f"sa-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
    key_name = f"race-key-{uuid.uuid4().hex[:8]}"
    return Race(
        tenant_id=tenant_id,
        actor_id=actor.user_id,
        mutate=lambda: create_service_account_api_key(
            caller=actor.caller,
            tenant_id=tenant_id,
            service_account_id=account.id,
            name=key_name,
        ),
        mutation_audit="api_key.create",
        mutated=lambda: any(key.name == key_name for key in list_api_keys(tenant_id)),
        denied_error=ApiKeyNotAuthorizedError,
        revoke=lambda: remove_role(
            tenant_id, actor.membership_id, actor.role_id, caller=revoker.caller
        ),
        still_authorized=lambda: _user_can(tenant_id, actor.user_id, "api_key", "create"),
    )


def _service_account_race(w: World) -> Race:
    """A service-account actor, authorized through its own role, is
    disabled concurrently."""
    tenant_id = w.tenant()
    actor = w.service_account(tenant_id, ("service_account", "create"))
    revoker = w.principal(tenant_id, ("service_account", "disable"))
    name = f"race-sa-{uuid.uuid4().hex[:8]}"
    return Race(
        tenant_id=tenant_id,
        actor_id=actor.service_account_id,
        mutate=lambda: create_service_account(tenant_id, name, caller=actor),
        mutation_audit="service_account.create",
        mutated=lambda: name in {account.name for account in list_service_accounts(tenant_id)},
        denied_error=AuthorityNotAuthorizedError,
        revoke=lambda: disable_service_account(
            tenant_id, actor.service_account_id, caller=revoker.caller
        ),
        still_authorized=lambda: can(
            actor_id=actor.service_account_id,
            tenant_id=tenant_id,
            action="create",
            resource="service_account",
            actor_type=PrincipalType.SERVICE_ACCOUNT,
            actor_tenant_id=tenant_id,
        ),
    )


def _user_deactivation_race(w: World) -> Race:
    """`User.is_active` flipped by a concurrent platform-level write."""
    tenant_id = w.tenant()
    actor = w.principal(tenant_id, ("role", "create"))
    name = f"race-role-{uuid.uuid4().hex[:8]}"

    def deactivate() -> None:
        with session_scope(session_factory=build_session_factory(w.admin)) as session:
            session.execute(
                text("UPDATE core.users SET is_active = false WHERE id = :u"),
                {"u": str(actor.user_id)},
            )
            _checkpoint(session)

    return Race(
        tenant_id=tenant_id,
        actor_id=actor.user_id,
        mutate=lambda: create_role(tenant_id, name, caller=actor.caller),
        mutation_audit="role.create",
        mutated=lambda: name in {role.name for role in list_roles(tenant_id)},
        denied_error=AuthorityNotAuthorizedError,
        revoke=deactivate,
        still_authorized=lambda: _user_can(tenant_id, actor.user_id, "role", "create"),
    )


def _tenant_move_race(w: World, *, root_ancestor: bool) -> Race:
    """The revocation is a re-parenting: `move_tenant(ancestor, destination)`
    where `destination` holds a `SUBTREE` deny against the actor, so after
    the move the actor is denied at `tenant_id`. With `root_ancestor` the
    ancestor has no parent: the move deletes no ancestry row the decision
    could have locked, it only inserts -- the tenant-row lock is what
    serializes it. Tenants are registered destination/parent first so
    cleanup (reverse order) removes children before their parents."""
    destination = w.tenant()
    parent = None if root_ancestor else w.tenant()
    ancestor = create_tenant(f"race-anc-{uuid.uuid4().hex[:8]}", parent_id=parent).id
    w.tenants.append(ancestor)
    tenant_id = create_tenant(f"race-t-{uuid.uuid4().hex[:8]}", parent_id=ancestor).id
    w.tenants.append(tenant_id)
    actor = w.principal(tenant_id, ("role", "create"))
    granter = w.principal(destination, ("deny_grant", "create"))
    create_deny(
        caller=granter.caller,
        principal_user_id=actor.user_id,
        tenant_id=destination,
        scope_mode=RoleScope.SUBTREE,
        permission_id=register_permission("role", "create").id,
    )
    name = f"race-role-{uuid.uuid4().hex[:8]}"
    return Race(
        tenant_id=tenant_id,
        actor_id=actor.user_id,
        mutate=lambda: create_role(tenant_id, name, caller=actor.caller),
        mutation_audit="role.create",
        mutated=lambda: name in {role.name for role in list_roles(tenant_id)},
        denied_error=AuthorityNotAuthorizedError,
        revoke=lambda: move_tenant(ancestor, destination),
        still_authorized=lambda: _user_can(tenant_id, actor.user_id, "role", "create"),
    )


_RACES: dict[str, Callable[[World], Race]] = {
    "role-via-remove-role": lambda w: _role_race(w, revoke_by="remove_role"),
    "role-via-revoke-permission": lambda w: _role_race(w, revoke_by="revoke_permission"),
    "membership": _membership_race,
    "deny": _deny_race,
    "delegation": _delegation_race,
    "support-access": _support_access_race,
    "api-key": _api_key_race,
    "service-account": _service_account_race,
    "user-deactivation": _user_deactivation_race,
    "tenant-move-root-ancestor": lambda w: _tenant_move_race(w, root_ancestor=True),
    "tenant-move-non-root-ancestor": lambda w: _tenant_move_race(w, root_ancestor=False),
}


# --- Ordering A: the mutation's authorization wins -----------------------------


@pytest.mark.parametrize("scenario", list(_RACES))
def test_revocation_waits_for_an_already_authorized_mutation_to_commit(
    scenario: str, world: World, gate_at_audit: Callable[[str], Gate]
) -> None:
    race = _RACES[scenario](world)
    assert race.still_authorized() is True

    gate = gate_at_audit("mutation")
    mutation, mutation_outcome = _start(race.mutate, "mutation")
    assert gate.paused.wait(timeout=30), "the mutation never reached its audit write"

    # The mutation is authorized and has written, but not committed. The
    # revocation must now wait on the rows that decision locked.
    revocation, revocation_outcome = _start(race.revoke, "revocation")
    _wait_until_blocked_by(world.admin, gate.pid)
    assert revocation.is_alive()
    assert race.still_authorized() is True  # nothing revoked has committed

    gate.release.set()
    mutation.join(timeout=30)
    revocation.join(timeout=30)

    assert "error" not in mutation_outcome, mutation_outcome
    assert "error" not in revocation_outcome, revocation_outcome
    assert race.mutated() is True
    assert _audit_count(world.admin, race.tenant_id, race.mutation_audit, race.actor_id) == 1
    assert race.still_authorized() is False  # the revocation landed after


# --- Ordering B: the revocation wins -------------------------------------------


@pytest.mark.parametrize("scenario", list(_RACES))
def test_mutation_authorization_observes_a_revocation_that_committed_first(
    scenario: str, world: World, gate_at_audit: Callable[[str], Gate]
) -> None:
    race = _RACES[scenario](world)
    assert race.still_authorized() is True

    gate = gate_at_audit("revocation")
    revocation, revocation_outcome = _start(race.revoke, "revocation")
    assert gate.paused.wait(timeout=30), "the revocation never reached its checkpoint"

    # The revocation has written but not committed; the mutation's
    # authorization must wait for it rather than read the old state.
    mutation, mutation_outcome = _start(race.mutate, "mutation")
    _wait_until_blocked_by(world.admin, gate.pid)
    assert mutation.is_alive()

    gate.release.set()
    revocation.join(timeout=30)
    mutation.join(timeout=30)

    assert "error" not in revocation_outcome, revocation_outcome
    assert isinstance(mutation_outcome.get("error"), race.denied_error), mutation_outcome
    assert race.mutated() is False
    assert _audit_count(world.admin, race.tenant_id, race.mutation_audit, race.actor_id) == 0
    assert race.still_authorized() is False


# --- The decision opens no transaction of its own ------------------------------


def test_a_protected_mutation_authorizes_without_opening_another_session(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With `session=` supplied, `can()` must neither open a session nor
    leave the mutation's transaction bound to another tenant's RLS scope
    -- even after walking an ancestor chain."""
    parent = world.tenant()
    child = create_tenant(f"race-child-{uuid.uuid4().hex[:8]}", parent_id=parent).id
    world.tenants.append(child)
    actor = world.principal(parent, ("role", "create"))
    # A SUBTREE assignment at the parent: the decision for `child` must
    # read rows at both tenants.
    subtree_role = create_role(parent, f"subtree-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
    grant_permission(
        parent, subtree_role.id, register_permission("role", "create").id, caller=PROVISIONING
    )
    with tenant_session_scope(parent) as session:
        session.add(
            MembershipRole(
                tenant_id=parent,
                membership_id=actor.membership_id,
                role_id=subtree_role.id,
                scope=RoleScope.SUBTREE.value,
            )
        )

    def no_new_session(*_: object, **__: object) -> object:
        raise AssertionError("can() opened its own session inside a protected mutation")

    monkeypatch.setattr(authz, "session_scope", no_new_session)

    with tenant_session_scope(child) as session:
        assert (
            can(
                actor_id=actor.user_id,
                tenant_id=child,
                action="create",
                resource="role",
                session=session,
            )
            is True
        )
        bound = session.execute(text("SELECT current_setting('app.tenant_id', true)")).scalar()
        assert bound == str(child)

    name = f"race-role-{uuid.uuid4().hex[:8]}"
    create_role(child, name, caller=actor.caller)
    assert name in {role.name for role in list_roles(child)}
