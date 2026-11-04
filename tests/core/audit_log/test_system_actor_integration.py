"""ADR 0061 step 1 -- `SystemActor` attribution against a real PostgreSQL.

- `record_system_action_in_transaction()` writes the executing actor, the
  initiating actor and the correlation (owner decision C) in the caller's
  own transaction: committed with it, rolled back with it.
- A `SystemCaller(..., actor=...)` writes the actor next to its purpose.
- The row's tenant is the session's verified tenant; a row aimed at
  another tenant fails closed (Row-Level Security), whatever the actor.
- An actorless successful `system` row through `record()` is still
  written, with the deprecation warning (nothing is refused yet).
- Every exported Core function that takes a `caller` refuses a
  `SystemActor` in its place.
- The audit digest verifies rows carrying the new metadata, and still finds
  a change to the actor.

Marked `integration`.
"""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import enum
import importlib
import inspect
import pkgutil
import typing
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

import saas_os.core
from lifecycle_callers import PROVISIONING
from saas_os.core.audit_digest import (
    LoggedRecord,
    build_record,
    compute_windows,
    record_digest,
    verify_records,
)
from saas_os.core.audit_log import (
    ActorType,
    AuditLogEntry,
    AuditOutcome,
    InvalidActorError,
    get,
    record,
    record_in_transaction,
    record_system_action_in_transaction,
)
from saas_os.core.authority import (
    CallerTypeError,
    Initiator,
    SystemActor,
    SystemActorKind,
    SystemAuthority,
    SystemCaller,
    SystemCorrelation,
)
from saas_os.core.billing.errors import BillingActorRequiredError
from saas_os.core.platform_authority import PlatformNotAuthorizedError
from saas_os.core.platform_authority.operations import (
    PERMISSION_GRANT_LEDGER_APPROVER_REVOKE_BY_SECURITY,
)
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db import select
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import tenant_session_scope

pytestmark = pytest.mark.integration

_ACTOR = SystemActor(SystemActorKind.WORKER_JOB, "nightly_export")


def _admin(statement: str, **params: object) -> builtins.list[tuple[object, ...]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(statement), params)
            return [tuple(row) for row in result.all()] if result.returns_rows else []
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _require_migrated_database() -> None:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.audit_log LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"migrated PostgreSQL not reachable: {exc}")
    finally:
        probe.dispose()


@pytest.fixture
def tenants() -> typing.Iterator[builtins.list[uuid.UUID]]:
    """Two fresh tenants; every row this file wrote for them is removed
    afterwards with the migrations role (the runtime role cannot delete
    audit rows), so later migration downgrades in a shared database are
    not blocked."""
    created = [
        create_tenant(f"sysactor-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id for _ in (1, 2)
    ]
    try:
        yield created
    finally:
        ids = [str(t) for t in created]
        _admin(
            "DELETE FROM core.audit_log WHERE tenant_id::text = ANY(:t) "
            "OR acting_as_tenant_id::text = ANY(:t)",
            t=ids,
        )
        _admin("DELETE FROM core.platform_audit_log WHERE target_tenant_id::text = ANY(:t)", t=ids)
        _admin("DELETE FROM core.tenants WHERE id::text = ANY(:t)", t=ids)


def _rows(tenant_id: uuid.UUID, action: str) -> builtins.list[AuditLogEntry]:
    with tenant_session_scope(tenant_id) as session:
        entries = (
            session.execute(
                select(AuditLogEntry)
                .where(AuditLogEntry.tenant_id == tenant_id)
                .where(AuditLogEntry.action == action)
            )
            .scalars()
            .all()
        )
        for entry in entries:
            session.expunge(entry)
        return builtins.list(entries)


# --- Same transaction -----------------------------------------------------------------


def test_the_actor_is_committed_with_the_callers_transaction(
    tenants: builtins.list[uuid.UUID],
) -> None:
    tenant = tenants[0]
    account_id = uuid.uuid4()
    with tenant_session_scope(tenant) as session:
        entry = record_system_action_in_transaction(
            session,
            tenant_id=tenant,
            actor=_ACTOR,
            action="test.system_actor.committed",
            resource_type="export",
            resource_id="e-1",
            correlation_id="corr-sa-1",
            metadata={"rows": 2},
            initiated_by=Initiator.service_account(account_id),
            correlation=SystemCorrelation(arq_job_id="job-1", request_id="corr-sa-1"),
        )
        entry_id = entry.id
    stored = get(tenant, entry_id)
    assert stored.actor_type == ActorType.SYSTEM.value
    assert stored.actor_user_id is None and stored.actor_service_account_id is None
    assert stored.tenant_id == tenant
    assert stored.correlation_id == "corr-sa-1"
    assert stored.entry_metadata == {
        "rows": 2,
        "system_actor": {"kind": "worker_job", "name": "nightly_export"},
        "initiated_by": {"type": "service_account", "service_account_id": str(account_id)},
        "correlation": {"arq_job_id": "job-1", "request_id": "corr-sa-1"},
    }

    # Owner decision D2 (2026-11-02): a user initiator is refused before
    # the insert, by both writers, and the caller's transaction commits
    # nothing of it -- not even the mutation it was meant to describe.
    user_id = uuid.uuid4()
    for action, write in (
        (
            "test.system_actor.d2_system_action",
            lambda session, action: record_system_action_in_transaction(
                session,
                tenant_id=tenant,
                actor=_ACTOR,
                action=action,
                resource_type="export",
                initiated_by=Initiator.user(user_id),
            ),
        ),
        (
            "test.system_actor.d2_system_caller",
            lambda session, action: record_in_transaction(
                session,
                caller=SystemCaller(SystemAuthority.PROVISIONING, actor=_ACTOR),
                tenant_id=tenant,
                action=action,
                resource_type="export",
                initiated_by=Initiator.user(user_id),
            ),
        ),
    ):
        with pytest.raises(InvalidActorError) as refused, tenant_session_scope(tenant) as session:
            record_system_action_in_transaction(
                session,
                tenant_id=tenant,
                actor=_ACTOR,
                action=f"{action}.change",
                resource_type="export",
            )
            write(session, action)
        assert str(user_id) not in str(refused.value)
        assert _rows(tenant, action) == []
        assert _rows(tenant, f"{action}.change") == []
    assert _admin(
        "SELECT count(*) FROM core.audit_log WHERE metadata::text LIKE :u", u=f"%{user_id}%"
    ) == [(0,)]


def test_the_actor_is_rolled_back_with_the_callers_transaction(
    tenants: builtins.list[uuid.UUID],
) -> None:
    tenant = tenants[0]

    class _ChangeFailed(Exception):
        pass

    with pytest.raises(_ChangeFailed), tenant_session_scope(tenant) as session:
        record_system_action_in_transaction(
            session,
            tenant_id=tenant,
            actor=_ACTOR,
            action="test.system_actor.rolled_back",
            resource_type="export",
        )
        raise _ChangeFailed
    assert _rows(tenant, "test.system_actor.rolled_back") == []


def test_a_system_callers_actor_is_written_beside_its_purpose(
    tenants: builtins.list[uuid.UUID],
) -> None:
    tenant = tenants[0]
    caller = SystemCaller(
        SystemAuthority.PROVISIONING,
        actor=SystemActor(SystemActorKind.MAINTENANCE, "seed_tenant"),
    )
    with tenant_session_scope(tenant) as session:
        record_in_transaction(
            session,
            caller=caller,
            tenant_id=tenant,
            action="test.system_actor.with_purpose",
            resource_type="tenant",
        )
    (row,) = _rows(tenant, "test.system_actor.with_purpose")
    assert row.entry_metadata == {
        "system_authority": "provisioning",
        "system_actor": {"kind": "maintenance", "name": "seed_tenant"},
        "initiated_by": "unavailable",
        "correlation": {},
    }


def test_the_rows_tenant_is_the_sessions_and_never_redirected(
    tenants: builtins.list[uuid.UUID],
) -> None:
    """The tenant comes from verified context: a row naming another tenant
    than the session's fails closed at the database, and nothing of the
    session's transaction survives."""
    own, other = tenants
    with pytest.raises(DBAPIError), tenant_session_scope(own) as session:
        record_system_action_in_transaction(
            session,
            tenant_id=other,
            actor=_ACTOR,
            action="test.system_actor.cross_tenant",
            resource_type="export",
        )
    assert _rows(own, "test.system_actor.cross_tenant") == []
    assert _rows(other, "test.system_actor.cross_tenant") == []


def test_an_actorless_successful_system_row_is_still_written_with_a_warning(
    tenants: builtins.list[uuid.UUID],
) -> None:
    tenant = tenants[0]
    with pytest.warns(DeprecationWarning, match="ADR 0061"):
        entry = record(
            tenant_id=tenant,
            actor_type=ActorType.SYSTEM,
            action="test.system_actor.unattributed",
            resource_type="export",
            outcome=AuditOutcome.SUCCESS,
        )
    assert get(tenant, entry.id).actor_type == "system"


# --- A SystemActor is never a caller ------------------------------------------------------

# Exported functions that take a `caller` but are not an operation to refuse
# it in: the guard itself, and a transaction helper whose only use of the
# caller is the statement-timeout choice (it authorizes nothing; every
# operation using it calls `authorize_platform_caller()` first).
_NOT_OPERATIONS = {"require_caller", "platform_change_session"}
# Functions that decide or record nothing for a non-caller instead of
# raising: the best-effort refusal recorder returns "not recorded", and the
# preliminary platform question answers "no authority".
_RETURNS_FALSE = {"record_platform_refusal", "platform_caller_could_hold_any"}
# The refusal-recording wrapper: a refusal inside it is re-raised unchanged
# and nothing is recorded for a non-caller.
_REFUSAL_WRAPPERS = {"recording_platform_refusal"}


def _exported_caller_functions() -> builtins.list[tuple[str, Callable[..., object]]]:
    found: dict[tuple[str, str], tuple[str, Callable[..., object]]] = {}
    for module_info in pkgutil.walk_packages(saas_os.core.__path__, "saas_os.core."):
        if not module_info.ispkg:
            continue
        package = importlib.import_module(module_info.name)
        for name in getattr(package, "__all__", ()):
            value = getattr(package, name, None)
            if not inspect.isfunction(value) or "caller" not in inspect.signature(value).parameters:
                continue
            if name in _NOT_OPERATIONS:
                continue
            found.setdefault(
                (value.__module__, value.__qualname__), (f"{module_info.name}.{name}", value)
            )
    return sorted(found.values())


_FUNCTIONS = _exported_caller_functions()

_OVERRIDES: dict[str, object] = {
    "operation": "tenant.read",
    "operations": ["tenant.read"],
    "reason": "system actor refusal test",
    "event_ids": [uuid.uuid4()],
    "tenant_ids": [uuid.uuid4()],
    # A SHA-256 hex digest in form (64 lower-case hex characters).
    "eligible_digest": "0" * 64,
}
# Optional parameters supplied anyway: without them some functions refuse
# their arguments ("name the tenants") before they reach the caller check.
_ALWAYS_SUPPLIED = ("event_ids", "tenant_ids")
# The one argument whose valid value depends on the function: the
# register revocation's operation must name a revocation, not `tenant.read`.
_PER_FUNCTION: dict[str, dict[str, object]] = {
    "revoke_register_entry": {"operation": PERMISSION_GRANT_LEDGER_APPROVER_REVOKE_BY_SECURITY},
}


def _dummy(function: Callable[..., object], name: str) -> object:
    if name in _OVERRIDES:
        return _OVERRIDES[name]
    annotation = typing.get_type_hints(function).get(name)
    if typing.get_origin(annotation) in (Sequence, list, tuple):
        # A well-formed (empty) sequence, not a mock the function refuses.
        return []
    for candidate in typing.get_args(annotation) or (annotation,):
        if isinstance(candidate, type) and issubclass(candidate, enum.Enum):
            return next(iter(candidate))
        if candidate is uuid.UUID:
            return uuid.uuid4()
        if candidate is str:
            return "x"
        if candidate is bool:
            return True
        if candidate is int:
            return 1
        if candidate is datetime:
            # Timezone-aware and in the future, as validity ends must be.
            return datetime.now(UTC) + timedelta(days=30)
    return uuid.uuid4() if name.endswith("_id") else MagicMock()


def test_the_inventory_of_caller_taking_functions_is_not_empty() -> None:
    assert len(_FUNCTIONS) >= 90


@pytest.mark.parametrize(("qualified", "function"), _FUNCTIONS, ids=[q for q, _ in _FUNCTIONS])
def test_every_exported_core_function_refuses_a_system_actor_as_its_caller(
    qualified: str, function: Callable[..., object]
) -> None:
    parameters = inspect.signature(function).parameters
    kwargs = {
        name: _dummy(function, name)
        for name, parameter in parameters.items()
        if parameter.default is inspect.Parameter.empty and name != "caller"
    }
    for supplied in _ALWAYS_SUPPLIED:
        if supplied in parameters:
            kwargs[supplied] = _OVERRIDES[supplied]
    name = qualified.rsplit(".", 1)[1]
    kwargs.update(_PER_FUNCTION.get(name, {}))
    kwargs["caller"] = _ACTOR
    if name in _RETURNS_FALSE:
        assert function(**kwargs) is False
        return
    if name in _REFUSAL_WRAPPERS:
        before = _admin("SELECT count(*) FROM core.platform_audit_log")
        wrapper = function(**kwargs)
        assert isinstance(wrapper, contextlib.AbstractContextManager)
        with pytest.raises(PlatformNotAuthorizedError), wrapper:
            raise PlatformNotAuthorizedError("tenant.read")
        assert _admin("SELECT count(*) FROM core.platform_audit_log") == before
        return
    with pytest.raises((CallerTypeError, BillingActorRequiredError)):
        result = function(**kwargs)
        if inspect.iscoroutine(result):
            asyncio.run(result)
        if isinstance(result, contextlib.AbstractContextManager):
            with result:
                pass


# --- The audit digest verifies rows carrying the actor ------------------------------------

# Earlier than any other test's fixed window, so no row lies before it.
_T0 = datetime(1980, 3, 1, tzinfo=UTC)
_WINDOW = timedelta(hours=1)


def test_the_digest_verifies_rows_with_the_new_metadata(
    tenants: builtins.list[uuid.UUID],
) -> None:
    """Rows written through the new path (and one through the existing
    purpose path) are moved into a fixed 1980 window with the migrations
    role, so the window holds only this test's rows. The digest of that
    window verifies, a change to the recorded actor is found, and restoring
    it verifies again -- the format is unchanged because metadata was
    already digested (ADR-0053)."""
    tenant = tenants[0]
    with tenant_session_scope(tenant) as session:
        attributed = record_system_action_in_transaction(
            session,
            tenant_id=tenant,
            actor=_ACTOR,
            action="test.system_actor.digest",
            resource_type="export",
        ).id
        with_purpose = record_in_transaction(
            session,
            caller=SystemCaller(SystemAuthority.PROVISIONING, actor=_ACTOR),
            tenant_id=tenant,
            action="test.system_actor.digest",
            resource_type="tenant",
        ).id
    _admin(
        "UPDATE core.audit_log SET created_at = :at WHERE id::text = ANY(:ids)",
        at=_T0 + timedelta(minutes=5),
        ids=[str(attributed), str(with_purpose)],
    )
    (window,) = compute_windows([_T0], _WINDOW)
    assert {t: s.rows for t, s in window.tenants.items()} == {str(tenant): 2}
    built = build_record(window, None)
    logged = [LoggedRecord(built, record_digest(built))]
    clean = verify_records(logged)
    assert clean.ok, clean.findings

    ((original,),) = _admin(
        "SELECT metadata::text FROM core.audit_log WHERE id = :i", i=str(attributed)
    )
    assert "nightly_export" in str(original)
    _admin(
        "UPDATE core.audit_log SET metadata = CAST(:m AS json) WHERE id = :i",
        m=str(original).replace("nightly_export", "forged_export"),
        i=str(attributed),
    )
    assert [f.kind for f in verify_records(logged).findings] == ["audit_log_changed"]
    _admin(
        "UPDATE core.audit_log SET metadata = CAST(:m AS json) WHERE id = :i",
        m=str(original),
        i=str(attributed),
    )
    assert verify_records(logged).ok
