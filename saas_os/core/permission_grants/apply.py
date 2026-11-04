"""Apply declared permission grant migrations to existing tenants (ADR 0060,
option C; owner decisions of 2026-11-01; ADR-0045 amendment of 2026-11-01;
docs/architecture/PERMISSION-GRANT-MIGRATIONS-DESIGN.md).

**Authority.** A platform operator (`UserCaller`) holding
`platform.permission_grant:apply` (operation `permission_grant.apply`,
person only, no system purpose), authorized by `authorize_platform_caller`
inside every transaction that reads or changes anything. Inside a tenant,
each grant is made by `SystemCaller(SystemAuthority.PERMISSION_UPGRADE)`
through `saas_os.core.rbac.service.grant_registered_permission_to_role`,
the one function that accepts that purpose. Nothing here removes a grant,
creates or renames a role, assigns a role, adds a membership, or reads or
writes a deny grant or a delegation: a deny grant keeps winning in `can()`.

**The run.**

1. The declaration is validated before any database work
   (`validate_permission_grant_migrations`).
2. A pre-flight transaction authorizes the operator, resolves every
   permission in the global catalog (an unregistered one is refused), lists
   the tenants in scope (the named ones, or every open tenant), and checks,
   tenant by tenant under its RLS scope, that no applied migration was
   edited since (a changed digest is refused). With `apply`, the same
   transaction writes the run's **started** platform row
   (`phase = started`); its id is the run id every ledger row and tenant
   audit row of the run names, so that id always resolves to a platform
   row, however the run ends. A dry run writes nothing.
3. Each tenant in its own transaction: authorization again; its RLS scope
   (`bind_tenant_scope`); `lock_open_tenant` (`PENDING`, `ACTIVE` and
   `SUSPENDED` are in scope; a closed or unknown tenant is reported and
   skipped); with `apply`, the tenant's advisory lock
   (`acquire_tenant_advisory_lock`) so concurrent runs serialize; the
   ledger. A migration already in the ledger is `already_applied` and is
   not looked at again. Otherwise the role is found by name (absent:
   `role_missing`, recorded, nothing created) and each permission it lacks
   is added (one `role_permission.grant` tenant audit row each; one it holds
   is `already_present`). Then one ledger row per newly applied migration
   and one `permission_grant_migration.apply` tenant audit row, and commit.
   Any failure rolls the whole tenant back; the run goes on with the next
   tenant and reports the failure (by error type only).
4. With `apply`, after the tenants, one **completed** platform row
   (`phase = completed`, `run_id`, `partial` when a tenant failed): counts
   only, never a tenant's role or permission names. A run that stops part
   way (a refusal of authority, an edited declaration found inside a
   tenant, a crash) has a started row and no completed row; the tenants it
   committed keep valid references.

Without `apply` the same counts are computed per tenant and nothing is
written or locked beyond the authorization's share locks.

A refusal writes one `denied` platform row after its rollback: a caller
that is not authorized (`PlatformNotAuthorizedError`), or a declaration
refused before any tenant changed (`PermissionGrantMigrationError`).
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field

from saas_os.core.audit_log import record_in_transaction
from saas_os.core.authority import CallerTypeError, SystemAuthority, SystemCaller, UserCaller
from saas_os.core.permission_grants.declarations import (
    PermissionGrantMigration,
    ValidatedMigration,
    declaration_digest,
    validate_permission_grant_migrations,
)
from saas_os.core.permission_grants.errors import (
    InvalidPermissionGrantMigrationError,
    PermissionGrantMigrationChangedError,
    PermissionGrantMigrationError,
    UnregisteredPermissionGrantError,
)
from saas_os.core.permission_grants.models import (
    APPLICATION_OUTCOME_APPLIED,
    APPLICATION_OUTCOME_ROLE_MISSING,
    PermissionGrantApplication,
)
from saas_os.core.platform_authority import (
    PlatformRefusalError,
    authorize_platform_caller,
    platform_change_session,
    platform_operation,
    record_platform_event_in_transaction,
    record_platform_refusal,
    recording_platform_refusal,
    validate_reason,
)
from saas_os.core.platform_authority.operations import PERMISSION_GRANT_APPLY
from saas_os.core.rbac import Permission, Role, RolePermission
from saas_os.core.rbac.service import grant_registered_permission_to_role
from saas_os.core.tenancy import (
    CLOSED_STATUSES,
    Tenant,
    TenantClosedError,
    TenantNotFoundError,
    lock_open_tenant,
    tenant_row_exists,
)
from saas_os.infra.db import (
    Session,
    acquire_tenant_advisory_lock,
    bind_tenant_scope,
    select,
)

logger = logging.getLogger(__name__)

# Per-tenant outcome of a run.
TENANT_CHANGED = "changed"
TENANT_UNCHANGED = "unchanged"
TENANT_CLOSED = "tenant_closed"
TENANT_NOT_FOUND = "tenant_not_found"
TENANT_FAILED = "failed"

MAX_NAMED_TENANTS = 1000

# The `phase` of a run's two platform rows (both `platform.permission_grant.apply`).
PHASE_STARTED = "started"
PHASE_COMPLETED = "completed"

_TARGET_TYPE = "permission_grant_namespace"
_TENANT_AUDIT_ACTION = "permission_grant_migration.apply"
_LOCK_KEY = "permission_grant_migrations"
_MAX_PLATFORM_MIGRATION_IDS_BYTES = 4000
_UPGRADE = SystemCaller(SystemAuthority.PERMISSION_UPGRADE)


@dataclass(frozen=True)
class TenantGrantResult:
    """What a run did (or, without `apply`, would do) in one tenant.
    Counts only: no role or permission name.

    `migrations_applied`: migrations newly recorded as applied (including
    one whose grants were all already present); `roles_missing`: migrations
    newly recorded as `role_missing`; `migrations_already_applied`: in the
    ledger before the run, not looked at again. `error` is the error type
    of a `failed` tenant, whose transaction rolled back."""

    tenant_id: uuid.UUID
    outcome: str
    migrations_applied: int = 0
    roles_missing: int = 0
    migrations_already_applied: int = 0
    grants_added: int = 0
    grants_already_present: int = 0
    error: str | None = None


@dataclass(frozen=True)
class PermissionGrantRunResult:
    """One run. `run_id` is the id of the run's platform audit row (and of
    every ledger row it wrote); `None` for a dry run, which writes
    nothing."""

    namespace: str
    applied: bool
    run_id: uuid.UUID | None
    tenants: tuple[TenantGrantResult, ...] = field(default_factory=tuple)

    def tenant_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.tenants:
            counts[result.outcome] = counts.get(result.outcome, 0) + 1
        return counts

    @property
    def failed_tenant_ids(self) -> tuple[uuid.UUID, ...]:
        return tuple(r.tenant_id for r in self.tenants if r.outcome == TENANT_FAILED)


def _scope(
    tenant_ids: Sequence[uuid.UUID], all_tenants: bool, apply: bool
) -> tuple[uuid.UUID, ...] | None:
    if not isinstance(all_tenants, bool):
        raise InvalidPermissionGrantMigrationError("all_tenants must be a bool.")
    if isinstance(tenant_ids, str | bytes) or not isinstance(tenant_ids, Sequence):
        raise InvalidPermissionGrantMigrationError("tenant_ids must be a list or tuple.")
    if not isinstance(apply, bool):
        raise InvalidPermissionGrantMigrationError("apply must be a bool.")
    if all_tenants == bool(tenant_ids):
        raise InvalidPermissionGrantMigrationError("Name the tenants or all_tenants, not both.")
    if all_tenants:
        return None
    if not all(isinstance(t, uuid.UUID) for t in tenant_ids):
        raise InvalidPermissionGrantMigrationError("Every tenant id must be a uuid.UUID.")
    named = tuple(dict.fromkeys(tenant_ids))
    if len(named) > MAX_NAMED_TENANTS:
        raise InvalidPermissionGrantMigrationError(
            f"At most {MAX_NAMED_TENANTS} named tenants; use all_tenants."
        )
    return named


def _resolve_permissions(
    session: Session, validated: Sequence[ValidatedMigration]
) -> dict[tuple[str, str], uuid.UUID]:
    """Every declared permission's id in the global catalog; an unregistered
    one is refused. Never registers anything."""
    resolved: dict[tuple[str, str], uuid.UUID] = {}
    for item in validated:
        for resource, action in item.migration.permissions:
            if (resource, action) in resolved:
                continue
            permission_id = session.execute(
                select(Permission.id).where(
                    Permission.resource == resource, Permission.action == action
                )
            ).scalar_one_or_none()
            if permission_id is None:
                raise UnregisteredPermissionGrantError(item.migration.id, resource, action)
            resolved[(resource, action)] = permission_id
    return resolved


def _open_tenants(session: Session) -> tuple[uuid.UUID, ...]:
    """Every tenant that is not closed, in a stable order. `core.tenants`
    is not RLS-scoped. A tenant closed after this read is reported
    `tenant_closed` by its own transaction."""
    closed = [status.value for status in CLOSED_STATUSES]
    rows = session.execute(
        select(Tenant.id).where(Tenant.status.not_in(closed)).order_by(Tenant.created_at, Tenant.id)
    )
    return tuple(rows.scalars().all())


def _ledger(session: Session, tenant_id: uuid.UUID, namespace: str) -> dict[str, str]:
    """`migration id -> content digest` of `tenant_id`'s ledger rows for
    `namespace`. The session must be bound to `tenant_id`."""
    rows = session.execute(
        select(
            PermissionGrantApplication.migration_id, PermissionGrantApplication.content_digest
        ).where(
            PermissionGrantApplication.tenant_id == tenant_id,
            PermissionGrantApplication.namespace == namespace,
        )
    ).all()
    return {row.migration_id: row.content_digest for row in rows}


def _refuse_changed(
    ledger: dict[str, str], validated: Sequence[ValidatedMigration], namespace: str
) -> None:
    for item in validated:
        recorded = ledger.get(item.migration.id)
        if recorded is not None and recorded != item.digest:
            raise PermissionGrantMigrationChangedError(namespace, item.migration.id)


def _check_ledgers(
    session: Session,
    tenant_ids: Sequence[uuid.UUID],
    validated: Sequence[ValidatedMigration],
    namespace: str,
) -> None:
    for tenant_id in tenant_ids:
        with bind_tenant_scope(session, tenant_id):
            _refuse_changed(_ledger(session, tenant_id, namespace), validated, namespace)


def _role_id(session: Session, tenant_id: uuid.UUID, role_name: str) -> uuid.UUID | None:
    return session.execute(
        select(Role.id).where(Role.tenant_id == tenant_id, Role.name == role_name)
    ).scalar_one_or_none()


def _holds(
    session: Session, tenant_id: uuid.UUID, role_id: uuid.UUID, permission_id: uuid.UUID
) -> bool:
    return (
        session.execute(
            select(RolePermission.id).where(
                RolePermission.tenant_id == tenant_id,
                RolePermission.role_id == role_id,
                RolePermission.permission_id == permission_id,
            )
        ).scalar_one_or_none()
        is not None
    )


def _apply_in_tenant(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    caller: UserCaller,
    namespace: str,
    validated: Sequence[ValidatedMigration],
    permission_ids: dict[tuple[str, str], uuid.UUID],
    run_id: uuid.UUID | None,
) -> TenantGrantResult:
    """One tenant, in `session` already bound to it, its row held
    `FOR SHARE`. With a `run_id`, writes; without, only counts."""
    apply = run_id is not None
    if apply:
        acquire_tenant_advisory_lock(session, tenant_id, _LOCK_KEY)
    ledger = _ledger(session, tenant_id, namespace)
    _refuse_changed(ledger, validated, namespace)
    applied: list[str] = []
    missing = already = added = present = 0
    for item in validated:
        migration = item.migration
        if migration.id in ledger:
            already += 1
            continue
        role_id = _role_id(session, tenant_id, migration.role_name)
        new_grants = 0
        if role_id is None:
            missing += 1
            outcome = APPLICATION_OUTCOME_ROLE_MISSING
        else:
            applied.append(migration.id)
            outcome = APPLICATION_OUTCOME_APPLIED
            for pair in migration.permissions:
                permission_id = permission_ids[pair]
                if apply:
                    inserted = grant_registered_permission_to_role(
                        session,
                        tenant_id=tenant_id,
                        role_id=role_id,
                        permission_id=permission_id,
                        caller=_UPGRADE,
                        metadata={
                            "namespace": namespace,
                            "migration_id": migration.id,
                            "operator_user_id": str(caller.user_id),
                            "run_id": str(run_id),
                        },
                    )
                else:
                    inserted = not _holds(session, tenant_id, role_id, permission_id)
                if inserted:
                    new_grants += 1
                else:
                    present += 1
        added += new_grants
        if apply:
            assert run_id is not None
            session.add(
                PermissionGrantApplication(
                    tenant_id=tenant_id,
                    namespace=namespace,
                    migration_id=migration.id,
                    content_digest=item.digest,
                    outcome=outcome,
                    grants_added=new_grants,
                    applied_by_platform_audit_id=run_id,
                )
            )
    changed = bool(applied) or missing > 0
    if apply and changed:
        session.flush()
        record_in_transaction(
            session,
            caller=caller,
            tenant_id=tenant_id,
            action=_TENANT_AUDIT_ACTION,
            resource_type="tenant",
            resource_id=str(tenant_id),
            metadata={
                "namespace": namespace,
                "run_id": str(run_id),
                "migration_ids": applied,
                "migrations_applied": len(applied),
                "roles_missing": missing,
                "grants_added": added,
                "grants_already_present": present,
                "platform": True,
            },
        )
    return TenantGrantResult(
        tenant_id=tenant_id,
        outcome=TENANT_CHANGED if changed else TENANT_UNCHANGED,
        migrations_applied=len(applied),
        roles_missing=missing,
        migrations_already_applied=already,
        grants_added=added,
        grants_already_present=present,
    )


def _run_tenant(
    tenant_id: uuid.UUID,
    *,
    caller: UserCaller,
    namespace: str,
    validated: Sequence[ValidatedMigration],
    permission_ids: dict[tuple[str, str], uuid.UUID],
    run_id: uuid.UUID | None,
) -> TenantGrantResult:
    """`tenant_id` in a transaction of its own. A refusal of authority or a
    changed declaration stops the run (re-raised); any other failure rolls
    the tenant back and is reported as `failed`."""
    try:
        with (
            recording_platform_refusal(
                caller=caller,
                operation=PERMISSION_GRANT_APPLY,
                target_type=_TARGET_TYPE,
                target_id=namespace,
            ),
            platform_change_session(caller, PERMISSION_GRANT_APPLY) as session,
        ):
            authorize_platform_caller(caller, session=session, operation=PERMISSION_GRANT_APPLY)
            with bind_tenant_scope(session, tenant_id):
                try:
                    lock_open_tenant(session, tenant_id)
                except TenantClosedError:
                    return TenantGrantResult(tenant_id, TENANT_CLOSED)
                except TenantNotFoundError:
                    return TenantGrantResult(tenant_id, TENANT_NOT_FOUND)
                return _apply_in_tenant(
                    session,
                    tenant_id=tenant_id,
                    caller=caller,
                    namespace=namespace,
                    validated=validated,
                    permission_ids=permission_ids,
                    run_id=run_id,
                )
    except (PlatformRefusalError, PermissionGrantMigrationError):
        raise
    except Exception as error:  # noqa: BLE001 -- reported per tenant; the run goes on (docstring)
        logger.warning(
            "permission_grant_migration_tenant_failed",
            extra={"tenant_id": str(tenant_id), "error_type": type(error).__name__},
        )
        return TenantGrantResult(tenant_id, TENANT_FAILED, error=type(error).__name__)


def _declaration_metadata(
    *, phase: str, namespace: str, all_tenants: bool, validated: Sequence[ValidatedMigration]
) -> dict[str, object]:
    ids = [item.migration.id for item in validated]
    metadata: dict[str, object] = {
        "phase": phase,
        "namespace": namespace,
        "scope": "all_tenants" if all_tenants else "tenants",
        "declaration_digest": declaration_digest(validated),
        "migrations": len(ids),
    }
    if len(json.dumps(ids)) <= _MAX_PLATFORM_MIGRATION_IDS_BYTES:
        metadata["migration_ids"] = ids
    else:
        metadata["migration_ids_omitted"] = True
    return metadata


def _started_metadata(
    *, namespace: str, all_tenants: bool, validated: Sequence[ValidatedMigration], tenants: int
) -> dict[str, object]:
    """The run's started row: the declaration and how many tenants are in
    scope; no outcome yet."""
    metadata = _declaration_metadata(
        phase=PHASE_STARTED, namespace=namespace, all_tenants=all_tenants, validated=validated
    )
    metadata["tenants"] = tenants
    return metadata


def _platform_metadata(
    *,
    namespace: str,
    all_tenants: bool,
    validated: Sequence[ValidatedMigration],
    results: Sequence[TenantGrantResult],
    run_id: uuid.UUID,
) -> dict[str, object]:
    """The run's completed row: counts by outcome, the run id (the started
    row's id) and `partial` when a tenant failed."""
    metadata = _declaration_metadata(
        phase=PHASE_COMPLETED, namespace=namespace, all_tenants=all_tenants, validated=validated
    )
    metadata["run_id"] = str(run_id)
    metadata["tenants"] = len(results)
    metadata["partial"] = any(r.outcome == TENANT_FAILED for r in results)
    for outcome in (TENANT_CHANGED, TENANT_UNCHANGED, TENANT_CLOSED, TENANT_NOT_FOUND):
        metadata[f"tenants_{outcome}"] = sum(1 for r in results if r.outcome == outcome)
    metadata["tenants_failed"] = sum(1 for r in results if r.outcome == TENANT_FAILED)
    metadata["migrations_applied"] = sum(r.migrations_applied for r in results)
    metadata["roles_missing"] = sum(r.roles_missing for r in results)
    metadata["grants_added"] = sum(r.grants_added for r in results)
    metadata["grants_already_present"] = sum(r.grants_already_present for r in results)
    return metadata


def apply_permission_grant_migrations(
    migrations: Sequence[PermissionGrantMigration],
    *,
    namespace: str,
    caller: object,
    reason: str,
    tenant_ids: Sequence[uuid.UUID] = (),
    all_tenants: bool = False,
    apply: bool = False,
) -> PermissionGrantRunResult:
    """Apply `namespace`'s declared `migrations` to the named tenants, or
    with `all_tenants` to every open tenant (exactly one of the two).
    Without `apply` it only counts. See the module docstring for the
    authority, the per-tenant procedure, the evidence and the refusals."""
    spec = platform_operation(PERMISSION_GRANT_APPLY)
    target_id = namespace if isinstance(namespace, str) and 0 < len(namespace) <= 100 else None
    try:
        validated = validate_permission_grant_migrations(migrations, namespace=namespace)
        named = _scope(tenant_ids, all_tenants, apply)
        reason = validate_reason(reason)
        with (
            recording_platform_refusal(
                caller=caller,
                operation=PERMISSION_GRANT_APPLY,
                target_type=_TARGET_TYPE,
                target_id=target_id,
            ),
            platform_change_session(caller, PERMISSION_GRANT_APPLY) as session,
        ):
            authorize_platform_caller(caller, session=session, operation=PERMISSION_GRANT_APPLY)
            permission_ids = _resolve_permissions(session, validated)
            targets = named if named is not None else _open_tenants(session)
            _check_ledgers(session, targets, validated, namespace)
            run_id = uuid.uuid4() if apply else None
            if run_id is not None:
                # The started row commits with the pre-flight, before any
                # tenant changes: every reference to `run_id` resolves.
                single = named[0] if named is not None and len(named) == 1 else None
                metadata = _started_metadata(
                    namespace=namespace,
                    all_tenants=all_tenants,
                    validated=validated,
                    tenants=len(targets),
                )
                record_platform_event_in_transaction(
                    session,
                    caller=caller,
                    action=spec.audit_action,
                    target_type=_TARGET_TYPE,
                    target_id=namespace,
                    target_tenant_id=single
                    if single is not None and tenant_row_exists(session, single)
                    else None,
                    reason=reason,
                    metadata=metadata,
                    entry_id=run_id,
                )
        # An explicit check, not an `assert` (stripped under `python -O`): the
        # operation accepts no system purpose.
        if not isinstance(caller, UserCaller):
            raise CallerTypeError(PERMISSION_GRANT_APPLY, caller, (UserCaller,))
        results = tuple(
            _run_tenant(
                tenant_id,
                caller=caller,
                namespace=namespace,
                validated=validated,
                permission_ids=permission_ids,
                run_id=run_id,
            )
            for tenant_id in targets
        )
    except PermissionGrantMigrationError as refused:
        record_platform_refusal(
            caller=caller,
            action=spec.audit_action,
            target_type=_TARGET_TYPE,
            target_id=target_id,
            code=refused.code,
        )
        raise
    if run_id is not None:
        with (
            recording_platform_refusal(
                caller=caller,
                operation=PERMISSION_GRANT_APPLY,
                target_type=_TARGET_TYPE,
                target_id=namespace,
            ),
            platform_change_session(caller, PERMISSION_GRANT_APPLY) as session,
        ):
            authorize_platform_caller(caller, session=session, operation=PERMISSION_GRANT_APPLY)
            single = named[0] if named is not None and len(named) == 1 else None
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=spec.audit_action,
                target_type=_TARGET_TYPE,
                target_id=namespace,
                target_tenant_id=single
                if single is not None and results[0].outcome != TENANT_NOT_FOUND
                else None,
                reason=reason,
                metadata=_platform_metadata(
                    namespace=namespace,
                    all_tenants=all_tenants,
                    validated=validated,
                    results=results,
                    run_id=run_id,
                ),
            )
    return PermissionGrantRunResult(namespace, apply, run_id, results)
