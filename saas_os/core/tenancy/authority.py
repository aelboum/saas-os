"""Platform authorization and evidence for the tenant lifecycle
(docs/ADR/0045-installation-scoped-platform-authority.md sections 8, 9c
and 12).

`create_tenant`, `move_tenant` and `transition_tenant_status` each take a
required, keyword-only `caller` and authorize it inside their own
transaction through the platform chokepoint
(`saas_os.core.platform_authority.authorize_platform_caller`), by the
operation key the declared operation table lists. This module holds the
authorization and evidence calls they share; `service.py` and
`registry.py` also import that package directly, for its operation keys
and errors, and all three are listed in the architecture test's approved
importers.

**Imports are deferred.** `saas_os.core.platform_authority` imports
`saas_os.core.identity`, which imports `saas_os.core.tenancy` at module
scope; a module-scope import here would be a load-time cycle.

**Ordering rule (ADR-0045 section 9c).** A platform table is read and
written only while no tenant is bound; a tenant-owned table only inside a
`bind_tenant_scope` block. `record_platform()` therefore runs outside any
bind block, and `record_tenant()` opens one for exactly its own insert.

**Dual evidence.** A platform operation that changes a tenant's state
writes one row to `core.platform_audit_log` and, in the same transaction,
one row to that tenant's own `core.audit_log`, so the tenant's
administrators see in their own trail that the platform acted on them.
Both commit or roll back with the change.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager

from saas_os.core.audit_log import record_in_transaction
from saas_os.core.authority import Caller, ServiceAccountCaller, UserCaller, require_caller
from saas_os.infra.db import Session, bind_tenant_scope, select

TENANT_TARGET = "tenant"

# Tenant-scoped permission for self-service suspension (ADR-0045 section
# 12): evaluated by tenant RBAC, never a platform permission.
SELF_SUSPEND_RESOURCE = "tenant"
SELF_SUSPEND_ACTION = "suspend"


def require_lifecycle_caller(operation: str, caller: object) -> None:
    """Refuse a missing or wrongly typed caller (`CallerTypeError`), and a
    service account, before any read. A service account is owned by one
    tenant and never holds platform authority."""
    from saas_os.core.platform_authority import PlatformNotAuthorizedError

    require_caller(operation, caller)
    if isinstance(caller, ServiceAccountCaller):
        raise PlatformNotAuthorizedError(operation)


def authorize(session: Session, caller: object, operation: str) -> None:
    """The authorization for a lifecycle operation, in its own transaction.
    Must run while no tenant is bound."""
    from saas_os.core.platform_authority import authorize_platform_caller

    authorize_platform_caller(caller, session=session, operation=operation)


def validated_reason(reason: str | None) -> str | None:
    if reason is None:
        return None
    from saas_os.core.platform_authority import validate_reason

    return validate_reason(reason)


@contextmanager
def refusal_recorded(
    caller: object,
    operation: str,
    tenant_id: uuid.UUID | None,
    metadata: dict[str, object] | None = None,
) -> Iterator[None]:
    """Record one `denied` platform audit row, after the rollback, if the
    wrapped transaction is refused."""
    from saas_os.core.platform_authority import recording_platform_refusal

    with recording_platform_refusal(
        caller=caller,
        operation=operation,
        target_type=TENANT_TARGET,
        target_id=None if tenant_id is None else str(tenant_id),
        metadata=metadata,
    ):
        yield


def record_refusal(
    caller: object,
    operation: str,
    tenant_id: uuid.UUID | None,
    code: str,
    metadata: dict[str, object] | None = None,
) -> None:
    """Record a refusal that is raised as an error of another family (a
    closed parent is `TenantClosedError`)."""
    from saas_os.core.platform_authority import platform_operation, record_platform_refusal

    record_platform_refusal(
        caller=caller,
        action=platform_operation(operation).audit_action,
        target_type=TENANT_TARGET,
        target_id=None if tenant_id is None else str(tenant_id),
        code=code,
        metadata=metadata,
    )


def record_platform(
    session: Session,
    *,
    caller: object,
    operation: str,
    tenant_id: uuid.UUID,
    reason: str | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    """The platform audit row of a lifecycle change. No tenant may be
    bound: inside a tenant scope the table's policy rejects the insert."""
    from saas_os.core.platform_authority import (
        platform_operation,
        record_platform_event_in_transaction,
    )

    record_platform_event_in_transaction(
        session,
        caller=caller,
        action=platform_operation(operation).audit_action,
        target_type=TENANT_TARGET,
        target_id=str(tenant_id),
        target_tenant_id=tenant_id,
        reason=reason,
        metadata=metadata,
    )


def record_tenant(
    session: Session,
    *,
    caller: Caller,
    tenant_id: uuid.UUID,
    action: str,
    subject_tenant_id: uuid.UUID | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    """One row in `tenant_id`'s own `core.audit_log`, under that tenant's
    row-level-security scope, naming the caller as the actor. The row is
    about `subject_tenant_id` (default: `tenant_id` itself)."""
    with bind_tenant_scope(session, tenant_id):
        record_in_transaction(
            session,
            caller=caller,
            tenant_id=tenant_id,
            action=action,
            resource_type=TENANT_TARGET,
            resource_id=str(subject_tenant_id if subject_tenant_id is not None else tenant_id),
            metadata=metadata,
        )


def holds_self_suspend(session: Session, caller: object, tenant_id: uuid.UUID) -> bool:
    """The self-service suspension rule: a `UserCaller` who is an ACTIVE
    member of exactly this tenant and holds `tenant:suspend` there through
    an ordinary membership role. A delegation, a role inherited from an
    ancestor, a support-access grant and a service account never satisfy
    it."""
    if not isinstance(caller, UserCaller):
        return False
    from saas_os.core.rbac.authorization import holds_through_own_membership
    from saas_os.core.rbac.service import register_permission

    register_permission(SELF_SUSPEND_RESOURCE, SELF_SUSPEND_ACTION, session=session)
    return holds_through_own_membership(
        session,
        user_id=caller.user_id,
        tenant_id=tenant_id,
        action=SELF_SUSPEND_ACTION,
        resource=SELF_SUSPEND_RESOURCE,
    )


def caller_is_member_of_any(
    session: Session, caller: object, tenant_ids: Sequence[uuid.UUID]
) -> bool:
    """Does the calling person hold a membership that is not revoked in
    any of `tenant_ids`? One existence query per tenant, each under that
    tenant's row-level-security scope. A suspended membership counts: it
    can be reactivated."""
    if not isinstance(caller, UserCaller):
        return False
    from saas_os.core.identity import MembershipStatus, TenantMembership

    for tenant_id in tenant_ids:
        with bind_tenant_scope(session, tenant_id):
            found = session.execute(
                select(TenantMembership.id)
                .where(
                    TenantMembership.tenant_id == tenant_id,
                    TenantMembership.user_id == caller.user_id,
                    TenantMembership.status != MembershipStatus.REVOKED.value,
                )
                .limit(1)
            ).first()
        if found is not None:
            return True
    return False
