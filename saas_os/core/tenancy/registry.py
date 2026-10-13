"""Operational oversight of the tenant registry
(docs/ADR/0045-installation-scoped-platform-authority.md sections 4, 8
and 9d).

Two reads, both gated by `platform.tenant:read` and both of the global
`core.tenants` table only: no tenant scope is ever entered, and no
tenant-owned row is read.

**The projection is fixed:** `id`, `name`, `status`, `parent_id`,
`created_at`, `updated_at`. There is no function here that takes a column
list. `PURGED` tombstones are omitted from the list; a `SUSPENDED` or
`DELETED` tenant is listed, because those are the tenants an operator most
needs to see. A tenant cannot opt out of oversight.

**Every call is audited, by two rows** (ADR-0045 sections 8 and 9d).

1. *The attempt* (`platform.tenant.read_attempt`): the caller is
   authorized and the row -- the actor, the cursor, the requested page
   size, the tenant id when one was named -- is committed in a
   transaction of its own, before the registry is read at all. If it
   cannot be committed, the call raises and nothing has been read.
2. *The completion* (`platform.tenant.read`): in a second transaction the
   caller is authorized again, the registry is read, and a row carrying
   the number of entries returned and the attempt row's id (`attempt_id`)
   is written. The data leaves the function only after that transaction
   commits.

Both transactions carry a statement timeout
(`PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS`, each for itself only): a
statement or lock wait that exceeds it is cancelled and the call raises
`OversightReadTimeoutError`. In the attempt transaction that leaves no
row and nothing read; in the read transaction it leaves the attempt row
with no completion.

A read that fails or times out, or whose caller lost the authority between
the two transactions, returns nothing and leaves the attempt row with no
completion (and, for the lost authority, a `denied` row). Neither row
ever holds a returned value. A read of a tenant id that does not exist is
a call like any other: both rows are committed, the completion records
that nothing was returned, and only then is `TenantNotFoundError` raised,
so an operator cannot probe ids without leaving evidence.

**Request limits (decision D3).** A page size above the maximum is
rejected (`InvalidPlatformRequestError`); it is never clamped, because a
silently shortened page looks like a complete answer. Nothing iterates
beyond one page per call.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

from saas_os.core.authority import ServiceAccountCaller, require_caller
from saas_os.core.tenancy.config import get_oversight_read_config
from saas_os.core.tenancy.errors import TenantNotFoundError
from saas_os.core.tenancy.lifecycle import TenantStatus
from saas_os.core.tenancy.models import Tenant
from saas_os.infra.db import (
    OperationalError,
    Session,
    is_statement_timeout,
    select,
    session_scope,
    set_local_statement_timeout,
)

DEFAULT_REGISTRY_PAGE_SIZE = 50
MAX_REGISTRY_PAGE_SIZE = 200

_TARGET = "tenant"


@dataclass(frozen=True)
class TenantRegistryEntry:
    """The complete oversight projection of one tenant."""

    id: uuid.UUID
    name: str
    status: str
    parent_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class TenantRegistryPage:
    """`next_cursor` is the id to pass as `cursor` for the following page,
    or `None` when this page was not full."""

    tenants: tuple[TenantRegistryEntry, ...]
    next_cursor: uuid.UUID | None


def _entry(tenant: Tenant) -> TenantRegistryEntry:
    return TenantRegistryEntry(
        id=tenant.id,
        name=tenant.name,
        status=tenant.status,
        parent_id=tenant.parent_id,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@contextmanager
def oversight_read_timeout(operation: str) -> Iterator[Callable[[Session], None]]:
    """Wrap the read transaction of one oversight read (ADR-0045 section
    9d). Yields a function the caller applies to that transaction's
    session as its first statement; it sets the configured statement
    timeout (`PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS`) for that
    transaction only. A statement PostgreSQL cancels inside the block
    leaves it as `OversightReadTimeoutError`, after the transaction has
    been rolled back by its own `session_scope()`.

        with oversight_read_timeout(TENANT_READ) as bound, session_scope() as session:
            bound(session)
            ...

    The attempt transaction carries the same timeout, set by
    `record_oversight_attempt(statement_timeout_ms=...)`. Shared with
    `saas_os.core.billing.oversight`, whose read pages the same
    registry."""
    from saas_os.core.platform_authority import OversightReadTimeoutError

    timeout_ms = get_oversight_read_config().statement_timeout_ms

    def bound(session: Session) -> None:
        set_local_statement_timeout(session, timeout_ms)

    try:
        yield bound
    except OperationalError as error:
        if is_statement_timeout(error):
            raise OversightReadTimeoutError(
                operation, timeout_ms, stage=OversightReadTimeoutError.STAGE_READ
            ) from error
        raise


def _require_caller(operation: str, caller: object) -> None:
    from saas_os.core.platform_authority import PlatformNotAuthorizedError

    require_caller(operation, caller)
    if isinstance(caller, ServiceAccountCaller):
        raise PlatformNotAuthorizedError(operation)


def list_tenant_registry(
    *, caller: object, cursor: uuid.UUID | None = None, limit: int = DEFAULT_REGISTRY_PAGE_SIZE
) -> TenantRegistryPage:
    """One page of the tenant registry, by keyset on the tenant id.
    Authority: `platform.tenant:read`."""
    from saas_os.core.platform_authority import (
        InvalidPlatformRequestError,
        authorize_platform_caller,
        platform_operation,
        record_oversight_attempt,
        record_platform_event_in_transaction,
        recording_platform_refusal,
    )
    from saas_os.core.platform_authority.operations import TENANT_READ

    _require_caller(TENANT_READ, caller)
    if cursor is not None and not isinstance(cursor, uuid.UUID):
        raise InvalidPlatformRequestError("cursor must be a uuid.UUID.")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise InvalidPlatformRequestError("limit must be a positive integer.")
    if limit > MAX_REGISTRY_PAGE_SIZE:
        raise InvalidPlatformRequestError(
            f"limit exceeds the maximum page size of {MAX_REGISTRY_PAGE_SIZE}."
        )

    with recording_platform_refusal(caller=caller, operation=TENANT_READ, target_type=_TARGET):
        # Committed before the registry is read; raises if it cannot be.
        attempt_id = record_oversight_attempt(
            caller=caller,
            operation=TENANT_READ,
            target_type=_TARGET,
            metadata={"cursor": None if cursor is None else str(cursor), "page_size": limit},
            statement_timeout_ms=get_oversight_read_config().statement_timeout_ms,
        )
        with oversight_read_timeout(TENANT_READ) as bound, session_scope() as session:
            bound(session)  # statement timeout, this transaction only
            # Again: the authority may have been revoked since the attempt.
            authorize_platform_caller(caller, session=session, operation=TENANT_READ)
            query = select(Tenant).where(Tenant.status != TenantStatus.PURGED.value)
            if cursor is not None:
                query = query.where(Tenant.id > cursor)
            tenants = session.execute(query.order_by(Tenant.id).limit(limit)).scalars().all()
            entries = tuple(_entry(tenant) for tenant in tenants)
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=platform_operation(TENANT_READ).audit_action,
                target_type=_TARGET,
                metadata={"attempt_id": str(attempt_id), "returned": len(entries)},
            )
    # Committed: the completion row is durable before the page leaves.
    return TenantRegistryPage(
        tenants=entries,
        next_cursor=entries[-1].id if len(entries) == limit else None,
    )


def read_tenant_registry_entry(tenant_id: uuid.UUID, *, caller: object) -> TenantRegistryEntry:
    """The oversight projection of one named tenant, whatever its status
    (a `PURGED` tombstone included: its name is already a placeholder).
    Authority: `platform.tenant:read`. The audit row names the tenant.

    Authorization comes first: a caller without the permission is refused
    before the tenant is looked up and learns nothing about whether it
    exists. For an authorized caller an unknown id raises
    `TenantNotFoundError`, after both audit rows of that call are
    committed (the completion with `returned: 0`; the id as `target_id`,
    and no `target_tenant_id`, which references an existing tenant)."""
    from saas_os.core.platform_authority import (
        InvalidPlatformRequestError,
        authorize_platform_caller,
        platform_operation,
        record_oversight_attempt,
        record_platform_event_in_transaction,
        recording_platform_refusal,
    )
    from saas_os.core.platform_authority.operations import TENANT_READ

    _require_caller(TENANT_READ, caller)
    if not isinstance(tenant_id, uuid.UUID):
        raise InvalidPlatformRequestError("tenant_id must be a uuid.UUID.")

    with recording_platform_refusal(
        caller=caller, operation=TENANT_READ, target_type=_TARGET, target_id=str(tenant_id)
    ):
        # Committed before the tenant is looked up; raises if it cannot be.
        attempt_id = record_oversight_attempt(
            caller=caller,
            operation=TENANT_READ,
            target_type=_TARGET,
            target_id=str(tenant_id),
            statement_timeout_ms=get_oversight_read_config().statement_timeout_ms,
        )
        with oversight_read_timeout(TENANT_READ) as bound, session_scope() as session:
            bound(session)  # statement timeout, this transaction only
            authorize_platform_caller(caller, session=session, operation=TENANT_READ)
            tenant = session.get(Tenant, tenant_id)
            entry = None if tenant is None else _entry(tenant)
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=platform_operation(TENANT_READ).audit_action,
                target_type=_TARGET,
                target_id=str(tenant_id),
                target_tenant_id=None if entry is None else tenant_id,
                metadata={"attempt_id": str(attempt_id), "returned": 0 if entry is None else 1},
            )
    # Committed: the completion row is durable before the answer leaves.
    if entry is None:
        raise TenantNotFoundError(tenant_id)
    return entry
