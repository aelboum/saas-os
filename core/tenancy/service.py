"""Tenant CRUD and lifecycle operations (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.1).

Tenant management is itself a platform-level operation, not scoped to "the
current tenant" -- a tenant cannot scope itself into existence, and
resolving a session's tenant requires reading the registry unscoped. Every
function here uses `infra.db.session_scope()` (untenanted), never
`tenant_session_scope()` -- `core.tenants` is not RLS-scoped (see
`core/tenancy/models.py`).
"""

from __future__ import annotations

import uuid

from core.tenancy.errors import TenantNotFoundError
from core.tenancy.lifecycle import TenantStatus, validate_transition
from core.tenancy.models import Tenant
from infra.db import select, session_scope


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


def create_tenant(name: str) -> Tenant:
    with session_scope() as session:
        tenant = Tenant(name=name, status=TenantStatus.PENDING.value)
        session.add(tenant)
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
    """
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)
        current_status = TenantStatus(tenant.status)
        validate_transition(current_status, TenantStatus.PURGED)
        session.delete(tenant)
