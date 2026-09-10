"""`core/tenancy` -- tenant entity and lifecycle (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.1; docs/MULTI-TENANCY.md; docs/ADR/0002-multi-tenancy-isolation-model.md).

The tenant entity *is* the customer organization (docs/MULTI-TENANCY.md
section 1) -- `tenant_id` is the one canonical identifier every other
tenant-owned table across the platform will carry. This module owns:

- the `Tenant` entity itself (`core.tenants`, `core/tenancy/models.py`);
- its lifecycle state machine (`TenantStatus`, `core/tenancy/lifecycle.py`);
- CRUD/lifecycle operations (`core/tenancy/service.py`);
- its optional tenant hierarchy (architecture research: universal
  multi-tenant tenancy, Phase A; ADR-0002 amendment) -- `Tenant.parent_id`,
  the `core.tenant_ancestry` closure table (`TenantAncestry`), and
  `move_tenant()`. Structural data only: a tenant's position in the tree
  grants no authorization by itself (`core/tenancy/models.py`'s docstring).

Tenant-scoping *enforcement* for tenant-*owned* data (as opposed to the
tenant registry itself) is `infra.db.tenant_session_scope()` +
`infra.db.rls.tenant_rls_statements()` -- completed in this same phase,
since `core/tenancy` is the first module that needs it, but those
primitives live in `infra/db` (docs/ARCHITECTURE.md section 2:
"Infrastructure has zero knowledge of business concepts" -- `infra/db`
provides the mechanism, `core/tenancy` is the first thing that uses it).

`core/tenancy` never imports `sqlalchemy` directly -- it defines its table
using `infra.db.orm`'s shared declarative base
(`pyproject.toml`'s "Only infra/db may import SQLAlchemy or psycopg
directly" contract).
"""

from core.tenancy.config import TenancyConfig, get_tenancy_config
from core.tenancy.errors import (
    InvalidTenantTransitionError,
    TenancyConfigurationError,
    TenantCycleError,
    TenantHierarchyDepthExceededError,
    TenantNotFoundError,
)
from core.tenancy.lifecycle import TenantStatus
from core.tenancy.models import Tenant, TenantAncestry
from core.tenancy.service import (
    create_tenant,
    find_tenants_by_name,
    get_tenant,
    move_tenant,
    purge_tenant,
    transition_tenant_status,
)

__all__ = [
    "Tenant",
    "TenantAncestry",
    "TenantStatus",
    "TenantNotFoundError",
    "InvalidTenantTransitionError",
    "TenantCycleError",
    "TenantHierarchyDepthExceededError",
    "TenancyConfigurationError",
    "TenancyConfig",
    "get_tenancy_config",
    "create_tenant",
    "find_tenants_by_name",
    "get_tenant",
    "move_tenant",
    "transition_tenant_status",
    "purge_tenant",
]
