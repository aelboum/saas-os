"""`saas_os/core/tenancy` -- tenant entity and lifecycle (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.1; docs/MULTI-TENANCY.md; docs/ADR/0002-multi-tenancy-isolation-model.md).

The tenant entity *is* the customer organization (docs/MULTI-TENANCY.md
section 1) -- `tenant_id` is the one canonical identifier every other
tenant-owned table across the platform will carry. This module owns:

- the `Tenant` entity itself (`core.tenants`, `saas_os/core/tenancy/models.py`);
- its lifecycle state machine (`TenantStatus`, `saas_os/core/tenancy/lifecycle.py`);
- CRUD/lifecycle operations (`saas_os/core/tenancy/service.py`);
- its optional tenant hierarchy (architecture research: universal
  multi-tenant tenancy, Phase A; ADR-0002 amendment) -- `Tenant.parent_id`,
  the `core.tenant_ancestry` closure table (`TenantAncestry`),
  `move_tenant()`, and the published `get_ancestor_ids()`/`get_ancestor_chain()`/
  `get_descendant_ids()` reads other Core modules use instead of querying
  `TenantAncestry` directly. Structural data only: a tenant's position in
  the tree grants no authorization by itself (`saas_os/core/tenancy/models.py`'s
  docstring) -- `saas_os/core/rbac`'s scoped roles (architecture research Phase B)
  are the first module to consume `get_ancestor_ids()`, to evaluate a
  `SUBTREE`-scoped role against the live hierarchy; `saas_os/core/billing`'s
  `resolve_billing_owner()` (architecture research Phase H) is the first
  to consume the ordered `get_ancestor_chain()`, and `saas_os/core/usage`'s
  hierarchy-aware rollup is the first to consume `get_descendant_ids()`.
- `Tenant.inherits_billing` -- retired forward (Phase 5.3 step 5): no
  code path can set it to `true` (a database trigger refuses it), existing
  `true` rows keep read compatibility in `saas_os/core/billing`'s entitlement
  resolution only (never authorization), and the only way to turn it off
  is the authorized, audited `saas_os.core.billing.opt_out_of_billing_inheritance()`
  or `migrate_inherited_tenant_to_sponsorship()`.

Tenant-scoping *enforcement* for tenant-*owned* data (as opposed to the
tenant registry itself) is `saas_os.infra.db.tenant_session_scope()` +
`saas_os.infra.db.rls.tenant_rls_statements()` -- completed in this same phase,
since `saas_os/core/tenancy` is the first module that needs it, but those
primitives live in `saas_os/infra/db` (docs/ARCHITECTURE.md section 2:
"Infrastructure has zero knowledge of business concepts" -- `saas_os/infra/db`
provides the mechanism, `saas_os/core/tenancy` is the first thing that uses it).

`saas_os/core/tenancy` never imports `sqlalchemy` directly -- it defines its table
using `saas_os.infra.db.orm`'s shared declarative base
(`pyproject.toml`'s "Only saas_os/infra/db may import SQLAlchemy or psycopg
directly" contract).
"""

from saas_os.core.tenancy.config import TenancyConfig, get_tenancy_config
from saas_os.core.tenancy.errors import (
    InvalidTenantTransitionError,
    PlatformTenantNotConfiguredError,
    TenancyConfigurationError,
    TenantClosedError,
    TenantCycleError,
    TenantHasDescendantsError,
    TenantHierarchyDepthExceededError,
    TenantInaccessibleError,
    TenantNotFoundError,
    TenantNotPurgingError,
    TenantPurgeIncompleteError,
)
from saas_os.core.tenancy.lifecycle import (
    CLOSED_STATUSES,
    PRINCIPAL_INACCESSIBLE_STATUSES,
    TenantStatus,
    is_accessible_to_principals,
    is_closed,
)
from saas_os.core.tenancy.models import Tenant, TenantAncestry
from saas_os.core.tenancy.registry import (
    TenantRegistryEntry,
    TenantRegistryPage,
    list_tenant_registry,
    read_tenant_registry_entry,
)
from saas_os.core.tenancy.retention import (
    PURGE_STEP_FOR_TABLE,
    RETENTION_CLASSIFICATION,
    RetentionClass,
    retention_class_for,
    tables_in,
)
from saas_os.core.tenancy.service import (
    PURGE_STEPS,
    TenantPurgeResult,
    count_unpurged_tenants,
    create_tenant,
    descendant_ids_by_depth,
    find_tenants_by_name,
    get_ancestor_chain,
    get_ancestor_ids,
    get_descendant_ids,
    get_platform_tenant_id,
    get_tenant,
    list_open_tenant_ids,
    lock_accessible_tenant,
    lock_ancestor_ids,
    lock_open_tenant,
    move_tenant,
    purge_tenant,
    require_open_tenant,
    require_platform_tenant,
    require_purging_tenant,
    root_depths,
    tenant_job_session,
    tenant_row_exists,
    transition_tenant_status,
    unpurged_tenant_ids_page,
)

__all__ = [
    "Tenant",
    "TenantAncestry",
    "TenantStatus",
    "RetentionClass",
    "RETENTION_CLASSIFICATION",
    "PURGE_STEP_FOR_TABLE",
    "retention_class_for",
    "tables_in",
    "CLOSED_STATUSES",
    "PRINCIPAL_INACCESSIBLE_STATUSES",
    "is_closed",
    "is_accessible_to_principals",
    "require_open_tenant",
    "require_purging_tenant",
    "lock_open_tenant",
    "lock_accessible_tenant",
    "lock_ancestor_ids",
    "tenant_job_session",
    "TenantInaccessibleError",
    "PURGE_STEPS",
    "TenantPurgeResult",
    # ADR-0045 section 9d: operational oversight of the registry.
    "TenantRegistryEntry",
    "TenantRegistryPage",
    "list_tenant_registry",
    "read_tenant_registry_entry",
    "TenantClosedError",
    "TenantNotPurgingError",
    "TenantHasDescendantsError",
    "TenantPurgeIncompleteError",
    "TenantNotFoundError",
    "InvalidTenantTransitionError",
    "TenantCycleError",
    "TenantHierarchyDepthExceededError",
    "TenancyConfigurationError",
    "PlatformTenantNotConfiguredError",
    "get_platform_tenant_id",
    "require_platform_tenant",
    "TenancyConfig",
    "get_tenancy_config",
    "create_tenant",
    "find_tenants_by_name",
    "get_ancestor_ids",
    "list_open_tenant_ids",
    "count_unpurged_tenants",
    "unpurged_tenant_ids_page",
    "root_depths",
    "get_ancestor_chain",
    "descendant_ids_by_depth",
    "get_descendant_ids",
    "get_tenant",
    "tenant_row_exists",
    "move_tenant",
    "transition_tenant_status",
    "purge_tenant",
]
