"""`core/feature-flags` -- flag definitions, per-tenant targeting rules,
and the evaluation SDK (docs/IMPLEMENTATION-ROADMAP.md Phase 4.2;
docs/ARCHITECTURE.md section 4: "Flag definitions, targeting rules,
evaluation").

The physical directory/package name uses an underscore
(`saas_os/core/feature_flags/`), not the hyphen `docs/ARCHITECTURE.md` section 3's
diagram uses (`core/feature-flags/`) -- a hyphen is not valid inside a
Python dotted import path, the same reason `core/audit-log/` maps to the
`saas_os.core.audit_log` import name (`saas_os/core/audit_log/__init__.py`'s own
docstring) and `control-plane/` maps to `control_plane`.

Owns:
- the global `FeatureFlag` catalog (`saas_os.core.feature_flags`) -- a flag
  definition and its platform-wide `enabled_by_default`;
- the tenant-owned `FeatureFlagTenantOverride` (`core.feature_flag_tenant_overrides`,
  RLS-protected) -- per-tenant targeting;
- `evaluate_flag()`, the consuming SDK entrypoint.

Does NOT own: authentication/authorization (a caller must already know
which `tenant_id` it is entitled to evaluate for -- this module trusts
its caller's `tenant_id` argument, the same convention every other Core
service function in this codebase follows), audit-log storage/immutability
(`saas_os.core.audit_log`, reused here for override changes, never reimplemented),
or any HTTP/API surface (Phase 8).
"""

from saas_os.core.feature_flags.errors import (
    DuplicateFeatureFlagKeyError,
    FeatureFlagNotFoundError,
    InvalidFeatureFlagKeyError,
)
from saas_os.core.feature_flags.models import FeatureFlag, FeatureFlagTenantOverride
from saas_os.core.feature_flags.service import (
    FlagCatalogEntry,
    FlagCatalogPage,
    TenantFlagOverride,
    TenantFlagOverridesPage,
    create_flag,
    evaluate_flag,
    get_flag,
    get_tenant_override,
    list_flags,
    read_flag_catalog,
    read_tenant_flag_overrides,
    remove_tenant_override,
    set_tenant_override,
)

__all__ = [
    "FeatureFlag",
    "FeatureFlagTenantOverride",
    "create_flag",
    "get_flag",
    "list_flags",
    "set_tenant_override",
    "remove_tenant_override",
    "get_tenant_override",
    "evaluate_flag",
    "read_flag_catalog",
    "read_tenant_flag_overrides",
    "FlagCatalogEntry",
    "FlagCatalogPage",
    "TenantFlagOverride",
    "TenantFlagOverridesPage",
    "InvalidFeatureFlagKeyError",
    "DuplicateFeatureFlagKeyError",
    "FeatureFlagNotFoundError",
]
