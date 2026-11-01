"""Permission grant migrations for existing tenants (ADR 0060, option C;
owner decisions of 2026-11-01; ADR-0045 amendment of 2026-11-01;
docs/architecture/PERMISSION-GRANT-MIGRATIONS-DESIGN.md).

A product declares, in its own code, an ordered, append-only list of
`PermissionGrantMigration`s: each adds registered, non-authority
permissions to one role name the product created at provisioning. A
platform operator holding `platform.permission_grant:apply` applies them
to existing tenants with `apply_permission_grant_migrations` (or the
operator command `saas-os-operator apply-permission-grants`), dry run by
default. Each application is recorded once per tenant in the tenant-owned
ledger `core.permission_grant_applications`, and never re-evaluated: a
permission a tenant administrator revoked afterwards stays revoked.

What it never does: remove a grant, create or rename a role, assign a role,
add a membership, touch a deny grant or a delegation, grant an
authority-changing permission, or register a permission.
"""

from saas_os.core.permission_grants.apply import (
    MAX_NAMED_TENANTS,
    TENANT_CHANGED,
    TENANT_CLOSED,
    TENANT_FAILED,
    TENANT_NOT_FOUND,
    TENANT_UNCHANGED,
    PermissionGrantRunResult,
    TenantGrantResult,
    apply_permission_grant_migrations,
)
from saas_os.core.permission_grants.declarations import (
    PermissionGrantMigration,
    permission_grant_migration_digest,
    validate_permission_grant_migrations,
)
from saas_os.core.permission_grants.errors import (
    AuthorityPermissionGrantError,
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

__all__ = [
    "PermissionGrantMigration",
    "permission_grant_migration_digest",
    "validate_permission_grant_migrations",
    "apply_permission_grant_migrations",
    "PermissionGrantRunResult",
    "TenantGrantResult",
    "MAX_NAMED_TENANTS",
    "TENANT_CHANGED",
    "TENANT_UNCHANGED",
    "TENANT_CLOSED",
    "TENANT_NOT_FOUND",
    "TENANT_FAILED",
    "PermissionGrantApplication",
    "APPLICATION_OUTCOME_APPLIED",
    "APPLICATION_OUTCOME_ROLE_MISSING",
    "PermissionGrantMigrationError",
    "InvalidPermissionGrantMigrationError",
    "AuthorityPermissionGrantError",
    "UnregisteredPermissionGrantError",
    "PermissionGrantMigrationChangedError",
]
