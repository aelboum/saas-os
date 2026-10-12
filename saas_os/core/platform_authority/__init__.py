"""Installation-scoped platform authority
(docs/ADR/0045-installation-scoped-platform-authority.md).

A platform operator is an existing `saas_os.core.identity` user enrolled in
this deployment's own database. What an operator may do is decided here,
from platform grant storage only, by `platform_can()`. It is a separate
authority system from tenant RBAC:

- `saas_os.core.rbac.can()` never reads platform operators or grants, and
  `saas_os.core.rbac` does not import this package (an import-linter
  contract pins that);
- `platform_can()` never reads a tenant membership, role, delegation, deny
  or support-access grant, a tenant's status, or `PLATFORM_TENANT_ID`;
- a platform permission is not a row in `core.permissions`, so it cannot be
  attached to a tenant role, delegated, or satisfied by support access.

The platform tables carry a row-level-security policy that hides them from
every tenant-scoped transaction. That policy is defence in depth. It does
not authorize anything: every operation in this package authorizes its
caller explicitly, in its own transaction.
"""

from saas_os.core.platform_authority.models import (
    OperatorStatus,
    PlatformActorType,
    PlatformAuditLogEntry,
    PlatformAuditOutcome,
    PlatformGrant,
    PlatformOperator,
)
from saas_os.core.platform_authority.permissions import (
    OWNER_PERMISSION,
    PLATFORM_PERMISSION_VALUES,
    PlatformPermission,
)

__all__ = [
    "PlatformPermission",
    "PLATFORM_PERMISSION_VALUES",
    "OWNER_PERMISSION",
    "PlatformOperator",
    "PlatformGrant",
    "PlatformAuditLogEntry",
    "OperatorStatus",
    "PlatformActorType",
    "PlatformAuditOutcome",
]
