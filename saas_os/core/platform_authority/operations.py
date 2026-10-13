"""The declared platform operation table
(docs/ADR/0045-installation-scoped-platform-authority.md sections 5a, 5b).

One row per platform operation: the permission a person needs, the system
purposes the operation accepts (most often none), and its platform audit
action. `authorize_platform_caller()` reads the row by key. A call site
names an operation; it cannot pass, and so cannot widen, the set of
accepted purposes -- which the tenant-side
`saas_os.core.rbac.authorize_caller(system_authorities=...)` shape allows.

The table is the whole decided inventory, including the operations later
phases implement. A row is a declaration of who *would* be authorized, not
an implementation: nothing in this package performs a tenant, user,
session, API-key, flag or oversight operation. The Core module that owns
the state performs it and authorizes through this table.

`tests/core/platform_authority/test_platform_operations_unit.py` compares
this table, row by row, with a literal copy of the ADR's inventory.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from saas_os.core.authority import SystemAuthority
from saas_os.core.platform_authority.permissions import PlatformPermission

_NONE: frozenset[SystemAuthority] = frozenset()
_PROVISIONING = frozenset({SystemAuthority.PROVISIONING})
_TENANT_PURGE = frozenset({SystemAuthority.TENANT_PURGE})
_PLATFORM_BOOTSTRAP = frozenset({SystemAuthority.PLATFORM_BOOTSTRAP})


@dataclass(frozen=True)
class PlatformOperation:
    """`permission` is `None` only for an operation no person may perform
    (the purge transitions). `system_authorities` is the complete set of
    purposes accepted; empty means the operation requires a person."""

    key: str
    permission: PlatformPermission | None
    system_authorities: frozenset[SystemAuthority]
    audit_action: str


# Keys of the operations the Core modules that own the state implement
# (Phase C): `saas_os.core.tenancy`, `saas_os.core.identity`,
# `saas_os.core.feature_flags` and `saas_os.core.billing`, each of which
# authorizes through this table.
TENANT_READ = "tenant.read"
BILLING_READ = "billing.read"
TENANT_CREATE_ROOT = "tenant.create_root"
TENANT_CREATE_CHILD = "tenant.create_child"
TENANT_ACTIVATE = "tenant.activate"
TENANT_SUSPEND = "tenant.suspend"
TENANT_REACTIVATE = "tenant.reactivate"
TENANT_MOVE = "tenant.move"
TENANT_DELETE = "tenant.delete"
TENANT_PURGE_TRANSITION = "tenant.purge_transition"
USER_DEACTIVATE = "user.deactivate"
USER_REACTIVATE = "user.reactivate"
SESSION_REVOKE = "session.revoke"
API_KEY_REVOKE = "api_key.revoke"  # pragma: allowlist secret -- an operation key
FEATURE_FLAG_DEFINE = "feature_flag.define"
FEATURE_FLAG_OVERRIDE = "feature_flag.override"

# Keys of the operations this package implements (Phase B).
OPERATOR_ENROLL = "operator.enroll"
OPERATOR_SUSPEND = "operator.suspend"
OPERATOR_REACTIVATE = "operator.reactivate"
OPERATOR_REVOKE = "operator.revoke"
GRANT_CREATE = "grant.create"
GRANT_REVOKE = "grant.revoke"

_P = PlatformPermission

_ROWS: tuple[PlatformOperation, ...] = (
    # --- oversight ---------------------------------------------------------
    PlatformOperation("tenant.read", _P.TENANT_READ, _NONE, "platform.tenant.read"),
    PlatformOperation("user.read", _P.USER_READ, _NONE, "platform.user.read"),
    PlatformOperation("operator.read", _P.OPERATOR_READ, _NONE, "platform.operator.read"),
    PlatformOperation("audit.read", _P.AUDIT_READ, _NONE, "platform.audit.read"),
    PlatformOperation("billing.read", _P.BILLING_READ, _NONE, "platform.billing.read"),
    PlatformOperation(
        "feature_flag.read", _P.FEATURE_FLAG_READ, _NONE, "platform.feature_flag.read"
    ),
    # --- tenant lifecycle --------------------------------------------------
    PlatformOperation(
        "tenant.create_root", _P.TENANT_CREATE, _PROVISIONING, "platform.tenant.create"
    ),
    # Provisioning is accepted here only beneath a PENDING parent; that
    # second condition is checked by `create_tenant` itself (section 12a).
    PlatformOperation(
        "tenant.create_child", _P.TENANT_CREATE, _PROVISIONING, "platform.tenant.create"
    ),
    PlatformOperation(
        "tenant.activate", _P.TENANT_CREATE, _PROVISIONING, "platform.tenant.activate"
    ),
    PlatformOperation("tenant.suspend", _P.TENANT_SUSPEND, _NONE, "platform.tenant.suspend"),
    PlatformOperation(
        "tenant.reactivate", _P.TENANT_REACTIVATE, _NONE, "platform.tenant.reactivate"
    ),
    PlatformOperation("tenant.move", _P.TENANT_MOVE, _NONE, "platform.tenant.move"),
    PlatformOperation("tenant.delete", _P.TENANT_DELETE, _NONE, "platform.tenant.delete"),
    PlatformOperation(
        "tenant.purge_transition", None, _TENANT_PURGE, "platform.tenant.purge_transition"
    ),
    # --- users and credentials ---------------------------------------------
    PlatformOperation("user.deactivate", _P.USER_DEACTIVATE, _NONE, "platform.user.deactivate"),
    PlatformOperation("user.reactivate", _P.USER_REACTIVATE, _NONE, "platform.user.reactivate"),
    PlatformOperation("session.revoke", _P.SESSION_REVOKE, _NONE, "platform.session.revoke"),
    PlatformOperation("api_key.revoke", _P.API_KEY_REVOKE, _NONE, "platform.api_key.revoke"),
    # --- feature flags -----------------------------------------------------
    PlatformOperation(
        "feature_flag.define",
        _P.FEATURE_FLAG_DEFINE,
        _PROVISIONING,
        "platform.feature_flag.define",
    ),
    PlatformOperation(
        "feature_flag.override", _P.FEATURE_FLAG_OVERRIDE, _NONE, "platform.feature_flag.override"
    ),
    # --- platform authority ------------------------------------------------
    PlatformOperation(
        OPERATOR_ENROLL, _P.AUTHORITY_MANAGE, _PLATFORM_BOOTSTRAP, "platform.operator.enroll"
    ),
    PlatformOperation(
        OPERATOR_SUSPEND, _P.AUTHORITY_MANAGE, _PLATFORM_BOOTSTRAP, "platform.operator.suspend"
    ),
    PlatformOperation(
        OPERATOR_REACTIVATE, _P.AUTHORITY_MANAGE, _NONE, "platform.operator.reactivate"
    ),
    PlatformOperation(OPERATOR_REVOKE, _P.AUTHORITY_MANAGE, _NONE, "platform.operator.revoke"),
    PlatformOperation(
        GRANT_CREATE, _P.AUTHORITY_MANAGE, _PLATFORM_BOOTSTRAP, "platform.grant.create"
    ),
    PlatformOperation(GRANT_REVOKE, _P.AUTHORITY_MANAGE, _NONE, "platform.grant.revoke"),
)

PLATFORM_OPERATIONS: MappingProxyType[str, PlatformOperation] = MappingProxyType(
    {row.key: row for row in _ROWS}
)

# A duplicate key would silently drop a row from the mapping.
if len(PLATFORM_OPERATIONS) != len(_ROWS):  # pragma: no cover -- import-time guard
    raise RuntimeError("duplicate key in the platform operation table")
