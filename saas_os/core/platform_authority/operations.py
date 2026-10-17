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
USER_READ = "user.read"
FEATURE_FLAG_READ = "feature_flag.read"
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

# Keys of the operations this package implements (Phase B; the two
# reads of its own tables, Phase D).
OPERATOR_READ = "operator.read"
AUDIT_READ = "audit.read"
OPERATOR_ENROLL = "operator.enroll"
OPERATOR_SUSPEND = "operator.suspend"
OPERATOR_REACTIVATE = "operator.reactivate"
OPERATOR_REVOKE = "operator.revoke"
GRANT_CREATE = "grant.create"
GRANT_REVOKE = "grant.revoke"

# Keys of the AI provider-configuration operations (ADR-0054 Phase AI-C),
# implemented by `saas_os.control_plane.inference.config` through
# `saas_os.core.platform_authority.changes.run_platform_change` and
# `run_oversight_read`.
AI_CONFIG_READ = "ai_config.read"
AI_PROVIDER_CONFIGURE = "ai_provider.configure"
AI_ENDPOINT_TRUST_CONFIGURE = "ai_endpoint_trust.configure"
AI_POLICY_CONFIGURE = "ai_policy.configure"
# ADR-0054 Phase AI-D (Q9): aggregate AI usage of one tenant, implemented by
# `saas_os.control_plane.inference.usage.read_ai_usage_totals` through
# `saas_os.core.platform_authority.oversight.run_tenant_oversight_read`.
AI_USAGE_READ = "ai_usage.read"

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
    # --- AI provider configuration (ADR-0054 Phase AI-C) ------------------
    PlatformOperation(AI_CONFIG_READ, _P.AI_CONFIG_READ, _NONE, "platform.ai_config.read"),
    PlatformOperation(AI_USAGE_READ, _P.AI_USAGE_READ, _NONE, "platform.ai_usage.read"),
    PlatformOperation(
        AI_PROVIDER_CONFIGURE, _P.AI_PROVIDER_MANAGE, _NONE, "platform.ai_provider.configure"
    ),
    PlatformOperation(
        AI_ENDPOINT_TRUST_CONFIGURE,
        _P.AI_ENDPOINT_TRUST_MANAGE,
        _NONE,
        "platform.ai_endpoint_trust.configure",
    ),
    PlatformOperation(
        AI_POLICY_CONFIGURE, _P.AI_POLICY_MANAGE, _NONE, "platform.ai_policy.configure"
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


# --- refusal labels that are not operations ------------------------------------------
#
# A `PlatformRefusalError` names what was refused in its `operation`
# attribute. Almost always that is a key of the table above. These are the
# only other values it may hold: names of things that are refused as a
# matter of platform authority and are deliberately *not* platform
# operations -- nobody is authorized for them through this table, they have
# no permission, and no route or policy is derived from them.
#
# A handler therefore maps a refusal by its type and its `code`, never by
# looking its `operation` up in `PLATFORM_OPERATIONS`.
# `tests/architecture/test_platform_refusal_labels.py` proves that every
# label a refusal is constructed with is a key of one of the two mappings.

# Identity erasure (`saas_os.core.identity.erasure`). Not a platform
# operation (ADR-0045 sections 4 and 7); refused for a user who is an
# enrolled operator (section 6), and that refusal is recorded.
USER_ERASE = "user.erase"
# `transition_tenant_status` before the edge is known: the name under which
# a caller of the wrong type is refused, before anything is read. Never
# recorded -- a refusal row needs a person or a system purpose.
TENANT_TRANSITION = "tenant.transition"
# The two composites of `saas_os.core.platform_authority.bootstrap`. Their
# refusal rows reuse the action of the first operation the composite would
# have performed (section 5b), so they have no action of their own.
PLATFORM_BOOTSTRAP_COMPOSITE = "platform.bootstrap"
PLATFORM_RECOVER_COMPOSITE = "platform.recover"


@dataclass(frozen=True)
class NonOperationRefusal:
    """`audit_action` is the platform audit action a refusal under this
    label is recorded with, or `None` when such a refusal is recorded
    under an operation's action or not at all."""

    label: str
    audit_action: str | None


_NON_OPERATION_ROWS: tuple[NonOperationRefusal, ...] = (
    NonOperationRefusal(USER_ERASE, "platform.user.erase"),
    NonOperationRefusal(TENANT_TRANSITION, None),
    NonOperationRefusal(PLATFORM_BOOTSTRAP_COMPOSITE, None),
    NonOperationRefusal(PLATFORM_RECOVER_COMPOSITE, None),
)

NON_OPERATION_REFUSALS: MappingProxyType[str, NonOperationRefusal] = MappingProxyType(
    {row.label: row for row in _NON_OPERATION_ROWS}
)

# A label is an operation or it is not: the two mappings never overlap.
if len(NON_OPERATION_REFUSALS) != len(_NON_OPERATION_ROWS) or (
    NON_OPERATION_REFUSALS.keys() & PLATFORM_OPERATIONS.keys()
):  # pragma: no cover -- import-time guard
    raise RuntimeError("the non-operation refusal labels overlap the operation table")


def is_refusal_label(label: object) -> bool:
    """Is `label` a value a `PlatformRefusalError.operation` may hold: a
    declared operation key, or one of the closed set above?"""
    return isinstance(label, str) and (
        label in PLATFORM_OPERATIONS or label in NON_OPERATION_REFUSALS
    )
