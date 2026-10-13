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

from saas_os.core.platform_authority.audit import (
    oversight_attempt_action,
    record_operator_session_issued_in_transaction,
    record_oversight_attempt,
    record_platform_event_in_transaction,
    record_platform_refusal,
    recording_platform_refusal,
    validate_reason,
)
from saas_os.core.platform_authority.authorization import (
    authorize_platform_caller,
    is_active_platform_operator,
    platform_caller_could_hold_any,
    platform_can,
    platform_operation,
)
from saas_os.core.platform_authority.bootstrap import (
    OperatorIdentity,
    PlatformBootstrapResult,
    PlatformRecoveryResult,
    bootstrap_platform_owner,
    recover_platform_authority,
)
from saas_os.core.platform_authority.config import (
    OversightReadConfig,
    OversightReadConfigurationError,
    get_oversight_read_config,
)
from saas_os.core.platform_authority.errors import (
    DeactivationScanLimitError,
    DuplicatePlatformGrantError,
    EnrolledOperatorErasureError,
    InactivePlatformSubjectError,
    InvalidPlatformOperatorStateError,
    InvalidPlatformRequestError,
    LastPlatformOwnerError,
    MoveIntoCallerHierarchyError,
    OversightReadTimeoutError,
    PlatformAlreadyBootstrappedError,
    PlatformAmplificationError,
    PlatformGrantNotFoundError,
    PlatformNotAuthorizedError,
    PlatformOperatorAlreadyEnrolledError,
    PlatformOperatorNotFoundError,
    PlatformRefusalError,
    PlatformSelfTargetError,
    PlatformSubjectNotFoundError,
    SelfAuthorityChangeError,
    TenantParentRuleError,
    UnknownPlatformOperationError,
    UserNotResolvedError,
)
from saas_os.core.platform_authority.models import (
    OperatorStatus,
    PlatformActorType,
    PlatformAuditLogEntry,
    PlatformAuditOutcome,
    PlatformGrant,
    PlatformOperator,
)
from saas_os.core.platform_authority.operations import (
    NON_OPERATION_REFUSALS,
    PLATFORM_OPERATIONS,
    NonOperationRefusal,
    PlatformOperation,
    is_refusal_label,
)
from saas_os.core.platform_authority.oversight import (
    DEFAULT_OVERSIGHT_PAGE_SIZE,
    MAX_OVERSIGHT_PAGE_SIZE,
    OversightOutcome,
    PlatformAuditPage,
    PlatformAuditView,
    PlatformGrantPage,
    PlatformGrantView,
    PlatformOperatorPage,
    PlatformOperatorView,
    list_platform_audit,
    list_platform_grants,
    list_platform_operators,
    oversight_read_timeout,
    require_oversight_caller,
    run_oversight_read,
    validate_page_request,
)
from saas_os.core.platform_authority.owners import lock_platform_owners, platform_owner_exists
from saas_os.core.platform_authority.permissions import (
    OWNER_PERMISSION,
    PLATFORM_PERMISSION_VALUES,
    PlatformPermission,
)
from saas_os.core.platform_authority.service import (
    enroll_operator,
    grant_platform_permission,
    reactivate_operator,
    revoke_operator,
    revoke_platform_permission,
    suspend_operator,
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
    # authorization
    "platform_can",
    "authorize_platform_caller",
    "platform_caller_could_hold_any",
    "is_active_platform_operator",
    "PLATFORM_OPERATIONS",
    "PlatformOperation",
    "platform_operation",
    "NON_OPERATION_REFUSALS",
    "NonOperationRefusal",
    "is_refusal_label",
    "platform_owner_exists",
    "lock_platform_owners",
    # operator and grant lifecycle
    "enroll_operator",
    "suspend_operator",
    "reactivate_operator",
    "revoke_operator",
    "grant_platform_permission",
    "revoke_platform_permission",
    # bootstrap and recovery (system purpose only)
    "bootstrap_platform_owner",
    "recover_platform_authority",
    "OperatorIdentity",
    "PlatformBootstrapResult",
    "PlatformRecoveryResult",
    # audit
    "record_platform_event_in_transaction",
    "record_platform_refusal",
    "recording_platform_refusal",
    "record_operator_session_issued_in_transaction",
    "record_oversight_attempt",
    "oversight_attempt_action",
    "validate_reason",
    # oversight reads
    "run_oversight_read",
    "OversightOutcome",
    "oversight_read_timeout",
    "validate_page_request",
    "require_oversight_caller",
    "DEFAULT_OVERSIGHT_PAGE_SIZE",
    "MAX_OVERSIGHT_PAGE_SIZE",
    "OversightReadConfig",
    "OversightReadConfigurationError",
    "get_oversight_read_config",
    "list_platform_operators",
    "list_platform_grants",
    "list_platform_audit",
    "PlatformOperatorView",
    "PlatformOperatorPage",
    "PlatformGrantView",
    "PlatformGrantPage",
    "PlatformAuditView",
    "PlatformAuditPage",
    # errors
    "OversightReadTimeoutError",
    "PlatformRefusalError",
    "EnrolledOperatorErasureError",
    "PlatformNotAuthorizedError",
    "SelfAuthorityChangeError",
    "PlatformAmplificationError",
    "LastPlatformOwnerError",
    "PlatformSelfTargetError",
    "TenantParentRuleError",
    "MoveIntoCallerHierarchyError",
    "DeactivationScanLimitError",
    "UnknownPlatformOperationError",
    "InvalidPlatformRequestError",
    "PlatformSubjectNotFoundError",
    "UserNotResolvedError",
    "InactivePlatformSubjectError",
    "PlatformOperatorNotFoundError",
    "PlatformOperatorAlreadyEnrolledError",
    "InvalidPlatformOperatorStateError",
    "PlatformGrantNotFoundError",
    "DuplicatePlatformGrantError",
    "PlatformAlreadyBootstrappedError",
]
