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

Retention (owner policy of 2026-11-02): the ledger is `SECURITY_RETAIN`; a
tenant's rows become eligible for expiry two years after the tenant reached
`PURGED`, unless a legal hold is active (`retention_eligibility`,
`permission_grant_ledger_retention_report`, `place_permission_grant_ledger_hold`,
`release_permission_grant_ledger_hold`). Nothing exported here deletes a
ledger row. The only deletion path is the manual migrations-role procedure
of owner decision B of 2026-11-02 (`saas_os.core.permission_grants.expiry`,
not exported), and it is **disabled** (`LedgerDeletionDisabledError`) until
a verifiable approval control exists: every operator id these commands
take is declared, not authenticated, so separation of duties between
releasing a hold and authorising a deletion cannot be verified.

The approval mechanism (owner decisions of 2026-11-03;
docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md): the authenticated
platform-admin retention API -- `request_permission_grant_ledger_deletion`,
`approve_permission_grant_ledger_deletion`,
`authorize_permission_grant_ledger_deletion_execution` and their reads,
`list_permission_grant_ledger_holds`, hold placement and release -- and the
append-only approver eligibility register (`propose_representative_designation`,
`confirm_representative_designation`, `enrol_approver`,
`revoke_register_entry`, `read_approver_register`,
`read_approver_eligibility`). Each takes the caller from the authenticated
session the platform-admin route names, never a declared id; releasing a
hold, approving and every register write require that session's evidence.
None of them deletes a ledger row; deletion stays disabled.

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
from saas_os.core.permission_grants.approvals import (
    DeletionApprovalView,
    DeletionRequestPage,
    DeletionRequestView,
    ExecutionAuthorizationView,
    approve_permission_grant_ledger_deletion,
    authorize_permission_grant_ledger_deletion_execution,
    read_permission_grant_ledger_deletion_requests,
    request_permission_grant_ledger_deletion,
    scope_digest,
)
from saas_os.core.permission_grants.declarations import (
    PermissionGrantMigration,
    permission_grant_migration_digest,
    validate_permission_grant_migrations,
)
from saas_os.core.permission_grants.errors import (
    APPROVAL_NOT_FOUND_CODES,
    APPROVAL_REFUSAL_CODES,
    AuthorityPermissionGrantError,
    InvalidLedgerRetentionRequestError,
    InvalidPermissionGrantMigrationError,
    LedgerApprovalRecordNotFoundError,
    LedgerApprovalRefusedError,
    LedgerDeletionDisabledError,
    LedgerExpiryConfirmationMismatchError,
    LedgerHoldAlreadyActiveError,
    LedgerHoldAlreadyReleasedError,
    LedgerHoldNotFoundError,
    LedgerHoldTenantNotFoundError,
    PermissionGrantLedgerRetentionError,
    PermissionGrantMigrationChangedError,
    PermissionGrantMigrationError,
    UnregisteredPermissionGrantError,
)
from saas_os.core.permission_grants.models import (
    APPLICATION_OUTCOME_APPLIED,
    APPLICATION_OUTCOME_ROLE_MISSING,
    REGISTER_ENTRY_TYPES,
    ApproverRegisterEntry,
    LedgerDeletionApproval,
    LedgerDeletionRequest,
    LedgerExecutionAuthorization,
    PermissionGrantApplication,
    PermissionGrantLedgerHold,
)
from saas_os.core.permission_grants.register import (
    EligibilityPage,
    EnrolmentEligibility,
    EnrolmentState,
    RegisterEntryView,
    RegisterPage,
    RevocationResult,
    approver_eligibility,
    confirm_representative_designation,
    enrol_approver,
    enrolment_state,
    propose_representative_designation,
    read_approver_eligibility,
    read_approver_register,
    revoke_register_entry,
)
from saas_os.core.permission_grants.retention import (
    MAX_REPORT_TENANTS,
    RETENTION_PERIOD_YEARS,
    LedgerHoldPage,
    LedgerHoldResult,
    LedgerHoldView,
    LedgerRetentionReport,
    RetentionDecision,
    RetentionStatus,
    TenantLedgerRetention,
    eligible_ledger_digest,
    list_permission_grant_ledger_holds,
    permission_grant_ledger_retention_report,
    place_permission_grant_ledger_hold,
    release_permission_grant_ledger_hold,
    retention_eligibility,
    retention_expires_at,
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
    "PermissionGrantLedgerHold",
    "RETENTION_PERIOD_YEARS",
    "MAX_REPORT_TENANTS",
    "RetentionStatus",
    "RetentionDecision",
    "retention_eligibility",
    "retention_expires_at",
    "permission_grant_ledger_retention_report",
    "LedgerRetentionReport",
    "TenantLedgerRetention",
    "place_permission_grant_ledger_hold",
    "release_permission_grant_ledger_hold",
    "LedgerHoldResult",
    "PermissionGrantLedgerRetentionError",
    "InvalidLedgerRetentionRequestError",
    "LedgerHoldTenantNotFoundError",
    "LedgerHoldAlreadyActiveError",
    "LedgerHoldNotFoundError",
    "LedgerHoldAlreadyReleasedError",
    "eligible_ledger_digest",
    "LedgerDeletionDisabledError",
    "LedgerExpiryConfirmationMismatchError",
    # the approval mechanism (owner decisions of 2026-11-03)
    "list_permission_grant_ledger_holds",
    "LedgerHoldView",
    "LedgerHoldPage",
    "request_permission_grant_ledger_deletion",
    "approve_permission_grant_ledger_deletion",
    "authorize_permission_grant_ledger_deletion_execution",
    "read_permission_grant_ledger_deletion_requests",
    "DeletionRequestView",
    "DeletionApprovalView",
    "DeletionRequestPage",
    "ExecutionAuthorizationView",
    "scope_digest",
    "propose_representative_designation",
    "confirm_representative_designation",
    "enrol_approver",
    "revoke_register_entry",
    "read_approver_register",
    "read_approver_eligibility",
    "RegisterEntryView",
    "RegisterPage",
    "RevocationResult",
    "EnrolmentState",
    "EnrolmentEligibility",
    "EligibilityPage",
    "enrolment_state",
    "approver_eligibility",
    "ApproverRegisterEntry",
    "LedgerDeletionRequest",
    "LedgerDeletionApproval",
    "LedgerExecutionAuthorization",
    "REGISTER_ENTRY_TYPES",
    "LedgerApprovalRefusedError",
    "LedgerApprovalRecordNotFoundError",
    "APPROVAL_REFUSAL_CODES",
    "APPROVAL_NOT_FOUND_CODES",
]
