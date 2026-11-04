"""The platform-admin routes
(docs/ADR/0045-installation-scoped-platform-authority.md section 7).

One route per row of the section's table that says "yes" under HTTP, and
none for a row that says "no" or "never": there is no route here for
moving or deleting a tenant, purging, erasing an identity, the owner
bootstrap, recovery, migrations or backup.

`PLATFORM_ROUTES` is the whole inventory -- method, path, permission,
operation and whether a fresh session is required -- and the router is
built from it, so the pinned-contract test compares one table with the
ADR's.

**Handlers are plain functions, not coroutines.** Every Core call is
synchronous database work; FastAPI runs a plain handler in its thread
pool, so a slow or lock-waiting operation holds one worker thread and not
the event loop, like the other opt-in capability routers.

**A route decides nothing.** Its dependency refuses a caller who is not an
active operator holding the permission, before the handler runs. The
handler names the authenticated user to one Core function, which
authorizes that caller again inside its own transaction and writes the
evidence. A refusal Core raises after the dependency passed (authority
revoked in between, an invariant, a state the request does not fit) is
translated by `_translating()` into a fixed response: never Core's own
message, except for a request-validation error, which is written for the
caller and names no stored value.

**Permission grant ledger retention** (owner decisions of 2026-11-03;
`docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`): the retention
report, legal holds, the deletion request, its approval and execution
authorisation, and the approver eligibility register. Every retention
request model forbids extra fields (`extra="forbid"`: an unknown field is a
`422` and the handler never runs) and has no identity field; a register
write names its subject in the path. The state-changing retention routes
hand Core the session the chain validated (`PlatformSessionEvidence`) and
whether the deployment requires a multi-factor login; Core checks both
against storage. There is no route for the deletion itself: it stays a
migrations-role procedure, and it is disabled.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from saas_os.api.dependencies import PlatformRequestContext, require_platform_permission
from saas_os.api.errors import (
    conflict,
    forbidden,
    invalid_request,
    not_found,
    service_unavailable,
)
from saas_os.api.platform_admin.config import get_platform_admin_http_config
from saas_os.core.authority import UserCaller
from saas_os.core.billing import commercial_overview
from saas_os.core.feature_flags import (
    DuplicateFeatureFlagKeyError,
    FeatureFlagNotFoundError,
    InvalidFeatureFlagKeyError,
    create_flag,
    read_flag_catalog,
    read_tenant_flag_overrides,
    remove_tenant_override,
    set_tenant_override,
)
from saas_os.core.identity import (
    deactivate_user,
    reactivate_user,
    resolve_user,
    revoke_user_api_keys,
    revoke_user_sessions,
)
from saas_os.core.identity.errors import (
    DeactivationRetryError,
    InvalidUserStateError,
    LastTenantAdministratorError,
)
from saas_os.core.permission_grants import (
    APPROVAL_NOT_FOUND_CODES,
    APPROVAL_REFUSAL_CODES,
    InvalidLedgerRetentionRequestError,
    LedgerApprovalRecordNotFoundError,
    LedgerApprovalRefusedError,
    LedgerExpiryConfirmationMismatchError,
    LedgerHoldAlreadyActiveError,
    LedgerHoldAlreadyReleasedError,
    LedgerHoldNotFoundError,
    LedgerHoldTenantNotFoundError,
    approve_permission_grant_ledger_deletion,
    authorize_permission_grant_ledger_deletion_execution,
    confirm_representative_designation,
    enrol_approver,
    list_permission_grant_ledger_holds,
    permission_grant_ledger_retention_report,
    place_permission_grant_ledger_hold,
    propose_representative_designation,
    read_approver_eligibility,
    read_approver_register,
    read_permission_grant_ledger_deletion_requests,
    release_permission_grant_ledger_hold,
    request_permission_grant_ledger_deletion,
    revoke_register_entry,
)
from saas_os.core.platform_authority import (
    DuplicatePlatformGrantError,
    InactivePlatformSubjectError,
    InvalidPlatformOperatorStateError,
    InvalidPlatformRequestError,
    OversightReadTimeoutError,
    PlatformGrantNotFoundError,
    PlatformNotAuthorizedError,
    PlatformOperationTimeoutError,
    PlatformOperatorAlreadyEnrolledError,
    PlatformOperatorNotFoundError,
    PlatformPermission,
    PlatformRefusalError,
    PlatformSessionEvidence,
    PlatformSubjectNotFoundError,
    UserNotResolvedError,
    enroll_operator,
    grant_platform_permission,
    list_platform_audit,
    list_platform_grants,
    list_platform_operators,
    reactivate_operator,
    revoke_operator,
    revoke_platform_permission,
    suspend_operator,
)
from saas_os.core.tenancy import (
    InvalidTenantTransitionError,
    TenantClosedError,
    TenantHierarchyDepthExceededError,
    TenantNotFoundError,
    TenantStatus,
    create_tenant,
    list_tenant_registry,
    read_tenant_registry_entry,
    transition_tenant_status,
)
from saas_os.infra.db import is_transaction_conflict

P = PlatformPermission
PREFIX = "/v1/platform"

# No control characters in free-text request fields: PostgreSQL rejects a
# NUL byte with a data error, which would surface as a 500.
_PRINTABLE = r"^[^\x00-\x1f\x7f]+$"
_RETRY_AFTER_SECONDS = 5

Reason = Annotated[str, Field(min_length=1, max_length=500, pattern=_PRINTABLE)]
OptionalReason = Annotated[str | None, Field(max_length=500, pattern=_PRINTABLE)]
# Bounded by Core, which rejects a page above its maximum (decision D3): a
# request above it is a 400, never a silently shortened page.
PageSize = Annotated[int | None, Query()]


# --- the inventory ---------------------------------------------------------------------


_PGL = "/permission-grant-ledger"
_REG = f"{_PGL}/approver-register"


@dataclass(frozen=True)
class PlatformRoute:
    method: str
    path: str  # relative to PREFIX
    permission: PlatformPermission
    operation: str
    fresh_session: bool = False


PLATFORM_ROUTES: tuple[PlatformRoute, ...] = (
    # oversight
    PlatformRoute("GET", "/tenants", P.TENANT_READ, "tenant.read"),
    PlatformRoute("GET", "/tenants/{tenant_id}", P.TENANT_READ, "tenant.read"),
    PlatformRoute("GET", "/users/{user_id}", P.USER_READ, "user.read"),
    PlatformRoute("POST", "/users/resolve", P.USER_READ, "user.read"),
    PlatformRoute("GET", "/operators", P.OPERATOR_READ, "operator.read"),
    PlatformRoute("GET", "/grants", P.OPERATOR_READ, "operator.read"),
    PlatformRoute("GET", "/audit", P.AUDIT_READ, "audit.read"),
    PlatformRoute("GET", "/billing/overview", P.BILLING_READ, "billing.read"),
    PlatformRoute("GET", "/feature-flags", P.FEATURE_FLAG_READ, "feature_flag.read"),
    PlatformRoute(
        "GET", "/tenants/{tenant_id}/feature-flags", P.FEATURE_FLAG_READ, "feature_flag.read"
    ),
    # tenant lifecycle (no move, no delete, no purge)
    PlatformRoute("POST", "/tenants", P.TENANT_CREATE, "tenant.create_root"),
    PlatformRoute("POST", "/tenants/{tenant_id}/activate", P.TENANT_CREATE, "tenant.activate"),
    PlatformRoute("POST", "/tenants/{tenant_id}/suspend", P.TENANT_SUSPEND, "tenant.suspend"),
    PlatformRoute(
        "POST", "/tenants/{tenant_id}/reactivate", P.TENANT_REACTIVATE, "tenant.reactivate"
    ),
    # users and credentials (no erasure)
    PlatformRoute("POST", "/users/{user_id}/deactivate", P.USER_DEACTIVATE, "user.deactivate"),
    PlatformRoute("POST", "/users/{user_id}/reactivate", P.USER_REACTIVATE, "user.reactivate"),
    PlatformRoute("POST", "/users/{user_id}/sessions/revoke", P.SESSION_REVOKE, "session.revoke"),
    PlatformRoute("POST", "/users/{user_id}/api-keys/revoke", P.API_KEY_REVOKE, "api_key.revoke"),
    # feature flags
    PlatformRoute("POST", "/feature-flags", P.FEATURE_FLAG_DEFINE, "feature_flag.define"),
    PlatformRoute(
        "PUT",
        "/tenants/{tenant_id}/feature-flags/{key}",
        P.FEATURE_FLAG_OVERRIDE,
        "feature_flag.override",
    ),
    PlatformRoute(
        "DELETE",
        "/tenants/{tenant_id}/feature-flags/{key}",
        P.FEATURE_FLAG_OVERRIDE,
        "feature_flag.override",
    ),
    # platform authority: every one requires a fresh session (decision D2)
    PlatformRoute("POST", "/operators", P.AUTHORITY_MANAGE, "operator.enroll", True),
    PlatformRoute(
        "POST", "/operators/{operator_id}/suspend", P.AUTHORITY_MANAGE, "operator.suspend", True
    ),
    PlatformRoute(
        "POST",
        "/operators/{operator_id}/reactivate",
        P.AUTHORITY_MANAGE,
        "operator.reactivate",
        True,
    ),
    PlatformRoute(
        "POST", "/operators/{operator_id}/revoke", P.AUTHORITY_MANAGE, "operator.revoke", True
    ),
    PlatformRoute(
        "POST", "/operators/{operator_id}/grants", P.AUTHORITY_MANAGE, "grant.create", True
    ),
    PlatformRoute(
        "POST", "/operators/{operator_id}/grants/revoke", P.AUTHORITY_MANAGE, "grant.revoke", True
    ),
    # permission grant ledger retention (owner decisions of 2026-11-03)
    PlatformRoute(
        "POST",
        f"{_PGL}/retention-report",
        P.SECURITY_RETENTION_REPORT,
        "permission_grant_ledger.retention_report",
    ),
    PlatformRoute(
        "GET",
        f"{_PGL}/holds",
        P.SECURITY_RETENTION_HOLD_MANAGE,
        "permission_grant_ledger.hold_read",
    ),
    PlatformRoute(
        "POST",
        f"{_PGL}/holds",
        P.SECURITY_RETENTION_HOLD_MANAGE,
        "permission_grant_ledger.hold_place",
    ),
    PlatformRoute(
        "POST",
        f"{_PGL}/holds/{{hold_id}}/release",
        P.SECURITY_RETENTION_HOLD_MANAGE,
        "permission_grant_ledger.hold_release",
        True,
    ),
    PlatformRoute(
        "POST",
        f"{_PGL}/deletion-requests",
        P.SECURITY_RETENTION_REPORT,
        "permission_grant_ledger.deletion_request",
    ),
    PlatformRoute(
        "GET",
        f"{_PGL}/deletion-requests",
        P.SECURITY_RETENTION_REPORT,
        "permission_grant_ledger.deletion_read",
    ),
    PlatformRoute(
        "GET",
        f"{_PGL}/deletion-requests/{{request_id}}",
        P.SECURITY_RETENTION_REPORT,
        "permission_grant_ledger.deletion_read",
    ),
    PlatformRoute(
        "POST",
        f"{_PGL}/deletion-requests/{{request_id}}/approve",
        P.SECURITY_RETENTION_REPORT,
        "permission_grant_ledger.deletion_approve",
        True,
    ),
    PlatformRoute(
        "POST",
        f"{_PGL}/deletion-requests/{{request_id}}/execution-authorizations",
        P.SECURITY_RETENTION_REPORT,
        "permission_grant_ledger.deletion_execution_authorize",
        True,
    ),
    PlatformRoute(
        "GET",
        f"{_REG}",
        P.AUDIT_READ,
        "permission_grant_ledger.approver_register_read",
    ),
    PlatformRoute(
        "GET",
        f"{_REG}/eligibility",
        P.AUDIT_READ,
        "permission_grant_ledger.approver_eligibility_read",
    ),
    PlatformRoute(
        "POST",
        f"{_REG}/representatives/{{user_id}}/proposals",
        P.AUTHORITY_MANAGE,
        "permission_grant_ledger.representative_propose",
        True,
    ),
    PlatformRoute(
        "POST",
        f"{_REG}/representatives/{{user_id}}/proposals/{{entry_id}}/confirm",
        P.SECURITY_RETENTION_HOLD_MANAGE,
        "permission_grant_ledger.representative_confirm",
        True,
    ),
    PlatformRoute(
        "POST",
        f"{_REG}/representatives/{{user_id}}/designations/{{entry_id}}/revoke",
        P.AUTHORITY_MANAGE,
        "permission_grant_ledger.representative_revoke_by_owner",
        True,
    ),
    PlatformRoute(
        "POST",
        f"{_REG}/representatives/{{user_id}}/designations/{{entry_id}}/security-revoke",
        P.SECURITY_RETENTION_HOLD_MANAGE,
        "permission_grant_ledger.representative_revoke_by_security",
        True,
    ),
    PlatformRoute(
        "POST",
        f"{_REG}/approvers/{{user_id}}/enrolments",
        P.SECURITY_RETENTION_REPORT,
        "permission_grant_ledger.approver_enrol",
        True,
    ),
    PlatformRoute(
        "POST",
        f"{_REG}/approvers/{{user_id}}/enrolments/{{entry_id}}/revoke",
        P.SECURITY_RETENTION_REPORT,
        "permission_grant_ledger.approver_revoke_by_representative",
        True,
    ),
    PlatformRoute(
        "POST",
        f"{_REG}/approvers/{{user_id}}/enrolments/{{entry_id}}/security-revoke",
        P.SECURITY_RETENTION_HOLD_MANAGE,
        "permission_grant_ledger.approver_revoke_by_security",
        True,
    ),
)


# --- responses ---------------------------------------------------------------------------


class TenantResponse(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    parent_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class TenantPageResponse(BaseModel):
    tenants: list[TenantResponse]
    next_cursor: uuid.UUID | None


class SessionSummaryResponse(BaseModel):
    id: uuid.UUID
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


class UserResponse(BaseModel):
    id: uuid.UUID
    is_active: bool
    created_at: datetime
    is_enrolled_operator: bool
    live_sessions: int
    more_live_sessions: bool
    sessions: list[SessionSummaryResponse]


class OperatorResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    status: str
    enrolled_by_user_id: uuid.UUID | None
    status_changed_at: datetime
    status_changed_by_user_id: uuid.UUID | None
    created_at: datetime


class OperatorPageResponse(BaseModel):
    operators: list[OperatorResponse]
    next_cursor: uuid.UUID | None


class GrantResponse(BaseModel):
    id: uuid.UUID
    operator_id: uuid.UUID
    permission: str
    granted_by_user_id: uuid.UUID | None
    granted_at: datetime
    revoked_at: datetime | None
    revoked_by_user_id: uuid.UUID | None


class GrantPageResponse(BaseModel):
    grants: list[GrantResponse]
    next_cursor: uuid.UUID | None


class AuditEntryResponse(BaseModel):
    id: uuid.UUID
    created_at: datetime
    actor_type: str
    actor_user_id: uuid.UUID | None
    system_authority: str | None
    action: str
    target_type: str
    target_id: str | None
    target_tenant_id: uuid.UUID | None
    outcome: str
    reason: str | None
    correlation_id: str | None
    metadata: dict[str, Any] | None


class AuditPageResponse(BaseModel):
    entries: list[AuditEntryResponse]
    next_cursor: uuid.UUID | None


class SubscriptionResponse(BaseModel):
    status: str
    plan_key: str
    payer_tenant_id: uuid.UUID | None
    updated_at: datetime


class TenantCommercialResponse(BaseModel):
    tenant_id: uuid.UUID
    subscriptions: list[SubscriptionResponse]


class CommercialOverviewResponse(BaseModel):
    tenants: list[TenantCommercialResponse]
    next_cursor: uuid.UUID | None


class FlagResponse(BaseModel):
    key: str
    enabled_by_default: bool


class FlagPageResponse(BaseModel):
    flags: list[FlagResponse]
    next_cursor: str | None


class OverrideResponse(BaseModel):
    key: str
    enabled: bool


class OverridePageResponse(BaseModel):
    tenant_id: uuid.UUID
    overrides: list[OverrideResponse]
    next_cursor: str | None


class UserCredentialsResponse(BaseModel):
    """Counts only: never a session id, a key id or a tenant id."""

    user_id: uuid.UUID
    sessions_revoked: int
    api_keys_revoked: int


class RevokedCountResponse(BaseModel):
    user_id: uuid.UUID
    revoked: int


# --- requests ----------------------------------------------------------------------------


class ResolveUserRequest(BaseModel):
    """In the body, not the path or the query: an external subject does
    not belong in an access log."""

    issuer: Annotated[str, Field(min_length=1, max_length=2048, pattern=_PRINTABLE)]
    subject: Annotated[str, Field(min_length=1, max_length=255, pattern=_PRINTABLE)]


class CreateTenantRequest(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=255, pattern=_PRINTABLE)]
    parent_id: uuid.UUID | None = None


class ReasonRequest(BaseModel):
    reason: Reason


class OptionalReasonRequest(BaseModel):
    reason: OptionalReason = None


class DefineFlagRequest(BaseModel):
    key: Annotated[str, Field(min_length=1, max_length=150, pattern=_PRINTABLE)]
    enabled_by_default: bool = False


class SetOverrideRequest(BaseModel):
    enabled: bool
    reason: OptionalReason = None


class EnrollOperatorRequest(BaseModel):
    user_id: uuid.UUID
    reason: Reason


class GrantRequest(BaseModel):
    permission: PlatformPermission
    reason: Reason


# --- permission grant ledger retention: requests and responses -------------------------
#
# Every request model forbids extra fields and has no identity field
# (`tests/architecture/test_retention_api_boundary.py`): the caller is the
# session's user, and a register write names its subject in the path.

_OPAQUE_REFERENCE = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$"
Reference = Annotated[str, Field(min_length=1, max_length=100, pattern=_OPAQUE_REFERENCE)]
Digest = Annotated[str, Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")]
TenantScope = Annotated[list[uuid.UUID], Field(min_length=1, max_length=1000)]


class _RetentionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RetentionReportRequest(_RetentionRequest):
    tenant_ids: Annotated[list[uuid.UUID], Field(max_length=1000)] = []
    all_purged: bool = False
    after: uuid.UUID | None = None
    limit: Annotated[int, Field(ge=1, le=1000)] = 1000
    reason: Reason


class RetentionReasonRequest(_RetentionRequest):
    reason: Reason


class PlaceHoldRequest(_RetentionRequest):
    tenant_id: uuid.UUID
    reference: Reference
    reason: Reason


class DeletionRequestBody(_RetentionRequest):
    tenant_ids: TenantScope
    eligible_ledger_rows: Annotated[int, Field(ge=1)]
    eligible_digest: Digest
    reason: Reason


class ApproveDeletionRequest(_RetentionRequest):
    eligible_ledger_rows: Annotated[int, Field(ge=1)]
    eligible_digest: Digest
    reason: Reason


class ProposeRepresentativeRequest(_RetentionRequest):
    designation_ref: Reference
    ticket_ref: Reference
    valid_until: AwareDatetime
    reason: Reason


class TicketReasonRequest(_RetentionRequest):
    ticket_ref: Reference
    reason: Reason


class EnrolApproverRequest(_RetentionRequest):
    natural_person_ref: Reference
    verification_ref: Reference
    authorisation_ref: Reference
    ticket_ref: Reference
    valid_until: AwareDatetime
    renews_entry_id: uuid.UUID | None = None
    reason: Reason


RETENTION_REQUEST_MODELS: tuple[type[BaseModel], ...] = (
    RetentionReportRequest,
    RetentionReasonRequest,
    PlaceHoldRequest,
    DeletionRequestBody,
    ApproveDeletionRequest,
    ProposeRepresentativeRequest,
    TicketReasonRequest,
    EnrolApproverRequest,
)


class TenantRetentionResponse(BaseModel):
    tenant_id: uuid.UUID
    status: str
    ledger_rows: int
    active_holds: int
    purged_at: datetime | None
    expires_at: datetime | None


class RetentionReportResponse(BaseModel):
    as_of: datetime
    more: bool
    eligible_ledger_rows: int
    eligible_digest: str
    tenants: list[TenantRetentionResponse]


class HoldResponse(BaseModel):
    hold_id: uuid.UUID
    tenant_id: uuid.UUID
    reference: str
    placed_at: datetime
    released_at: datetime | None
    platform_audit_id: uuid.UUID
    replay: bool


class HoldSummaryResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    reference: str
    placed_at: datetime
    released_at: datetime | None
    release_authenticated: bool | None


class HoldPageResponse(BaseModel):
    holds: list[HoldSummaryResponse]
    next_cursor: uuid.UUID | None


class DeletionApprovalResponse(BaseModel):
    id: uuid.UUID
    approved_by_user_id: uuid.UUID
    approved_at: datetime
    expires_at: datetime
    consumed_at: datetime | None
    invalidated_at: datetime | None


class DeletionRequestResponse(BaseModel):
    id: uuid.UUID
    tenant_ids: list[uuid.UUID]
    scope_digest: str
    eligible_ledger_rows: int
    eligible_digest: str
    requested_by_user_id: uuid.UUID
    requested_at: datetime
    request_expires_at: datetime
    state: str
    approval: DeletionApprovalResponse | None
    replay: bool


class DeletionRequestPageResponse(BaseModel):
    requests: list[DeletionRequestResponse]
    next_cursor: uuid.UUID | None


class ExecutionAuthorizationResponse(BaseModel):
    id: uuid.UUID
    approval_id: uuid.UUID
    request_id: uuid.UUID
    authorized_by_user_id: uuid.UUID
    authorized_at: datetime
    expires_at: datetime
    eligible_ledger_rows: int
    eligible_digest: str
    scope_digest: str
    replay: bool


class RegisterEntryResponse(BaseModel):
    id: uuid.UUID
    entry_type: str
    subject_user_id: uuid.UUID
    recorded_by_user_id: uuid.UUID
    designation_ref: str | None
    natural_person_ref: str | None
    verification_ref: str | None
    authorisation_ref: str | None
    ticket_ref: str
    proposal_entry_id: uuid.UUID | None
    authorised_by_entry_id: uuid.UUID | None
    revokes_entry_id: uuid.UUID | None
    renews_entry_id: uuid.UUID | None
    valid_until: datetime | None
    eligible_from: datetime | None
    proposal_expires_at: datetime | None
    recorded_at: datetime
    recorded_by_platform_audit_id: uuid.UUID
    replay: bool


class RegisterPageResponse(BaseModel):
    entries: list[RegisterEntryResponse]
    next_cursor: uuid.UUID | None


class RevocationResponse(BaseModel):
    entry: RegisterEntryResponse
    suspended_enrolments: int
    invalidated_approvals: int
    invalidated_execution_authorizations: int


class ApproverEligibilityResponse(BaseModel):
    entry_id: uuid.UUID
    subject_user_id: uuid.UUID
    natural_person_ref: str
    state: str
    eligible_from: datetime
    valid_until: datetime
    authorised_by_entry_id: uuid.UUID


class ApproverEligibilityPageResponse(BaseModel):
    as_of: datetime
    approvers: list[ApproverEligibilityResponse]
    next_cursor: uuid.UUID | None


# --- permission grant ledger retention: error codes -------------------------------------

# Every retention refusal code and the one status it maps to (design section
# 3.4). A code missing here stays a 500 (`_retention_response`).
_RETENTION_NOT_FOUND: dict[str, str] = {
    "request_not_found": "deletion request",
    "register_entry_not_found": "register entry",
    "subject_not_found": "user",
    "execution_authorization_not_found": "execution authorization",
}
RETENTION_STATUS: dict[str, int] = {
    "invalid_request": 400,
    "tenant_not_found": 404,
    "hold_not_found": 404,
    **dict.fromkeys(_RETENTION_NOT_FOUND, 404),
    "hold_already_active": 409,
    "hold_already_released": 409,
    "confirmation_mismatch": 409,
    **dict.fromkeys(sorted(APPROVAL_REFUSAL_CODES), 409),
}
if set(_RETENTION_NOT_FOUND) != set(APPROVAL_NOT_FOUND_CODES):  # pragma: no cover
    raise RuntimeError("the retention not-found codes and their resources differ")


def _retention_response(error: Exception) -> HTTPException | None:
    """The response for a permission grant ledger retention refusal, by its
    code; `None` (a 500) for a code the table does not name."""
    code = getattr(error, "code", None)
    status = RETENTION_STATUS.get(code) if isinstance(code, str) else None
    if status is None:
        return None
    if isinstance(error, InvalidLedgerRetentionRequestError):
        return invalid_request(str(error))
    if isinstance(error, LedgerHoldTenantNotFoundError):
        return not_found("tenant")
    if isinstance(error, LedgerHoldNotFoundError):
        return not_found("hold")
    if isinstance(error, LedgerApprovalRecordNotFoundError):
        return not_found(_RETENTION_NOT_FOUND[error.code])
    if isinstance(
        error,
        LedgerApprovalRefusedError
        | LedgerHoldAlreadyActiveError
        | LedgerHoldAlreadyReleasedError
        | LedgerExpiryConfirmationMismatchError,
    ):
        return conflict(error.code)
    return None  # pragma: no cover -- every code above has its type


# --- Core errors, translated --------------------------------------------------------------

_NOT_FOUND: tuple[tuple[type[Exception], str], ...] = (
    (TenantNotFoundError, "tenant"),
    (PlatformSubjectNotFoundError, "user"),
    (UserNotResolvedError, "user"),
    (PlatformOperatorNotFoundError, "operator"),
    (PlatformGrantNotFoundError, "grant"),
    (FeatureFlagNotFoundError, "feature flag"),
)
# The request is well-formed and authorized, and the resource is not in a
# state that allows it. Each has one fixed, literal reason.
_CONFLICTS: tuple[tuple[type[Exception], str], ...] = (
    (InvalidTenantTransitionError, "invalid_tenant_transition"),
    (TenantClosedError, "tenant_closed"),
    (TenantHierarchyDepthExceededError, "hierarchy_depth_exceeded"),
    (InvalidUserStateError, "invalid_user_state"),
    (LastTenantAdministratorError, "last_tenant_administrator"),
    (PlatformOperatorAlreadyEnrolledError, "operator_already_enrolled"),
    (InvalidPlatformOperatorStateError, "invalid_operator_state"),
    (InactivePlatformSubjectError, "inactive_user"),
    (DuplicatePlatformGrantError, "grant_already_exists"),
    (DuplicateFeatureFlagKeyError, "feature_flag_already_exists"),
)


def _translated(error: Exception) -> HTTPException | None:
    """The response for an error a Core function raised, or `None` for one
    this module does not know (which stays a 500, with no detail)."""
    if isinstance(error, PlatformNotAuthorizedError):
        return forbidden()
    if isinstance(error, PlatformRefusalError):
        # Refused by an invariant or a rule (last owner, self-target,
        # amplification, the parent rule): the fixed code Core recorded.
        return conflict(error.code)
    if isinstance(error, InvalidPlatformRequestError):
        return invalid_request(str(error))
    if isinstance(error, InvalidFeatureFlagKeyError):
        return invalid_request("Invalid feature flag key.")
    if isinstance(
        error,
        InvalidLedgerRetentionRequestError
        | LedgerHoldTenantNotFoundError
        | LedgerHoldNotFoundError
        | LedgerApprovalRecordNotFoundError
        | LedgerApprovalRefusedError
        | LedgerHoldAlreadyActiveError
        | LedgerHoldAlreadyReleasedError
        | LedgerExpiryConfirmationMismatchError,
    ):
        return _retention_response(error)
    if isinstance(
        error,
        OversightReadTimeoutError | PlatformOperationTimeoutError | DeactivationRetryError,
    ):
        return service_unavailable(_RETRY_AFTER_SECONDS)
    if is_transaction_conflict(error):
        # PostgreSQL aborted this transaction to resolve a deadlock or a
        # serialization failure (ADR-0045, residual cases 5 and 7): nothing
        # was changed, and the request can be repeated.
        return service_unavailable(_RETRY_AFTER_SECONDS)
    for kind, resource in _NOT_FOUND:
        if isinstance(error, kind):
            return not_found(resource)
    for kind, reason in _CONFLICTS:
        if isinstance(error, kind):
            return conflict(reason)
    return None


@contextmanager
def _translating() -> Iterator[None]:
    try:
        yield
    except HTTPException:
        raise
    except Exception as error:
        response = _translated(error)
        if response is None:
            raise
        raise response from None


def _caller(context: PlatformRequestContext) -> UserCaller:
    """The verified request actor as a Core caller. Always the session's
    own user -- never an identifier taken from the path or the body."""
    return UserCaller(context.actor_id)


def _evidence(context: PlatformRequestContext) -> PlatformSessionEvidence:
    """The session the chain validated, and whether the deployment requires
    a multi-factor login (ADR-0049): what Core checks for a retention act."""
    return PlatformSessionEvidence(
        session_id=context.session_id,
        multi_factor_required=get_platform_admin_http_config().require_multi_factor,
    )


def _page_arguments(cursor: Any, limit: int | None) -> dict[str, Any]:
    arguments: dict[str, Any] = {"cursor": cursor}
    if limit is not None:
        arguments["limit"] = limit
    return arguments


def _user_response(resolution: Any) -> UserResponse:
    return UserResponse(
        id=resolution.id,
        is_active=resolution.is_active,
        created_at=resolution.created_at,
        is_enrolled_operator=resolution.is_enrolled_operator,
        live_sessions=resolution.live_sessions,
        more_live_sessions=resolution.more_live_sessions,
        sessions=[
            SessionSummaryResponse(
                id=session.id,
                created_at=session.created_at,
                expires_at=session.expires_at,
                revoked_at=session.revoked_at,
            )
            for session in resolution.sessions
        ],
    )


def _tenant_response(tenant: Any) -> TenantResponse:
    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        status=tenant.status,
        parent_id=tenant.parent_id,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


def _operator_response(operator: Any) -> OperatorResponse:
    return OperatorResponse(
        id=operator.id,
        user_id=operator.user_id,
        status=operator.status,
        enrolled_by_user_id=operator.enrolled_by_user_id,
        status_changed_at=operator.status_changed_at,
        status_changed_by_user_id=operator.status_changed_by_user_id,
        created_at=operator.created_at,
    )


def _grant_response(grant: Any) -> GrantResponse:
    return GrantResponse(
        id=grant.id,
        operator_id=grant.operator_id,
        permission=grant.permission,
        granted_by_user_id=grant.granted_by_user_id,
        granted_at=grant.granted_at,
        revoked_at=grant.revoked_at,
        revoked_by_user_id=grant.revoked_by_user_id,
    )


# --- the router --------------------------------------------------------------------------


def build_router() -> APIRouter:
    """A new router carrying every route of `PLATFORM_ROUTES`. Each call
    builds its own dependency objects."""
    router = APIRouter(prefix=PREFIX, tags=["platform-admin"])
    gates = {
        (route.method, route.path): Depends(
            require_platform_permission(
                route.permission, operation=route.operation, fresh_session=route.fresh_session
            )
        )
        for route in PLATFORM_ROUTES
    }

    def gate(method: str, path: str) -> Any:
        return gates.pop((method, path))  # each declared route is built exactly once

    # --- oversight -----------------------------------------------------------------

    @router.get("/tenants", response_model=TenantPageResponse)
    def list_tenants(
        cursor: uuid.UUID | None = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", "/tenants"),
    ) -> TenantPageResponse:
        with _translating():
            page = list_tenant_registry(caller=_caller(context), **_page_arguments(cursor, limit))
        return TenantPageResponse(
            tenants=[_tenant_response(tenant) for tenant in page.tenants],
            next_cursor=page.next_cursor,
        )

    @router.get("/tenants/{tenant_id}", response_model=TenantResponse)
    def read_tenant(
        tenant_id: uuid.UUID,
        context: PlatformRequestContext = gate("GET", "/tenants/{tenant_id}"),
    ) -> TenantResponse:
        with _translating():
            return _tenant_response(read_tenant_registry_entry(tenant_id, caller=_caller(context)))

    @router.get("/users/{user_id}", response_model=UserResponse)
    def read_user(
        user_id: uuid.UUID,
        context: PlatformRequestContext = gate("GET", "/users/{user_id}"),
    ) -> UserResponse:
        with _translating():
            return _user_response(resolve_user(caller=_caller(context), user_id=user_id))

    @router.post("/users/resolve", response_model=UserResponse)
    def resolve_user_by_identity(
        body: ResolveUserRequest,
        context: PlatformRequestContext = gate("POST", "/users/resolve"),
    ) -> UserResponse:
        with _translating():
            return _user_response(
                resolve_user(caller=_caller(context), issuer=body.issuer, subject=body.subject)
            )

    @router.get("/operators", response_model=OperatorPageResponse)
    def list_operators(
        cursor: uuid.UUID | None = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", "/operators"),
    ) -> OperatorPageResponse:
        with _translating():
            page = list_platform_operators(
                caller=_caller(context), **_page_arguments(cursor, limit)
            )
        return OperatorPageResponse(
            operators=[_operator_response(operator) for operator in page.operators],
            next_cursor=page.next_cursor,
        )

    @router.get("/grants", response_model=GrantPageResponse)
    def list_grants(
        operator_id: uuid.UUID | None = None,
        cursor: uuid.UUID | None = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", "/grants"),
    ) -> GrantPageResponse:
        with _translating():
            page = list_platform_grants(
                caller=_caller(context), operator_id=operator_id, **_page_arguments(cursor, limit)
            )
        return GrantPageResponse(
            grants=[_grant_response(grant) for grant in page.grants], next_cursor=page.next_cursor
        )

    @router.get("/audit", response_model=AuditPageResponse)
    def list_audit(
        since: datetime | None = None,
        until: datetime | None = None,
        actor_user_id: uuid.UUID | None = None,
        action: Annotated[str | None, Query(max_length=200, pattern=_PRINTABLE)] = None,
        target_tenant_id: uuid.UUID | None = None,
        cursor: uuid.UUID | None = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", "/audit"),
    ) -> AuditPageResponse:
        with _translating():
            page = list_platform_audit(
                caller=_caller(context),
                since=since,
                until=until,
                actor_user_id=actor_user_id,
                action=action,
                target_tenant_id=target_tenant_id,
                **_page_arguments(cursor, limit),
            )
        return AuditPageResponse(
            entries=[
                AuditEntryResponse(
                    id=entry.id,
                    created_at=entry.created_at,
                    actor_type=entry.actor_type,
                    actor_user_id=entry.actor_user_id,
                    system_authority=entry.system_authority,
                    action=entry.action,
                    target_type=entry.target_type,
                    target_id=entry.target_id,
                    target_tenant_id=entry.target_tenant_id,
                    outcome=entry.outcome,
                    reason=entry.reason,
                    correlation_id=entry.correlation_id,
                    metadata=entry.metadata,
                )
                for entry in page.entries
            ],
            next_cursor=page.next_cursor,
        )

    @router.get("/billing/overview", response_model=CommercialOverviewResponse)
    def billing_overview(
        cursor: uuid.UUID | None = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", "/billing/overview"),
    ) -> CommercialOverviewResponse:
        with _translating():
            page = commercial_overview(caller=_caller(context), **_page_arguments(cursor, limit))
        return CommercialOverviewResponse(
            tenants=[
                TenantCommercialResponse(
                    tenant_id=tenant.tenant_id,
                    subscriptions=[
                        SubscriptionResponse(
                            status=subscription.status,
                            plan_key=subscription.plan_key,
                            payer_tenant_id=subscription.payer_tenant_id,
                            updated_at=subscription.updated_at,
                        )
                        for subscription in tenant.subscriptions
                    ],
                )
                for tenant in page.tenants
            ],
            next_cursor=page.next_cursor,
        )

    @router.get("/feature-flags", response_model=FlagPageResponse)
    def list_flags(
        cursor: Annotated[str | None, Query(max_length=150, pattern=_PRINTABLE)] = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", "/feature-flags"),
    ) -> FlagPageResponse:
        with _translating():
            page = read_flag_catalog(caller=_caller(context), **_page_arguments(cursor, limit))
        return FlagPageResponse(
            flags=[
                FlagResponse(key=flag.key, enabled_by_default=flag.enabled_by_default)
                for flag in page.flags
            ],
            next_cursor=page.next_cursor,
        )

    @router.get("/tenants/{tenant_id}/feature-flags", response_model=OverridePageResponse)
    def list_overrides(
        tenant_id: uuid.UUID,
        cursor: Annotated[str | None, Query(max_length=150, pattern=_PRINTABLE)] = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", "/tenants/{tenant_id}/feature-flags"),
    ) -> OverridePageResponse:
        with _translating():
            page = read_tenant_flag_overrides(
                tenant_id, caller=_caller(context), **_page_arguments(cursor, limit)
            )
        return OverridePageResponse(
            tenant_id=page.tenant_id,
            overrides=[
                OverrideResponse(key=override.key, enabled=override.enabled)
                for override in page.overrides
            ],
            next_cursor=page.next_cursor,
        )

    # --- tenant lifecycle ----------------------------------------------------------

    @router.post("/tenants", response_model=TenantResponse, status_code=201)
    def create(
        body: CreateTenantRequest,
        context: PlatformRequestContext = gate("POST", "/tenants"),
    ) -> TenantResponse:
        with _translating():
            tenant = create_tenant(body.name, parent_id=body.parent_id, caller=_caller(context))
        return _tenant_response(tenant)

    def _transition(
        tenant_id: uuid.UUID,
        target: TenantStatus,
        operation: str,
        context: PlatformRequestContext,
        reason: Any,
    ) -> TenantResponse:
        # `expected_operation`: the route performs the operation its
        # permission gates and no other. A tenant whose status selects a
        # different one is a 409, whatever else the operator holds.
        with _translating():
            tenant = transition_tenant_status(
                tenant_id,
                target,
                caller=_caller(context),
                reason=reason,
                expected_operation=operation,
            )
        return _tenant_response(tenant)

    @router.post("/tenants/{tenant_id}/activate", response_model=TenantResponse)
    def activate(
        tenant_id: uuid.UUID,
        body: OptionalReasonRequest,
        context: PlatformRequestContext = gate("POST", "/tenants/{tenant_id}/activate"),
    ) -> TenantResponse:
        # A suspended tenant is a reactivation, which this route does not
        # perform: Core answers with an invalid transition.
        return _transition(tenant_id, TenantStatus.ACTIVE, "tenant.activate", context, body.reason)

    @router.post("/tenants/{tenant_id}/suspend", response_model=TenantResponse)
    def suspend(
        tenant_id: uuid.UUID,
        body: ReasonRequest,
        context: PlatformRequestContext = gate("POST", "/tenants/{tenant_id}/suspend"),
    ) -> TenantResponse:
        return _transition(
            tenant_id, TenantStatus.SUSPENDED, "tenant.suspend", context, body.reason
        )

    @router.post("/tenants/{tenant_id}/reactivate", response_model=TenantResponse)
    def reactivate(
        tenant_id: uuid.UUID,
        body: ReasonRequest,
        context: PlatformRequestContext = gate("POST", "/tenants/{tenant_id}/reactivate"),
    ) -> TenantResponse:
        return _transition(
            tenant_id, TenantStatus.ACTIVE, "tenant.reactivate", context, body.reason
        )

    # --- users and credentials ---------------------------------------------------------

    def _credentials(
        operation: Callable[..., Any], user_id: uuid.UUID, context: Any, reason: str
    ) -> UserCredentialsResponse:
        with _translating():
            result = operation(user_id, caller=_caller(context), reason=reason)
        return UserCredentialsResponse(
            user_id=result.user_id,
            sessions_revoked=result.sessions_revoked,
            api_keys_revoked=result.api_keys_revoked,
        )

    @router.post("/users/{user_id}/deactivate", response_model=UserCredentialsResponse)
    def deactivate(
        user_id: uuid.UUID,
        body: ReasonRequest,
        context: PlatformRequestContext = gate("POST", "/users/{user_id}/deactivate"),
    ) -> UserCredentialsResponse:
        return _credentials(deactivate_user, user_id, context, body.reason)

    @router.post("/users/{user_id}/reactivate", response_model=UserCredentialsResponse)
    def reactivate_a_user(
        user_id: uuid.UUID,
        body: ReasonRequest,
        context: PlatformRequestContext = gate("POST", "/users/{user_id}/reactivate"),
    ) -> UserCredentialsResponse:
        return _credentials(reactivate_user, user_id, context, body.reason)

    @router.post("/users/{user_id}/sessions/revoke", response_model=RevokedCountResponse)
    def revoke_sessions(
        user_id: uuid.UUID,
        body: ReasonRequest,
        context: PlatformRequestContext = gate("POST", "/users/{user_id}/sessions/revoke"),
    ) -> RevokedCountResponse:
        with _translating():
            revoked = revoke_user_sessions(user_id, caller=_caller(context), reason=body.reason)
        return RevokedCountResponse(user_id=user_id, revoked=revoked)

    @router.post("/users/{user_id}/api-keys/revoke", response_model=RevokedCountResponse)
    def revoke_api_keys(
        user_id: uuid.UUID,
        body: ReasonRequest,
        context: PlatformRequestContext = gate("POST", "/users/{user_id}/api-keys/revoke"),
    ) -> RevokedCountResponse:
        with _translating():
            revoked = revoke_user_api_keys(user_id, caller=_caller(context), reason=body.reason)
        return RevokedCountResponse(user_id=user_id, revoked=revoked)

    # --- feature flags -------------------------------------------------------------------

    @router.post("/feature-flags", response_model=FlagResponse, status_code=201)
    def define_flag(
        body: DefineFlagRequest,
        context: PlatformRequestContext = gate("POST", "/feature-flags"),
    ) -> FlagResponse:
        with _translating():
            flag = create_flag(
                body.key, enabled_by_default=body.enabled_by_default, caller=_caller(context)
            )
        return FlagResponse(key=flag.key, enabled_by_default=flag.enabled_by_default)

    @router.put("/tenants/{tenant_id}/feature-flags/{key}", response_model=OverrideResponse)
    def set_override(
        tenant_id: uuid.UUID,
        key: Annotated[str, Path(min_length=1, max_length=150, pattern=_PRINTABLE)],
        body: SetOverrideRequest,
        context: PlatformRequestContext = gate("PUT", "/tenants/{tenant_id}/feature-flags/{key}"),
    ) -> OverrideResponse:
        with _translating():
            override = set_tenant_override(
                tenant_id, key, body.enabled, caller=_caller(context), reason=body.reason
            )
        return OverrideResponse(key=key, enabled=override.enabled)

    @router.delete("/tenants/{tenant_id}/feature-flags/{key}", status_code=204)
    def remove_override(
        tenant_id: uuid.UUID,
        key: Annotated[str, Path(min_length=1, max_length=150, pattern=_PRINTABLE)],
        reason: Annotated[str | None, Query(max_length=500, pattern=_PRINTABLE)] = None,
        context: PlatformRequestContext = gate(
            "DELETE", "/tenants/{tenant_id}/feature-flags/{key}"
        ),
    ) -> None:
        with _translating():
            remove_tenant_override(tenant_id, key, caller=_caller(context), reason=reason)

    # --- platform authority (fresh session) --------------------------------------------

    @router.post("/operators", response_model=OperatorResponse, status_code=201)
    def enroll(
        body: EnrollOperatorRequest,
        context: PlatformRequestContext = gate("POST", "/operators"),
    ) -> OperatorResponse:
        with _translating():
            operator = enroll_operator(body.user_id, caller=_caller(context), reason=body.reason)
        return _operator_response(operator)

    def _operator_change(
        change: Callable[..., Any], operator_id: uuid.UUID, context: Any, reason: str
    ) -> OperatorResponse:
        with _translating():
            return _operator_response(change(operator_id, caller=_caller(context), reason=reason))

    @router.post("/operators/{operator_id}/suspend", response_model=OperatorResponse)
    def suspend_an_operator(
        operator_id: uuid.UUID,
        body: ReasonRequest,
        context: PlatformRequestContext = gate("POST", "/operators/{operator_id}/suspend"),
    ) -> OperatorResponse:
        return _operator_change(suspend_operator, operator_id, context, body.reason)

    @router.post("/operators/{operator_id}/reactivate", response_model=OperatorResponse)
    def reactivate_an_operator(
        operator_id: uuid.UUID,
        body: ReasonRequest,
        context: PlatformRequestContext = gate("POST", "/operators/{operator_id}/reactivate"),
    ) -> OperatorResponse:
        return _operator_change(reactivate_operator, operator_id, context, body.reason)

    @router.post("/operators/{operator_id}/revoke", response_model=OperatorResponse)
    def revoke_an_operator(
        operator_id: uuid.UUID,
        body: ReasonRequest,
        context: PlatformRequestContext = gate("POST", "/operators/{operator_id}/revoke"),
    ) -> OperatorResponse:
        return _operator_change(revoke_operator, operator_id, context, body.reason)

    @router.post("/operators/{operator_id}/grants", response_model=GrantResponse, status_code=201)
    def grant(
        operator_id: uuid.UUID,
        body: GrantRequest,
        context: PlatformRequestContext = gate("POST", "/operators/{operator_id}/grants"),
    ) -> GrantResponse:
        with _translating():
            created = grant_platform_permission(
                operator_id, body.permission, caller=_caller(context), reason=body.reason
            )
        return _grant_response(created)

    @router.post("/operators/{operator_id}/grants/revoke", response_model=GrantResponse)
    def revoke_grant(
        operator_id: uuid.UUID,
        body: GrantRequest,
        context: PlatformRequestContext = gate("POST", "/operators/{operator_id}/grants/revoke"),
    ) -> GrantResponse:
        with _translating():
            revoked = revoke_platform_permission(
                operator_id, body.permission, caller=_caller(context), reason=body.reason
            )
        return _grant_response(revoked)

    # --- permission grant ledger retention (owner decisions of 2026-11-03) ---------------

    @router.post(f"{_PGL}/retention-report", response_model=RetentionReportResponse)
    def retention_report(
        body: RetentionReportRequest,
        context: PlatformRequestContext = gate("POST", f"{_PGL}/retention-report"),
    ) -> RetentionReportResponse:
        with _translating():
            report = permission_grant_ledger_retention_report(
                caller=_caller(context),
                reason=body.reason,
                tenant_ids=body.tenant_ids,
                all_purged=body.all_purged,
                after=body.after,
                limit=body.limit,
            )
        return RetentionReportResponse(
            as_of=report.as_of,
            more=report.more,
            eligible_ledger_rows=report.eligible_ledger_rows,
            eligible_digest=report.eligible_digest,
            tenants=[
                TenantRetentionResponse(
                    tenant_id=t.tenant_id,
                    status=t.status.value,
                    ledger_rows=t.ledger_rows,
                    active_holds=t.active_holds,
                    purged_at=t.purged_at,
                    expires_at=t.expires_at,
                )
                for t in report.tenants
            ],
        )

    def _hold_response(result: Any) -> HoldResponse:
        return HoldResponse(
            hold_id=result.hold_id,
            tenant_id=result.tenant_id,
            reference=result.reference,
            placed_at=result.placed_at,
            released_at=result.released_at,
            platform_audit_id=result.platform_audit_id,
            replay=result.replay,
        )

    @router.get(f"{_PGL}/holds", response_model=HoldPageResponse)
    def list_holds(
        tenant_id: uuid.UUID | None = None,
        active: bool | None = None,
        cursor: uuid.UUID | None = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", f"{_PGL}/holds"),
    ) -> HoldPageResponse:
        with _translating():
            page = list_permission_grant_ledger_holds(
                caller=_caller(context),
                tenant_id=tenant_id,
                active=active,
                **_page_arguments(cursor, limit),
            )
        return HoldPageResponse(
            holds=[
                HoldSummaryResponse(
                    id=h.id,
                    tenant_id=h.tenant_id,
                    reference=h.reference,
                    placed_at=h.placed_at,
                    released_at=h.released_at,
                    release_authenticated=h.release_authenticated,
                )
                for h in page.holds
            ],
            next_cursor=page.next_cursor,
        )

    @router.post(f"{_PGL}/holds", response_model=HoldResponse, status_code=201)
    def place_hold(
        body: PlaceHoldRequest,
        context: PlatformRequestContext = gate("POST", f"{_PGL}/holds"),
    ) -> HoldResponse:
        with _translating():
            result = place_permission_grant_ledger_hold(
                body.tenant_id,
                reference=body.reference,
                caller=_caller(context),
                reason=body.reason,
                session_evidence=_evidence(context),
            )
        return _hold_response(result)

    @router.post(f"{_PGL}/holds/{{hold_id}}/release", response_model=HoldResponse)
    def release_hold(
        hold_id: uuid.UUID,
        body: RetentionReasonRequest,
        context: PlatformRequestContext = gate("POST", f"{_PGL}/holds/{{hold_id}}/release"),
    ) -> HoldResponse:
        with _translating():
            result = release_permission_grant_ledger_hold(
                hold_id,
                caller=_caller(context),
                reason=body.reason,
                session_evidence=_evidence(context),
            )
        return _hold_response(result)

    def _request_response(view: Any) -> DeletionRequestResponse:
        approval = view.approval
        return DeletionRequestResponse(
            id=view.id,
            tenant_ids=list(view.tenant_ids),
            scope_digest=view.scope_digest,
            eligible_ledger_rows=view.eligible_ledger_rows,
            eligible_digest=view.eligible_digest,
            requested_by_user_id=view.requested_by_user_id,
            requested_at=view.requested_at,
            request_expires_at=view.request_expires_at,
            state=view.state,
            approval=None
            if approval is None
            else DeletionApprovalResponse(
                id=approval.id,
                approved_by_user_id=approval.approved_by_user_id,
                approved_at=approval.approved_at,
                expires_at=approval.expires_at,
                consumed_at=approval.consumed_at,
                invalidated_at=approval.invalidated_at,
            ),
            replay=view.replay,
        )

    @router.post(
        f"{_PGL}/deletion-requests", response_model=DeletionRequestResponse, status_code=201
    )
    def request_deletion(
        body: DeletionRequestBody,
        context: PlatformRequestContext = gate("POST", f"{_PGL}/deletion-requests"),
    ) -> DeletionRequestResponse:
        with _translating():
            view = request_permission_grant_ledger_deletion(
                caller=_caller(context),
                session_evidence=_evidence(context),
                tenant_ids=body.tenant_ids,
                eligible_ledger_rows=body.eligible_ledger_rows,
                eligible_digest=body.eligible_digest,
                reason=body.reason,
            )
        return _request_response(view)

    @router.get(f"{_PGL}/deletion-requests", response_model=DeletionRequestPageResponse)
    def list_deletion_requests(
        cursor: uuid.UUID | None = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", f"{_PGL}/deletion-requests"),
    ) -> DeletionRequestPageResponse:
        with _translating():
            page = read_permission_grant_ledger_deletion_requests(
                caller=_caller(context), **_page_arguments(cursor, limit)
            )
        return DeletionRequestPageResponse(
            requests=[_request_response(view) for view in page.requests],
            next_cursor=page.next_cursor,
        )

    @router.get(f"{_PGL}/deletion-requests/{{request_id}}", response_model=DeletionRequestResponse)
    def read_deletion_request(
        request_id: uuid.UUID,
        context: PlatformRequestContext = gate("GET", f"{_PGL}/deletion-requests/{{request_id}}"),
    ) -> DeletionRequestResponse:
        with _translating():
            page = read_permission_grant_ledger_deletion_requests(
                caller=_caller(context), request_id=request_id
            )
        return _request_response(page.requests[0])

    @router.post(
        f"{_PGL}/deletion-requests/{{request_id}}/approve",
        response_model=DeletionRequestResponse,
        status_code=201,
    )
    def approve_deletion(
        request_id: uuid.UUID,
        body: ApproveDeletionRequest,
        context: PlatformRequestContext = gate(
            "POST", f"{_PGL}/deletion-requests/{{request_id}}/approve"
        ),
    ) -> DeletionRequestResponse:
        with _translating():
            view = approve_permission_grant_ledger_deletion(
                request_id,
                caller=_caller(context),
                session_evidence=_evidence(context),
                eligible_ledger_rows=body.eligible_ledger_rows,
                eligible_digest=body.eligible_digest,
                reason=body.reason,
            )
        return _request_response(view)

    @router.post(
        f"{_PGL}/deletion-requests/{{request_id}}/execution-authorizations",
        response_model=ExecutionAuthorizationResponse,
        status_code=201,
    )
    def authorize_execution(
        request_id: uuid.UUID,
        body: RetentionReasonRequest,
        context: PlatformRequestContext = gate(
            "POST", f"{_PGL}/deletion-requests/{{request_id}}/execution-authorizations"
        ),
    ) -> ExecutionAuthorizationResponse:
        with _translating():
            view = authorize_permission_grant_ledger_deletion_execution(
                request_id,
                caller=_caller(context),
                session_evidence=_evidence(context),
                reason=body.reason,
            )
        return ExecutionAuthorizationResponse(
            id=view.id,
            approval_id=view.approval_id,
            request_id=view.request_id,
            authorized_by_user_id=view.authorized_by_user_id,
            authorized_at=view.authorized_at,
            expires_at=view.expires_at,
            eligible_ledger_rows=view.eligible_ledger_rows,
            eligible_digest=view.eligible_digest,
            scope_digest=view.scope_digest,
            replay=view.replay,
        )

    def _entry_response(view: Any) -> RegisterEntryResponse:
        return RegisterEntryResponse(
            id=view.id,
            entry_type=view.entry_type,
            subject_user_id=view.subject_user_id,
            recorded_by_user_id=view.recorded_by_user_id,
            designation_ref=view.designation_ref,
            natural_person_ref=view.natural_person_ref,
            verification_ref=view.verification_ref,
            authorisation_ref=view.authorisation_ref,
            ticket_ref=view.ticket_ref,
            proposal_entry_id=view.proposal_entry_id,
            authorised_by_entry_id=view.authorised_by_entry_id,
            revokes_entry_id=view.revokes_entry_id,
            renews_entry_id=view.renews_entry_id,
            valid_until=view.valid_until,
            eligible_from=view.eligible_from,
            proposal_expires_at=view.proposal_expires_at,
            recorded_at=view.recorded_at,
            recorded_by_platform_audit_id=view.recorded_by_platform_audit_id,
            replay=view.replay,
        )

    @router.get(f"{_REG}", response_model=RegisterPageResponse)
    def read_register(
        subject_user_id: uuid.UUID | None = None,
        entry_type: Annotated[str | None, Query(max_length=40, pattern=r"^[a-z_]+$")] = None,
        cursor: uuid.UUID | None = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", f"{_REG}"),
    ) -> RegisterPageResponse:
        with _translating():
            page = read_approver_register(
                caller=_caller(context),
                subject_user_id=subject_user_id,
                entry_type=entry_type,
                **_page_arguments(cursor, limit),
            )
        return RegisterPageResponse(
            entries=[_entry_response(view) for view in page.entries],
            next_cursor=page.next_cursor,
        )

    @router.get(f"{_REG}/eligibility", response_model=ApproverEligibilityPageResponse)
    def read_eligibility(
        cursor: uuid.UUID | None = None,
        limit: PageSize = None,
        context: PlatformRequestContext = gate("GET", f"{_REG}/eligibility"),
    ) -> ApproverEligibilityPageResponse:
        with _translating():
            page = read_approver_eligibility(
                caller=_caller(context), **_page_arguments(cursor, limit)
            )
        return ApproverEligibilityPageResponse(
            as_of=page.as_of,
            approvers=[
                ApproverEligibilityResponse(
                    entry_id=a.entry_id,
                    subject_user_id=a.subject_user_id,
                    natural_person_ref=a.natural_person_ref,
                    state=a.state.value,
                    eligible_from=a.eligible_from,
                    valid_until=a.valid_until,
                    authorised_by_entry_id=a.authorised_by_entry_id,
                )
                for a in page.approvers
            ],
            next_cursor=page.next_cursor,
        )

    @router.post(
        f"{_REG}/representatives/{{user_id}}/proposals",
        response_model=RegisterEntryResponse,
        status_code=201,
    )
    def propose_representative(
        user_id: uuid.UUID,
        body: ProposeRepresentativeRequest,
        context: PlatformRequestContext = gate(
            "POST", f"{_REG}/representatives/{{user_id}}/proposals"
        ),
    ) -> RegisterEntryResponse:
        with _translating():
            view = propose_representative_designation(
                user_id,
                caller=_caller(context),
                session_evidence=_evidence(context),
                designation_ref=body.designation_ref,
                ticket_ref=body.ticket_ref,
                valid_until=body.valid_until,
                reason=body.reason,
            )
        return _entry_response(view)

    @router.post(
        f"{_REG}/representatives/{{user_id}}/proposals/{{entry_id}}/confirm",
        response_model=RegisterEntryResponse,
        status_code=201,
    )
    def confirm_representative(
        user_id: uuid.UUID,
        entry_id: uuid.UUID,
        body: TicketReasonRequest,
        context: PlatformRequestContext = gate(
            "POST", f"{_REG}/representatives/{{user_id}}/proposals/{{entry_id}}/confirm"
        ),
    ) -> RegisterEntryResponse:
        with _translating():
            view = confirm_representative_designation(
                user_id,
                entry_id,
                caller=_caller(context),
                session_evidence=_evidence(context),
                ticket_ref=body.ticket_ref,
                reason=body.reason,
            )
        return _entry_response(view)

    @router.post(
        f"{_REG}/approvers/{{user_id}}/enrolments",
        response_model=RegisterEntryResponse,
        status_code=201,
    )
    def enrol(
        user_id: uuid.UUID,
        body: EnrolApproverRequest,
        context: PlatformRequestContext = gate("POST", f"{_REG}/approvers/{{user_id}}/enrolments"),
    ) -> RegisterEntryResponse:
        with _translating():
            view = enrol_approver(
                user_id,
                caller=_caller(context),
                session_evidence=_evidence(context),
                natural_person_ref=body.natural_person_ref,
                verification_ref=body.verification_ref,
                authorisation_ref=body.authorisation_ref,
                ticket_ref=body.ticket_ref,
                valid_until=body.valid_until,
                renews_entry_id=body.renews_entry_id,
                reason=body.reason,
            )
        return _entry_response(view)

    def _revocation(
        operation: str, path: str
    ) -> Callable[[uuid.UUID, uuid.UUID, TicketReasonRequest, PlatformRequestContext], Any]:
        def revoke(
            user_id: uuid.UUID,
            entry_id: uuid.UUID,
            body: TicketReasonRequest,
            context: PlatformRequestContext = gate("POST", path),
        ) -> RevocationResponse:
            with _translating():
                result = revoke_register_entry(
                    user_id,
                    entry_id,
                    operation=operation,
                    caller=_caller(context),
                    session_evidence=_evidence(context),
                    ticket_ref=body.ticket_ref,
                    reason=body.reason,
                )
            return RevocationResponse(
                entry=_entry_response(result.entry),
                suspended_enrolments=result.suspended_enrolments,
                invalidated_approvals=result.invalidated_approvals,
                invalidated_execution_authorizations=result.invalidated_execution_authorizations,
            )

        revoke.__name__ = operation.rpartition(".")[2]
        return revoke

    for operation, path in (
        (
            "permission_grant_ledger.representative_revoke_by_owner",
            f"{_REG}/representatives/{{user_id}}/designations/{{entry_id}}/revoke",
        ),
        (
            "permission_grant_ledger.representative_revoke_by_security",
            f"{_REG}/representatives/{{user_id}}/designations/{{entry_id}}/security-revoke",
        ),
        (
            "permission_grant_ledger.approver_revoke_by_representative",
            f"{_REG}/approvers/{{user_id}}/enrolments/{{entry_id}}/revoke",
        ),
        (
            "permission_grant_ledger.approver_revoke_by_security",
            f"{_REG}/approvers/{{user_id}}/enrolments/{{entry_id}}/security-revoke",
        ),
    ):
        router.post(path, response_model=RevocationResponse, status_code=201)(
            _revocation(operation, path)
        )

    # Every declared route was built, and nothing else was.
    if gates:  # pragma: no cover -- a programming error, caught at import
        raise RuntimeError(f"platform routes declared but not built: {sorted(gates)}")
    return router
