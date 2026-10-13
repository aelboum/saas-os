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
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

from saas_os.api.dependencies import PlatformRequestContext, require_platform_permission
from saas_os.api.errors import (
    conflict,
    forbidden,
    invalid_request,
    not_found,
    service_unavailable,
)
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
from saas_os.core.platform_authority import (
    DuplicatePlatformGrantError,
    InactivePlatformSubjectError,
    InvalidPlatformOperatorStateError,
    InvalidPlatformRequestError,
    OversightReadTimeoutError,
    PlatformGrantNotFoundError,
    PlatformNotAuthorizedError,
    PlatformOperatorAlreadyEnrolledError,
    PlatformOperatorNotFoundError,
    PlatformPermission,
    PlatformRefusalError,
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
    if isinstance(error, OversightReadTimeoutError | DeactivationRetryError):
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

    # Every declared route was built, and nothing else was.
    if gates:  # pragma: no cover -- a programming error, caught at import
        raise RuntimeError(f"platform routes declared but not built: {sorted(gates)}")
    return router
