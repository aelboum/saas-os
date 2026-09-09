"""The enforced ingress middleware chain
(docs/IMPLEMENTATION-ROADMAP.md Phase 8.1's own Objective: "wire
core/identity (auth) and core/rbac (authz) as the enforced middleware
every route passes through").

Four composable FastAPI dependencies, each depending on the previous,
matching this checkpoint's own required chain:

    Authentication (get_current_actor)
        -> Tenant Resolution (get_tenant_context)
        -> Rate Limiting (rate limit check)
        -> RBAC Authorization (require_permission)

`require_permission(resource, action)` is the one dependency a route
handler actually declares (`api/v1/tenant_status.py`) -- it composes all
four steps, so no route can accidentally skip one by only depending on
an earlier step in the chain.

P1.9 adds two more optional steps after RBAC, composed the same way:
`require_entitlement_and_quota(resource, action, entitlement_key=...,
quota_metric=...)` wraps `require_permission()` and adds Entitlement
(`core.billing.require_entitlement()`) -> Quota
(`core.usage.consume_quota()`), matching the fixed order
Authentication -> Tenant Resolution -> RBAC -> Entitlement -> Quota ->
business operation. See that function's own docstring for the full
denial/audit contract.

P1.11 adds `get_idempotency_key()`, a standalone dependency (no ordering
dependency on the others -- see its own docstring for why) that extracts
and validates an optional `Idempotency-Key` request header. The actual
idempotent-execution logic lives in the business operation itself
(`core.usage.service.consume_quota_idempotent()`, `core.billing.service.
subscribe_idempotent()`), never split across a second HTTP dependency.

**Authentication mechanism (Phase 8's own scope)**: session bearer
tokens only (`core.identity.sessions.validate_session()`), per
`docs/IMPLEMENTATION-ROADMAP.md` Phase 8.1's own Dependencies line
("3.2, 3.3" -- `core/identity`, `core/rbac` -- not 4.1 `core/api_keys`).
API-key HTTP authentication is a deliberate Non-Goal of this phase (see
`api/__init__.py`), not an oversight -- a future phase that needs it
extends `get_current_actor()` with a second accepted credential shape,
resolved through the existing `core.api_keys` module, never a new
identity model.

**Tenant resolution (this checkpoint's own Rule 13: "Do not rely on
callers to supply trustworthy actor/tenant identity")**: the `tenant_id`
path parameter is a *claim*, not a trust boundary by itself -- it is
always validated against a real `core.identity.TenantMembership` for the
authenticated actor before being treated as the request's tenant
context. A caller cannot access data for a tenant they do not genuinely
belong to merely by naming it in the URL.

**Non-enumeration**: `get_tenant_context()` returns the identical 404 for
"tenant does not exist" and "tenant exists but the caller is not a
member" (`api/errors.py`'s own docstring) -- an authenticated caller
learns nothing about which tenant IDs are real.

**Audit**: only the RBAC-denial path is audited here
(`core.audit_log`, `action="api.access_denied"`) -- mirrors
`control_plane.orchestration`'s own Phase 7.1 precedent of auditing a
denied invocation. Authentication failures are not audited (no
resolvable, trustworthy `tenant_id` exists yet at that point --
`core/audit_log/models.py`'s own "no tenant-less audit event"
constraint); a 404 tenant-not-found/not-a-member response is not audited
either, for the same reason -- recording an event "within" a tenant the
caller has no genuine relationship to would misrepresent what actually
happened. A successful, routine read is not audited, mirroring
`core/billing`/`core/webhooks`/`core/notifications`'s own established
"routine reads are not privileged mutations" precedent. A rate-limit
*backend* failure (P1.5, below) is likewise not audited -- an
infrastructure outage, not a security-relevant decision about this actor
(`infra/ratelimit/limiter.py`'s own structured-logging call already makes
it operationally visible, correlated with `request_id`; duplicating that
into `core.audit_log` would misrepresent a Redis outage as an audit-worthy
actor decision).

**P1.5: rate-limit backend failure is fail-closed, never fail-open**. If
Redis itself fails (connection refused, timeout, any other
`infra.ratelimit.RateLimitBackendError`), `_enforce_rate_limit_for_route`
raises `api.errors.service_unavailable()` (503) -- never lets the
request fall through to RBAC/the handler unlimited, and never reports
429 for a request that was never actually evaluated against its limit
(`RateLimitBackendError` is a distinct exception from
`RateLimitExceededError` precisely so these two outcomes can never be
conflated). Because this dependency still runs *after* authentication
and tenant resolution in the chain above, a Redis outage can only ever
reject an already-authenticated, already-tenant-scoped request -- it
never bypasses or weakens either of those steps, and RBAC/the handler
below it in the chain never runs when this raises.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

from core.billing.errors import EntitlementDeniedError
from core.billing.service import require_entitlement
from core.idempotency.errors import IdempotencyKeyInvalidError
from core.identity.errors import SessionExpiredError, SessionNotFoundError, SessionRevokedError
from core.identity.models import Session
from core.identity.sessions import validate_session
from core.usage.errors import QuotaExceededError
from core.usage.service import consume_quota
from fastapi import Depends, Header, Request

from api.context import RequestContext
from api.errors import (
    forbidden,
    idempotency_key_invalid,
    not_found,
    quota_exceeded,
    rate_limited,
    service_unavailable,
    unauthorized,
)
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.idempotency import validate_idempotency_key
from core.identity import get_membership
from core.rbac import can as rbac_can
from core.tenancy import TenantNotFoundError, get_tenant
from infra.ratelimit import (
    RateLimitBackendError,
    RateLimitExceededError,
    enforce_rate_limit,
    get_ratelimit_config,
)

# A small, fixed, bounded hint -- never derived from the failed Redis
# backend itself (there is nothing trustworthy to derive it from once
# Redis has failed). Deliberately much shorter than a typical rate-limit
# window: this signals "retry soon, this is likely transient
# infrastructure trouble," not "wait out a window."
_BACKEND_FAILURE_RETRY_AFTER_SECONDS = 5

_BEARER_PREFIX = "Bearer "


def _session_cookie_token(request: Request) -> str | None:
    """P2.2: the session secret as carried by the browser cookie
    `api.auth.config.AuthHttpConfig.cookie_name` -- the *same* secret a
    `Bearer` header carries, validated by the same `validate_session()`
    below; only the transport differs. If auth is not configured at all
    (no `OIDC_REDIRECT_URI`), there is no cookie name to read and this
    transport is simply absent -- header authentication is unaffected."""
    from api.auth.config import get_auth_http_config

    try:
        cookie_name = get_auth_http_config().cookie_name
    except ValueError:
        return None
    return request.cookies.get(cookie_name) or None


def _resolve_session(authorization: str | None, cookie_token: str | None) -> Session:
    """Header first, cookie second -- never both, never a fallback from a
    *malformed* header to the cookie: an `Authorization` header that is
    present must be a well-formed `Bearer` credential on its own. One
    generic 401 for every failure (`api/errors.py`'s non-enumeration
    docstring). `isinstance(..., str)` also makes the function safe to
    call directly (outside FastAPI's dependency resolution) with the
    cookie argument left at its `Depends` default."""
    if authorization is not None:
        if not authorization.startswith(_BEARER_PREFIX):
            raise unauthorized()
        raw_token = authorization[len(_BEARER_PREFIX) :]
    elif isinstance(cookie_token, str):
        raw_token = cookie_token
    else:
        raw_token = ""
    if not raw_token:
        raise unauthorized()
    try:
        return validate_session(raw_token)
    except (SessionNotFoundError, SessionExpiredError, SessionRevokedError):
        raise unauthorized() from None


async def get_current_session(
    authorization: str | None = Header(default=None),
    cookie_token: str | None = Depends(_session_cookie_token),
) -> Session:
    """P2.2: the validated `core.identity.Session` record for this request
    (needed by `/auth/logout`, which revokes *this* session by id). Same
    credential resolution as `get_current_actor()`; never the raw token."""
    return _resolve_session(authorization, cookie_token)


async def get_current_actor(
    authorization: str | None = Header(default=None),
    cookie_token: str | None = Depends(_session_cookie_token),
) -> uuid.UUID:
    """Authentication: resolve the session secret -- from an
    `Authorization: Bearer` header, or (P2.2) from the session cookie --
    to its `core.identity.User` id. Raises 401 for a missing credential,
    a malformed header, or any invalid/expired/revoked session -- one
    generic response for every case (`api/errors.py`'s own
    non-enumeration docstring)."""
    return _resolve_session(authorization, cookie_token).user_id


async def get_tenant_context(
    tenant_id: uuid.UUID, actor_id: uuid.UUID = Depends(get_current_actor)
) -> RequestContext:
    """Tenant resolution: the `tenant_id` path parameter is validated
    against a real membership before being trusted (module docstring)."""
    try:
        get_tenant(tenant_id)
    except TenantNotFoundError:
        raise not_found("tenant") from None

    membership = get_membership(tenant_id, actor_id)
    if membership is None:
        raise not_found("tenant") from None

    return RequestContext(actor_id=actor_id, tenant_id=tenant_id, membership_id=membership.id)


async def _enforce_rate_limit_for_route(
    request: Request, context: RequestContext = Depends(get_tenant_context)
) -> RequestContext:
    """Rate limiting (docs/API-ARCHITECTURE.md section 6: "scoped by
    tenant"). Runs after tenant resolution -- rate limiting *by tenant*
    is only meaningful once a genuine tenant context has been
    established."""
    config = get_ratelimit_config()
    key = f"{context.tenant_id}:{request.url.path}"
    try:
        await enforce_rate_limit(key, config=config)
    except RateLimitExceededError as exc:
        raise rate_limited(exc.retry_after_seconds) from None
    except RateLimitBackendError:
        # Fail closed (P1.5, module docstring): the limit could not be
        # evaluated, so the request is rejected -- never treated as
        # allowed (would bypass rate limiting) and never reported as 429
        # (would falsely claim the caller exceeded a limit that was never
        # actually checked).
        raise service_unavailable(_BACKEND_FAILURE_RETRY_AFTER_SECONDS) from None
    return context


def require_permission(resource: str, action: str):
    """RBAC authorization (docs/SECURITY.md section 3: "a single
    policy-evaluation call (`can(actor, action, resource)`)"). The
    dependency a route handler actually declares -- composes
    authentication, tenant resolution, and rate limiting ahead of the
    permission check, so no route can invoke this without every earlier
    step already having passed."""

    async def _dependency(
        context: RequestContext = Depends(_enforce_rate_limit_for_route),
    ) -> RequestContext:
        allowed = rbac_can(
            actor_id=context.actor_id, tenant_id=context.tenant_id, action=action, resource=resource
        )
        if not allowed:
            record_audit_event(
                tenant_id=context.tenant_id,
                actor_type=ActorType.USER,
                actor_user_id=context.actor_id,
                action="api.access_denied",
                resource_type="http_route",
                resource_id=f"{resource}:{action}",
                outcome=AuditOutcome.DENIED,
            )
            raise forbidden()
        return context

    return _dependency


def require_entitlement_and_quota(
    resource: str,
    action: str,
    *,
    entitlement_key: str | None = None,
    quota_metric: str | None = None,
    quota_quantity: Decimal = Decimal("1"),
):
    """P1.9: Entitlement -> Quota, composed on top of `require_permission`'s
    existing chain (Authentication -> Tenant Resolution -> Rate Limiting ->
    RBAC, module docstring) -- the fixed enforcement order stays:

        Authentication -> Tenant Resolution -> RBAC -> Entitlement ->
        Quota -> (route handler) business operation

    A route that needs no entitlement/quota gating keeps using
    `require_permission()` directly; this wraps it rather than
    duplicating it, so every step `require_permission()` already
    guarantees (including its RBAC-denial audit write) still runs
    first, unchanged.

    `entitlement_key`/`quota_metric` are both optional and independent --
    a route can gate on either, both, or (by passing neither) behave
    identically to `require_permission()` alone. Both checks run against
    `context.tenant_id` -- the authenticated, membership-verified tenant
    `get_tenant_context()` already established (module docstring's own
    "tenant_id is a claim, not a trust boundary" rule) -- never a
    caller-supplied tenant id from anywhere else in the request.

    **Entitlement denial -> 403** (`api.errors.forbidden()`, the same
    generic, non-enumerating response `require_permission()`'s own RBAC
    denial already returns -- a client cannot distinguish "wrong
    permission" from "plan doesn't include this capability," which is
    the intended non-disclosure). Audited exactly like an RBAC denial
    (`core.audit_log`, `action="api.access_denied"`) -- an entitlement
    check is an authorization decision about this actor/tenant, the same
    class of event RBAC denial already is.

    **Quota denial -> 429** (`api.errors.quota_exceeded()`). Deliberately
    NOT audited -- mirrors `_enforce_rate_limit_for_route`'s own
    rate-limit-exceeded precedent (module docstring): a routine,
    expected, high-frequency-capable business outcome, not a
    security-relevant decision about the actor. `consume_quota()`
    (`core/usage/service.py`) already raises before recording any usage
    when it would deny, so a quota denial here never has a side effect
    to undo.
    """

    async def _dependency(
        context: RequestContext = Depends(require_permission(resource, action)),
    ) -> RequestContext:
        if entitlement_key is not None:
            try:
                require_entitlement(context.tenant_id, entitlement_key)
            except EntitlementDeniedError:
                record_audit_event(
                    tenant_id=context.tenant_id,
                    actor_type=ActorType.USER,
                    actor_user_id=context.actor_id,
                    action="api.access_denied",
                    resource_type="entitlement",
                    resource_id=entitlement_key,
                    outcome=AuditOutcome.DENIED,
                )
                raise forbidden() from None

        if quota_metric is not None:
            try:
                consume_quota(context.tenant_id, quota_metric, quota_quantity)
            except QuotaExceededError:
                raise quota_exceeded() from None

        return context

    return _dependency


_IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"


async def get_idempotency_key(
    idempotency_key: str | None = Header(default=None, alias=_IDEMPOTENCY_KEY_HEADER),
) -> str | None:
    """P1.11: extracts and validates the optional `Idempotency-Key`
    request header. Returns `None` when the header is absent -- whether
    an operation *requires* one is that operation's own business
    decision (a route handler checks for `None` itself and either
    proceeds without idempotency or rejects the request), not something
    this generic, operation-agnostic dependency can know.

    Deliberately a standalone dependency, not fused into
    `require_permission()`/`require_entitlement_and_quota()`'s chain:
    validating a header's shape needs no tenant/actor context and makes
    no database call, so it carries no ordering dependency on
    Authentication/RBAC/Entitlement/Quota -- a route composes it as a
    sibling `Depends(...)`. The actual reservation-and-replay logic
    (`core.idempotency.run_idempotent()`/`begin_idempotent_operation()`)
    runs inside the route's own business-operation call (e.g.
    `core.usage.service.consume_quota_idempotent()`), never split across
    a second HTTP-layer dependency -- the reservation and the business
    mutation must stay coupled (`core/idempotency/service.py`'s own
    module docstring), which a second, separate FastAPI dependency step
    could not guarantee.
    """
    if idempotency_key is None:
        return None
    try:
        validate_idempotency_key(idempotency_key)
    except IdempotencyKeyInvalidError:
        raise idempotency_key_invalid() from None
    return idempotency_key
