"""The enforced ingress middleware chain
(docs/IMPLEMENTATION-ROADMAP.md Phase 8.1's own Objective: "wire
saas_os/core/identity (auth) and saas_os/core/rbac (authz) as the enforced middleware
every route passes through").

Four composable FastAPI dependencies, each depending on the previous,
matching this checkpoint's own required chain:

    Authentication (get_current_actor)
        -> Tenant Resolution (get_tenant_context)
        -> Rate Limiting (rate limit check)
        -> RBAC Authorization (require_permission)

`require_permission(resource, action)` is the one dependency a route
handler actually declares (`saas_os/api/v1/tenant_status.py`) -- it composes all
four steps, so no route can accidentally skip one by only depending on
an earlier step in the chain.

P1.9 adds two more optional steps after RBAC, composed the same way:
`require_entitlement_and_quota(resource, action, entitlement_key=...,
quota_metric=...)` wraps `require_permission()` and adds Entitlement
(`saas_os.core.billing.require_entitlement()`) -> Quota
(`saas_os.core.usage.consume_quota()`), matching the fixed order
Authentication -> Tenant Resolution -> RBAC -> Entitlement -> Quota ->
business operation. See that function's own docstring for the full
denial/audit contract.

P1.11 adds `get_idempotency_key()`, a standalone dependency (no ordering
dependency on the others -- see its own docstring for why) that extracts
and validates an optional `Idempotency-Key` request header. The actual
idempotent-execution logic lives in the business operation itself
(`saas_os.core.usage.service.consume_quota_idempotent()`, `saas_os.core.billing.service.
subscribe_idempotent()`), never split across a second HTTP dependency.

**Authentication mechanism (Phase 8's own scope)**: session bearer
tokens (`saas_os.core.identity.sessions.validate_session()`), per
`docs/IMPLEMENTATION-ROADMAP.md` Phase 8.1's own Dependencies line
("3.2, 3.3" -- `saas_os/core/identity`, `saas_os/core/rbac` -- not 4.1 `saas_os/core/api_keys`).
Since ADR-0047 a route may also accept an API key, by declaring
`require_permission(..., api_key=True)`: the key is presented in its own
`X-API-Key` header and resolved through `saas_os.core.api_keys.validate_api_key()`,
never a new identity model. `get_current_actor()` itself still accepts a
session only.

**Tenant resolution (this checkpoint's own Rule 13: "Do not rely on
callers to supply trustworthy actor/tenant identity")**: the `tenant_id`
path parameter is a *claim*, not a trust boundary by itself -- it is
always validated against a real `saas_os.core.identity.TenantMembership` for the
authenticated actor before being treated as the request's tenant
context. A caller cannot access data for a tenant they do not genuinely
belong to merely by naming it in the URL.

**Non-enumeration**: `get_tenant_context()` returns the identical 404 for
"tenant does not exist" and "tenant exists but the caller is not a
member" (`saas_os/api/errors.py`'s own docstring) -- an authenticated caller
learns nothing about which tenant IDs are real.

**Audit**: only the RBAC-denial path is audited here
(`saas_os.core.audit_log`, `action="api.access_denied"`) -- mirrors
`saas_os.control_plane.orchestration`'s own Phase 7.1 precedent of auditing a
denied invocation. Authentication failures are not audited (no
resolvable, trustworthy `tenant_id` exists yet at that point --
`saas_os/core/audit_log/models.py`'s own "no tenant-less audit event"
constraint); a 404 tenant-not-found/not-a-member response is not audited
either, for the same reason -- recording an event "within" a tenant the
caller has no genuine relationship to would misrepresent what actually
happened. A successful, routine read is not audited, mirroring
`saas_os/core/billing`/`saas_os/core/webhooks`/`saas_os/core/notifications`'s own established
"routine reads are not privileged mutations" precedent. A rate-limit
*backend* failure (P1.5, below) is likewise not audited -- an
infrastructure outage, not a security-relevant decision about this actor
(`saas_os/infra/ratelimit/limiter.py`'s own structured-logging call already makes
it operationally visible, correlated with `request_id`; duplicating that
into `core.audit_log` would misrepresent a Redis outage as an audit-worthy
actor decision).

**P1.5: rate-limit backend failure is fail-closed, never fail-open**. If
Redis itself fails (connection refused, timeout, any other
`saas_os.infra.ratelimit.RateLimitBackendError`), `_enforce_rate_limit_for_route`
raises `saas_os.api.errors.service_unavailable()` (503) -- never lets the
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

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, Header, Request

from saas_os.api.context import RequestContext, RequestPrincipal
from saas_os.api.errors import (
    forbidden,
    idempotency_key_invalid,
    not_found,
    quota_exceeded,
    rate_limited,
    route_not_found,
    service_unavailable,
    session_not_fresh,
    unauthorized,
)
from saas_os.api.platform_admin.config import get_platform_admin_http_config
from saas_os.api.route_policy import RoutePolicy, RoutePolicyKind, _register_policy_dependency
from saas_os.core.api_keys import (
    ExpiredApiKeyError,
    InactiveServiceAccountError,
    InvalidApiKeyError,
    RevokedApiKeyError,
    validate_api_key,
)
from saas_os.core.audit_log import ActorType, AuditOutcome
from saas_os.core.audit_log import record as record_audit_event
from saas_os.core.authority import UserCaller
from saas_os.core.billing.errors import EntitlementDeniedError
from saas_os.core.billing.service import require_entitlement
from saas_os.core.idempotency import validate_idempotency_key
from saas_os.core.idempotency.errors import IdempotencyKeyInvalidError
from saas_os.core.identity import get_membership
from saas_os.core.identity.errors import (
    InactiveUserError,
    SessionExpiredError,
    SessionNotFoundError,
    SessionRevokedError,
)
from saas_os.core.identity.models import Session
from saas_os.core.identity.sessions import validate_session
from saas_os.core.platform_authority import (
    PlatformOperationTimeoutError,
    PlatformPermission,
    is_active_platform_operator,
    platform_can,
    platform_operation,
    record_platform_refusal,
)
from saas_os.core.rbac import PrincipalType, is_authority_changing
from saas_os.core.rbac import can as rbac_can
from saas_os.core.tenancy import (
    TenantNotFoundError,
    TenantStatus,
    get_tenant,
    is_accessible_to_principals,
)
from saas_os.core.usage.errors import QuotaExceededError
from saas_os.core.usage.service import consume_quota
from saas_os.infra.ratelimit import (
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
    `saas_os.api.auth.config.AuthHttpConfig.cookie_name` -- the *same* secret a
    `Bearer` header carries, validated by the same `validate_session()`
    below; only the transport differs. If auth is not configured at all
    (no `OIDC_REDIRECT_URI`), there is no cookie name to read and this
    transport is simply absent -- header authentication is unaffected."""
    from saas_os.api.auth.config import get_auth_http_config

    try:
        cookie_name = get_auth_http_config().cookie_name
    except ValueError:
        return None
    return request.cookies.get(cookie_name) or None


def _resolve_session(authorization: str | None, cookie_token: str | None) -> Session:
    """Header first, cookie second -- never both, never a fallback from a
    *malformed* header to the cookie: an `Authorization` header that is
    present must be a well-formed `Bearer` credential on its own. One
    generic 401 for every failure (`saas_os/api/errors.py`'s non-enumeration
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
    except (SessionNotFoundError, SessionExpiredError, SessionRevokedError, InactiveUserError):
        raise unauthorized() from None


_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_csrf_logger = logging.getLogger("saas_os.api.csrf")


def _normalized_origin(value: str) -> str | None:
    """`scheme://host[:port]`, lower-cased, default port dropped -- or `None`
    if `value` is not exactly an origin (a path, a query, credentials,
    `null`, an unknown scheme)."""
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        return None
    if parts.password is not None:
        return None
    host = parts.hostname.lower()
    if port is None or port == _DEFAULT_PORTS[parts.scheme]:
        return f"{parts.scheme}://{host}"
    return f"{parts.scheme}://{host}:{port}"


def _trusted_browser_origin() -> str | None:
    """The one origin a browser legitimately sends the session cookie from:
    `PUBLIC_APP_ORIGIN` (ADR-0024), or -- for a deployment that declares
    only `OIDC_REDIRECT_URI` -- the origin of that callback, which is the
    host that set the cookie."""
    from saas_os.api.auth.config import get_auth_http_config

    try:
        config = get_auth_http_config()
    except ValueError:
        return None
    source = config.public_app_origin
    if source is None:
        callback = urlsplit(config.redirect_uri)
        source = f"{callback.scheme}://{callback.netloc}"
    return _normalized_origin(source)


def _enforce_same_origin_for_cookie_mutation(request: Request, authorization: str | None) -> None:
    """ADR-0044: cross-site request forgery defense for cookie-authenticated
    state changes.

    A browser attaches the session cookie to any request it sends to this
    host, including one a different site caused. `SameSite=Lax` stops the
    cross-*site* case; it does not stop another origin of the *same site*
    (a sibling subdomain), because "site" is the registrable domain. So an
    unsafe-method request that authenticates by cookie must prove it was
    issued by this application's own origin:

    - `Origin` must be present and equal the trusted origin exactly
      (scheme, host and port). Every current browser sends `Origin` on
      every non-GET/HEAD request, same-origin included; its absence means
      a non-browser client, which has no reason to be using the cookie.
    - `Sec-Fetch-Site`, when the browser sends it, must be `same-origin`.

    Not applied to safe methods (they must not change state), and not
    applied when the credential is an `Authorization` header: a page cannot
    make a browser attach that header to another origin without a CORS
    preflight this API never answers, so header-authenticated clients --
    scripts, services, a frontend that stores the token itself -- are
    unaffected. One generic 403, the reason only in a structured log.
    """
    if authorization is not None or request.method.upper() in _SAFE_METHODS:
        return
    trusted = _trusted_browser_origin()
    origin_header = request.headers.get("origin")
    fetch_site = request.headers.get("sec-fetch-site")
    if trusted is None:
        reason = "no_trusted_origin_configured"
    elif origin_header is None:
        reason = "origin_missing"
    elif _normalized_origin(origin_header) != trusted:
        reason = "origin_mismatch"
    elif fetch_site is not None and fetch_site.strip().lower() != "same-origin":
        reason = "fetch_site_not_same_origin"
    else:
        return
    _csrf_logger.warning(
        "csrf_rejected", extra={"csrf_reason": reason, "http_method": request.method.upper()}
    )
    raise forbidden()


def _cookie_mutation_guard(
    request: Request,
    authorization: str | None = Header(default=None),
    cookie_token: str | None = Depends(_session_cookie_token),
) -> None:
    """Runs the ADR-0044 check exactly when the session cookie is the
    credential in play: a cookie is present and no `Authorization` header
    replaces it. A request with no credential at all is left to
    authentication's own 401."""
    if isinstance(cookie_token, str):
        _enforce_same_origin_for_cookie_mutation(request, authorization)


async def get_current_session(
    authorization: str | None = Header(default=None),
    cookie_token: str | None = Depends(_session_cookie_token),
    _same_origin: None = Depends(_cookie_mutation_guard),
) -> Session:
    """P2.2: the validated `saas_os.core.identity.Session` record for this request
    (needed by `/auth/logout`, which revokes *this* session by id). Same
    credential resolution as `get_current_actor()`; never the raw token."""
    return _resolve_session(authorization, cookie_token)


async def get_current_actor(
    authorization: str | None = Header(default=None),
    cookie_token: str | None = Depends(_session_cookie_token),
    _same_origin: None = Depends(_cookie_mutation_guard),
) -> uuid.UUID:
    """Authentication: resolve the session secret -- from an
    `Authorization: Bearer` header, or (P2.2) from the session cookie --
    to its `saas_os.core.identity.User` id. Raises 401 for a missing credential,
    a malformed header, or any invalid/expired/revoked session -- one
    generic response for every case (`saas_os/api/errors.py`'s own
    non-enumeration docstring).

    A cookie-authenticated request with an unsafe method must also come
    from this application's own origin (ADR-0044) -- 403 otherwise."""
    return _resolve_session(authorization, cookie_token).user_id


# Foundation Enforcement (FE-4, saas_os/api/route_policy.py): these exact function
# objects declare the "authenticated" route policy (identity registry, not a
# function attribute) -- the functions behave exactly as before.
_register_policy_dependency(get_current_session, RoutePolicy(RoutePolicyKind.AUTHENTICATED))
_register_policy_dependency(get_current_actor, RoutePolicy(RoutePolicyKind.AUTHENTICATED))


async def get_tenant_context(
    tenant_id: uuid.UUID, actor_id: uuid.UUID = Depends(get_current_actor)
) -> RequestContext:
    """Tenant resolution: the `tenant_id` path parameter is validated
    against a real membership before being trusted (module docstring).

    PRIV-03 P8 (privacy re-audit RA-04): a tenant whose lifecycle no
    longer admits tenant principals (`SUSPENDED`/`DELETED`/`PURGING`/
    `PURGED`, `saas_os.core.tenancy.lifecycle.PRINCIPAL_INACCESSIBLE_STATUSES`)
    yields no request context at all -- the identical, non-enumerating
    404 a nonexistent tenant or a non-member already gets, so a caller
    learns nothing about the tenant's state. This pre-check is unlocked
    (a request has no transaction to lock in); the authorization decision
    downstream (`require_permission()` -> `saas_os.core.rbac.can()`) re-reads the
    lifecycle under `lock_accessible_tenant()`, which is the race-safe
    fence."""
    try:
        tenant = get_tenant(tenant_id)
    except TenantNotFoundError:
        raise not_found("tenant") from None
    if not is_accessible_to_principals(TenantStatus(tenant.status)):
        raise not_found("tenant")

    membership = get_membership(tenant_id, actor_id)
    if membership is None:
        raise not_found("tenant") from None

    return RequestContext(actor_id=actor_id, tenant_id=tenant_id, membership_id=membership.id)


_API_KEY_HEADER = "X-API-Key"  # pragma: allowlist secret -- a header name
# Longer than any key SaaS OS issues (`sok_` and 43 characters); a longer
# value is refused before it is hashed or looked up.
_MAX_API_KEY_LENGTH = 256


def _api_key_context(raw_key: str, tenant_id: uuid.UUID) -> RequestContext:
    """ADR-0047: the context of a request authenticated by an API key.
    Authentication is `validate_api_key()` -- the one path that honours
    revocation, expiry, the tenant's lifecycle, an inactive owning user and
    a disabled service account, auditing each refusal -- and every such
    failure is the one generic 401. A key reaches only its own tenant: any
    other is the 404 a non-member gets, which says nothing about whether
    the tenant exists."""
    # Whitespace around a header value is not part of it (RFC 9110); a key
    # never contains any.
    raw_key = raw_key.strip()
    if not raw_key or len(raw_key) > _MAX_API_KEY_LENGTH:
        raise unauthorized()
    try:
        key = validate_api_key(raw_key)
    except (
        InvalidApiKeyError,
        RevokedApiKeyError,
        ExpiredApiKeyError,
        InactiveServiceAccountError,
    ):
        raise unauthorized() from None
    if key.tenant_id != tenant_id:
        raise not_found("tenant")
    if key.user_id is not None:
        # The key's composite foreign key guarantees the membership row;
        # its status is decided by `can()` below, as for a session.
        membership = get_membership(tenant_id, key.user_id)
        if membership is None:
            raise not_found("tenant")
        return RequestContext(
            actor_id=key.user_id,
            tenant_id=tenant_id,
            membership_id=membership.id,
            api_key_id=key.id,
        )
    assert key.service_account_id is not None  # exactly one owner (ck_api_keys_single_owner)
    return RequestContext(
        actor_id=key.service_account_id,
        tenant_id=tenant_id,
        membership_id=None,
        principal=RequestPrincipal.SERVICE_ACCOUNT,
        api_key_id=key.id,
    )


async def _tenant_context_accepting_api_key(
    request: Request,
    tenant_id: uuid.UUID,
    x_api_key: str | None = Header(default=None, alias=_API_KEY_HEADER),
    authorization: str | None = Header(default=None),
    cookie_token: str | None = Depends(_session_cookie_token),
) -> RequestContext:
    """Authentication and tenant resolution for a route that accepts an
    API key (ADR-0047). Without an `X-API-Key` header this is exactly the
    session chain: the ADR-0044 same-origin check for a cookie mutation,
    then the session, then the membership. With one, the key alone
    authenticates: a request that also carries a session credential (an
    `Authorization` header or the session cookie) is the generic 401 --
    one request, one principal, and no cookie riding along with a key."""
    if x_api_key is None:
        _cookie_mutation_guard(request, authorization, cookie_token)
        actor_id = _resolve_session(authorization, cookie_token).user_id
        return await get_tenant_context(tenant_id, actor_id)
    if authorization is not None or isinstance(cookie_token, str):
        raise unauthorized()
    return _api_key_context(x_api_key, tenant_id)


async def _enforce_rate_limit(request: Request, context: RequestContext) -> None:
    """The limits of one request: per tenant and path, and -- for a request
    authenticated by an API key (ADR-0047) -- per key as well. Fails
    closed (module docstring)."""
    config = get_ratelimit_config()
    keys = [f"{context.tenant_id}:{request.url.path}"]
    if context.api_key_id is not None:
        keys.append(f"api-key:{context.api_key_id}")
    try:
        for key in keys:
            await enforce_rate_limit(key, config=config)
    except RateLimitExceededError as exc:
        raise rate_limited(exc.retry_after_seconds) from None
    except RateLimitBackendError:
        raise service_unavailable(_BACKEND_FAILURE_RETRY_AFTER_SECONDS) from None


async def _enforce_rate_limit_accepting_api_key(
    request: Request, context: RequestContext = Depends(_tenant_context_accepting_api_key)
) -> RequestContext:
    await _enforce_rate_limit(request, context)
    return context


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


def require_permission(resource: str, action: str, *, api_key: bool = False):
    """RBAC authorization (docs/SECURITY.md section 3: "a single
    policy-evaluation call (`can(actor, action, resource)`)"). The
    dependency a route handler actually declares -- composes
    authentication, tenant resolution, and rate limiting ahead of the
    permission check, so no route can invoke this without every earlier
    step already having passed.

    `api_key=True` (ADR-0047) lets the route also be called with an
    `X-API-Key` instead of a session; the same permission is then
    evaluated for the key's user, or for its service account. A
    permission that changes authority (`saas_os.core.rbac.is_authority_changing`:
    every capability on memberships, roles, invitations, API keys,
    service accounts, ...; the billing mutations; tenant self-suspension --
    what a support-access grant may never satisfy either) never accepts a
    key: asking for it is a `ValueError` when the route is defined."""
    if api_key:
        if is_authority_changing(resource, action):
            raise ValueError(
                f"{resource}:{action} changes authority and cannot accept an API key (ADR-0047)."
            )
        return _require_permission_accepting_api_key(resource, action)

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

    # FE-4: declares the "permission" route policy for this exact permission.
    return _register_policy_dependency(
        _dependency, RoutePolicy(RoutePolicyKind.PERMISSION, f"{resource}:{action}")
    )


def _audit_actor(context: RequestContext) -> dict[str, Any]:
    """The actor columns of an audit row about this request: the user, or
    the service account whose API key authenticated it (ADR-0047)."""
    if context.principal is RequestPrincipal.SERVICE_ACCOUNT:
        return {
            "actor_type": ActorType.SERVICE_ACCOUNT,
            "actor_user_id": None,
            "actor_service_account_id": context.actor_id,
        }
    return {"actor_type": ActorType.USER, "actor_user_id": context.actor_id}


def _require_permission_accepting_api_key(resource: str, action: str):
    async def _dependency(
        context: RequestContext = Depends(_enforce_rate_limit_accepting_api_key),
    ) -> RequestContext:
        service_account = context.principal is RequestPrincipal.SERVICE_ACCOUNT
        allowed = rbac_can(
            actor_id=context.actor_id,
            tenant_id=context.tenant_id,
            action=action,
            resource=resource,
            actor_type=PrincipalType.SERVICE_ACCOUNT if service_account else PrincipalType.USER,
            actor_tenant_id=context.tenant_id if service_account else None,
        )
        if not allowed:
            record_audit_event(
                tenant_id=context.tenant_id,
                **_audit_actor(context),
                action="api.access_denied",
                resource_type="http_route",
                resource_id=f"{resource}:{action}",
                outcome=AuditOutcome.DENIED,
            )
            raise forbidden()
        return context

    return _register_policy_dependency(
        _dependency,
        RoutePolicy(RoutePolicyKind.PERMISSION, f"{resource}:{action}", accepts_api_key=True),
    )


def require_entitlement_and_quota(
    resource: str,
    action: str,
    *,
    entitlement_key: str | None = None,
    quota_metric: str | None = None,
    quota_quantity: Decimal = Decimal("1"),
    api_key: bool = False,
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

    **Entitlement denial -> 403** (`saas_os.api.errors.forbidden()`, the same
    generic, non-enumerating response `require_permission()`'s own RBAC
    denial already returns -- a client cannot distinguish "wrong
    permission" from "plan doesn't include this capability," which is
    the intended non-disclosure). Audited exactly like an RBAC denial
    (`saas_os.core.audit_log`, `action="api.access_denied"`) -- an entitlement
    check is an authorization decision about this actor/tenant, the same
    class of event RBAC denial already is.

    **Quota denial -> 429** (`saas_os.api.errors.quota_exceeded()`). Deliberately
    NOT audited -- mirrors `_enforce_rate_limit_for_route`'s own
    rate-limit-exceeded precedent (module docstring): a routine,
    expected, high-frequency-capable business outcome, not a
    security-relevant decision about the actor. `consume_quota()`
    (`saas_os/core/usage/service.py`) already raises before recording any usage
    when it would deny, so a quota denial here never has a side effect
    to undo.
    """

    async def _dependency(
        context: RequestContext = Depends(require_permission(resource, action, api_key=api_key)),
    ) -> RequestContext:
        if entitlement_key is not None:
            try:
                require_entitlement(context.tenant_id, entitlement_key)
            except EntitlementDeniedError:
                record_audit_event(
                    tenant_id=context.tenant_id,
                    **_audit_actor(context),
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


# --- the platform chain (ADR-0045 section 7) -------------------------------------------

_PLATFORM_ROUTE_TARGET = "http_route"
_CODE_NOT_AUTHORIZED = "not_authorized"
_CODE_SESSION_NOT_FRESH = "session_not_fresh"


@dataclass(frozen=True)
class PlatformRequestContext:
    """The verified context of a platform request: the authenticated user,
    who is an active operator holding the route's permission, and the
    session that was presented. There is no tenant in it. Only ever
    constructed by `require_platform_permission()`."""

    actor_id: uuid.UUID
    session_id: uuid.UUID


async def _enforce_platform_rate_limit(request: Request, actor_id: uuid.UUID) -> None:
    """Keyed by actor and route, and fail closed on a backend error, as the
    tenant chain is. The route is the declared template, not the path as
    requested: one bucket per actor per route, whatever identifiers the
    path carries, so varying an id neither escapes the limit nor creates a
    key per id."""
    key = f"platform:{actor_id}:{_route_label(request)}"
    try:
        await enforce_rate_limit(key, config=get_ratelimit_config())
    except RateLimitExceededError as exc:
        raise rate_limited(exc.retry_after_seconds) from None
    except RateLimitBackendError:
        raise service_unavailable(_BACKEND_FAILURE_RETRY_AFTER_SECONDS) from None


def _route_label(request: Request) -> str:
    """`METHOD /path/template`: the route as declared, never the path as
    requested -- no identifier from the URL reaches the audit row."""
    route = request.scope.get("route")
    template = getattr(route, "path", None) or "unknown"
    return f"{request.method.upper()} {template}"


def require_platform_permission(
    permission: PlatformPermission, *, operation: str, fresh_session: bool = False
):
    """The fourth route policy (ADR-0045 section 7): the dependency a
    platform route declares. `operation` is the key of the platform
    operation the route performs; its declared permission must be
    `permission` (checked here, when the route is declared), and its audit
    action is the one a refusal is recorded under.

    The chain, in order:

    0. The deployment's opt-in: unless `PLATFORM_ADMIN_HTTP_ENABLED` is
       true, the `404` of an unknown path, for every caller. (Startup
       already refuses to serve a mounted router without it; this holds
       where the startup check did not run.)
    1. Authentication: `get_current_session`, with the ADR-0044
       same-origin check for a cookie-authenticated unsafe method.
       Sessions only. `401`.
    2. Rate limit, keyed by actor and route; `429`, or `503` if the backend
       fails (never open).
    3. Is the caller an active operator at all? If not: the `404` an
       unknown path returns, and nothing recorded -- the caller is not an
       operator, and must not learn that the route exists.
    4. With `fresh_session=True`: the presenting session must be at most
       `PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS` old (decision D2).
       Older: `401` with the code `session_not_fresh`, and a `denied`
       platform audit row. It measures the SaaS OS session and proves
       nothing about when the person last authenticated at the identity
       provider.
    5. `platform_can()` for the permission. Without it: `403`, and a
       `denied` platform audit row.

    There is no tenant resolution: a platform route never takes authority
    from a tenant in the path. The route adds no decision: the Core
    function it calls authorizes the same caller again, in its own
    transaction, and is what enforces."""
    if not isinstance(permission, PlatformPermission):
        raise TypeError("permission must be a PlatformPermission.")
    spec = platform_operation(operation)
    if spec.permission is not permission:
        raise ValueError(f"Platform operation {operation!r} is not gated by {permission.value!r}.")
    if not isinstance(fresh_session, bool):
        raise TypeError("fresh_session must be a bool.")

    def _refused(request: Request, actor_id: uuid.UUID, code: str) -> None:
        record_platform_refusal(
            caller=UserCaller(actor_id),
            action=spec.audit_action,
            target_type=_PLATFORM_ROUTE_TARGET,
            target_id=_route_label(request),
            code=code,
        )

    async def _not_enabled_is_not_found() -> None:
        # The deployment's opt-in, at request time as well as at startup:
        # an application whose lifespan did not run (a sub-application, a
        # replaced lifespan, an app not built by `build_platform_app()`)
        # serves no platform route unless the setting is true. Before
        # authentication: with the surface off, every caller gets the 404
        # of an unknown path.
        if not get_platform_admin_http_config().enabled:
            raise route_not_found()

    async def _dependency(
        request: Request,
        _enabled: None = Depends(_not_enabled_is_not_found),
        session: Session = Depends(get_current_session),
    ) -> PlatformRequestContext:
        actor_id = session.user_id
        await _enforce_platform_rate_limit(request, actor_id)
        try:
            operator = is_active_platform_operator(user_id=actor_id)
        except PlatformOperationTimeoutError:
            # A lock held the check past its statement timeout (ADR-0045,
            # amendment of 2026-10-14). Whether the caller is an operator is
            # not known, so the answer is the one a non-operator gets (section
            # 7): the 404 of an unknown path. An operator retries.
            raise route_not_found() from None
        if not operator:
            raise route_not_found()
        if fresh_session:
            limit = get_platform_admin_http_config().authority_session_max_age_seconds
            age = (datetime.now(UTC) - session.created_at).total_seconds()
            if age > limit:
                _refused(request, actor_id, _CODE_SESSION_NOT_FRESH)
                raise session_not_fresh()
        try:
            allowed = platform_can(user_id=actor_id, permission=permission)
        except PlatformOperationTimeoutError:
            # An operator, past the check above: nothing was decided; retry.
            raise service_unavailable(_BACKEND_FAILURE_RETRY_AFTER_SECONDS) from None
        if not allowed:
            _refused(request, actor_id, _CODE_NOT_AUTHORIZED)
            raise forbidden()
        return PlatformRequestContext(actor_id=actor_id, session_id=session.id)

    return _register_policy_dependency(
        _dependency,
        RoutePolicy(
            RoutePolicyKind.PLATFORM_PERMISSION, permission.value, fresh_session=fresh_session
        ),
    )


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
    (`saas_os.core.idempotency.run_idempotent()`/`begin_idempotent_operation()`)
    runs inside the route's own business-operation call (e.g.
    `saas_os.core.usage.service.consume_quota_idempotent()`), never split across
    a second HTTP-layer dependency -- the reservation and the business
    mutation must stay coupled (`saas_os/core/idempotency/service.py`'s own
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
