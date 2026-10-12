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
tokens only (`saas_os.core.identity.sessions.validate_session()`), per
`docs/IMPLEMENTATION-ROADMAP.md` Phase 8.1's own Dependencies line
("3.2, 3.3" -- `saas_os/core/identity`, `saas_os/core/rbac` -- not 4.1 `saas_os/core/api_keys`).
API-key HTTP authentication is a deliberate Non-Goal of this phase (see
`saas_os/api/__init__.py`), not an oversight -- a future phase that needs it
extends `get_current_actor()` with a second accepted credential shape,
resolved through the existing `saas_os.core.api_keys` module, never a new
identity model.

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
from decimal import Decimal
from urllib.parse import urlsplit

from fastapi import Depends, Header, Request

from saas_os.api.context import RequestContext
from saas_os.api.errors import (
    forbidden,
    idempotency_key_invalid,
    not_found,
    quota_exceeded,
    rate_limited,
    service_unavailable,
    unauthorized,
)
from saas_os.api.route_policy import RoutePolicy, RoutePolicyKind, _register_policy_dependency
from saas_os.core.audit_log import ActorType, AuditOutcome
from saas_os.core.audit_log import record as record_audit_event
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

    # FE-4: declares the "permission" route policy for this exact permission.
    return _register_policy_dependency(
        _dependency, RoutePolicy(RoutePolicyKind.PERMISSION, f"{resource}:{action}")
    )


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
