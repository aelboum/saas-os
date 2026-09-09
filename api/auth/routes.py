"""The OIDC Authorization Code Flow routes (P2.2). See `api/auth/__init__.py`
for the boundary this package keeps; this module is the sequence:

    GET /auth/login
        begin_login_transaction()           -> state, nonce, code_challenge (S256)
        Set-Cookie: <session>_login=<tx id>  (HttpOnly, Secure, SameSite=Lax, 10 min)
        303 -> provider authorization_endpoint (discovered, never hard-coded)

    GET /auth/callback?code=...&state=...
        require tx cookie + state + code     (400 otherwise, one generic message)
        consume_login_transaction(tx, state) (single-use, row-locked, constant-time)
        exchange_authorization_code(...)     (server-side, verifier + optional secret)
        validate_id_token(id_token, nonce)   (existing validator: sig/iss/aud/exp/alg/nonce)
        get_or_create_user_for_external_identity(iss, sub)
        issue_session(user_id)               (existing: 256-bit secret, SHA-256 at rest)
        Set-Cookie: <session>=<raw token>    (HttpOnly, Secure, SameSite=Lax, Path=/)
        delete the tx cookie; 303 -> AUTH_POST_LOGIN_PATH (fixed, configured)

    POST /auth/logout                        (requires a valid session)
        revoke_session(session.id); clear the cookie; 204

    GET /auth/me                             (requires a valid session)
        {"user_id": "<uuid>"}

**Failure semantics** (this checkpoint's own §17): every failure is a
fixed, generic response -- 400 for a malformed/unbound callback
(missing code/state/cookie, unknown/expired/replayed transaction, state
mismatch: one message for all of them, so a probe cannot tell which
check failed), 401 for an ID token the existing validator rejects, 502
for a provider that rejected/failed the exchange, 503 when the provider
was unreachable or the rate-limit backend is down. Never a 500 because
the provider said no, never a provider body, never a token, code,
verifier, or secret in a response or a log line.

**Rate limiting**: `/auth/login` and `/auth/callback` run before any
tenant exists, so the tenant-keyed chain in `api/dependencies.py` cannot
apply; they use the *same* `infra.ratelimit.enforce_rate_limit()` with a
`auth:<client address>` key and the same fail-closed 503 on backend
failure. No second limiter.

**CSRF**: the callback is protected by the single-use, cookie-bound
`state`; logout is a `POST` whose only credential is a `SameSite=Lax`
cookie (never sent on a cross-site POST by any current browser) or an
explicit `Authorization` header. No CSRF framework exists in this
repository to reuse; none is invented.

**Audit**: `core.audit_log` requires a tenant on every row
(`core/audit_log/models.py`: no tenant-less audit table exists, and
none is invented here). Login/logout happen before any tenant is known,
so they are recorded as structured, correlated log events
(`auth_login_started`, `auth_login_succeeded`, `auth_login_failed`,
`auth_callback_rejected`, `auth_logout`) carrying only the request id,
an outcome classification, the issuer, and -- after success -- the
stable internal user id. This is a documented limitation of P2.2, not
a claim of audit-log coverage.
"""

from __future__ import annotations

import logging
import uuid

from core.identity.errors import (
    LoginTransactionInvalidError,
    OIDCExchangeError,
    TokenValidationError,
)
from core.identity.models import Session as CoreSession
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from api.auth.config import AuthHttpConfig, get_auth_http_config
from api.dependencies import get_current_actor, get_current_session
from api.errors import service_unavailable, unauthorized
from core.identity import (
    OIDCConfigurationError,
    begin_login_transaction,
    build_authorization_url,
    consume_login_transaction,
    exchange_authorization_code,
    get_oidc_client_secret,
    get_oidc_flow_endpoints,
    get_oidc_provider_config,
    get_or_create_user_for_external_identity,
    issue_session,
    revoke_session,
    validate_id_token,
)
from infra.ratelimit import (
    RateLimitBackendError,
    RateLimitExceededError,
    enforce_rate_limit,
    get_ratelimit_config,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_SESSION_COOKIE_MAX_AGE_SECONDS = 12 * 60 * 60  # matches core.identity.sessions' default lifetime
_LOGIN_COOKIE_MAX_AGE_SECONDS = 10 * 60  # matches begin_login_transaction()'s default lifetime
_BACKEND_FAILURE_RETRY_AFTER_SECONDS = 5
_MAX_CALLBACK_PARAM_LENGTH = 2048


def _bad_callback() -> HTTPException:
    """One fixed message for every malformed/unbound callback (module
    docstring) -- deliberately never says *which* parameter or check."""
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid login callback.")


def _provider_rejected() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY, detail="Identity provider rejected the login."
    )


def _provider_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Identity provider unavailable.",
        headers={"Retry-After": str(_BACKEND_FAILURE_RETRY_AFTER_SECONDS)},
    )


def _auth_not_configured() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Authentication is not configured."
    )


def _config() -> AuthHttpConfig:
    try:
        return get_auth_http_config()
    except ValueError:
        logger.error("auth_not_configured", extra={"auth_config_error": "AuthConfigurationError"})
        raise _auth_not_configured() from None


_FORWARDED_FOR_HEADER = "X-Forwarded-For"


def _resolve_client_address(request: Request, config: AuthHttpConfig) -> str:
    """P2.3: the address the pre-login rate limit key is built from.

    `config.trust_proxy_headers` is `false` unless a deployment explicitly
    declares it sits behind the trusted reverse proxy
    (`docker-compose.prod.yml`'s `backend` service only) -- when it is
    `false` (every development/test environment, and any deployment that
    hasn't opted in), this is exactly `request.client.host`, unchanged
    from before P2.3.

    When trusted, `X-Forwarded-For` may contain a chain --
    `<client>, <hop-1>, ..., <hop-n>` -- where every entry except the
    *last* is attacker-controlled (a client can send any `X-Forwarded-For`
    value it likes; Caddy's `reverse_proxy` appends the peer address it
    actually observed as the final entry, never trusting or rewriting
    what came before it). This function therefore only ever reads the
    last entry -- the one hop that could not have been forged, because it
    was appended by the one proxy this deployment's own network topology
    (P2.3: `backend` has no host-published port and is reachable only via
    `edge`, i.e. only from `proxy`) guarantees is the actual, trusted
    peer. Reading any earlier entry, or trusting this header at all
    without `trust_proxy_headers`, would let an attacker set their own
    rate-limit identity at will -- the exact spoofing this checkpoint's
    own security requirement rules out. No second IP-parsing library or
    abstraction is introduced; this is a single, narrow `rsplit`.
    """
    direct_peer = request.client.host if request.client is not None else "unknown"
    if not config.trust_proxy_headers:
        return direct_peer
    forwarded = request.headers.get(_FORWARDED_FOR_HEADER)
    if not forwarded:
        return direct_peer
    last_hop = forwarded.rsplit(",", 1)[-1].strip()
    return last_hop or direct_peer


async def _enforce_auth_rate_limit(
    request: Request, config: AuthHttpConfig = Depends(_config)
) -> None:
    """Pre-authentication rate limit for `/auth/login` and `/auth/callback`
    -- the existing limiter, keyed by client address (module docstring).
    Fails closed (503) exactly like `api.dependencies._enforce_rate_limit_for_route`."""
    client_host = _resolve_client_address(request, config)
    key = f"auth:{client_host}"
    try:
        await enforce_rate_limit(key, config=get_ratelimit_config())
    except RateLimitExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded.",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from None
    except RateLimitBackendError:
        raise service_unavailable(_BACKEND_FAILURE_RETRY_AFTER_SECONDS) from None


def _set_session_cookie(response: Response, config: AuthHttpConfig, raw_token: str) -> None:
    response.set_cookie(
        key=config.cookie_name,
        value=raw_token,
        max_age=_SESSION_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        path="/",
    )


def _clear_cookie(response: Response, config: AuthHttpConfig, name: str) -> None:
    response.delete_cookie(
        key=name, path="/", httponly=True, secure=config.cookie_secure, samesite="lax"
    )


# --- GET /auth/login ------------------------------------------------------------


@router.get("/login", include_in_schema=True, status_code=status.HTTP_303_SEE_OTHER)
async def login(
    request: Request, _rate_limited: None = Depends(_enforce_auth_rate_limit)
) -> Response:
    config = _config()
    try:
        provider = get_oidc_provider_config()
        endpoints = get_oidc_flow_endpoints()
    except (OIDCConfigurationError, LookupError) as exc:
        logger.error("auth_login_failed", extra={"auth_failure": type(exc).__name__})
        raise _auth_not_configured() from None

    started = begin_login_transaction()
    url = build_authorization_url(
        provider,
        endpoints,
        redirect_uri=config.redirect_uri,
        state=started.state,
        nonce=started.nonce,
        code_challenge=started.code_challenge,
    )
    logger.info(
        "auth_login_started",
        extra={"issuer": provider.issuer, "login_transaction_id": str(started.transaction_id)},
    )
    response = RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=config.login_transaction_cookie_name,
        value=str(started.transaction_id),
        max_age=_LOGIN_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        path="/auth",
    )
    return response


# --- GET /auth/callback ---------------------------------------------------------


def _parse_transaction_cookie(raw: str | None) -> uuid.UUID | None:
    if not raw:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


@router.get("/callback", status_code=status.HTTP_303_SEE_OTHER)
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    _rate_limited: None = Depends(_enforce_auth_rate_limit),
) -> Response:
    config = _config()
    transaction_id = _parse_transaction_cookie(
        request.cookies.get(config.login_transaction_cookie_name)
    )
    if (
        transaction_id is None
        or not code
        or not state
        or len(code) > _MAX_CALLBACK_PARAM_LENGTH
        or len(state) > _MAX_CALLBACK_PARAM_LENGTH
    ):
        logger.warning("auth_callback_rejected", extra={"auth_failure": "malformed_callback"})
        raise _bad_callback()

    try:
        consumed = consume_login_transaction(transaction_id, state)
    except LoginTransactionInvalidError:
        logger.warning("auth_callback_rejected", extra={"auth_failure": "invalid_transaction"})
        raise _bad_callback() from None

    try:
        provider = get_oidc_provider_config()
        endpoints = get_oidc_flow_endpoints()
    except (OIDCConfigurationError, LookupError) as exc:
        logger.error("auth_login_failed", extra={"auth_failure": type(exc).__name__})
        raise _auth_not_configured() from None

    try:
        id_token = exchange_authorization_code(
            provider,
            endpoints,
            code=code,
            code_verifier=consumed.code_verifier,
            redirect_uri=config.redirect_uri,
            client_secret=get_oidc_client_secret(),
        )
    except OIDCExchangeError as exc:
        logger.warning("auth_login_failed", extra={"auth_failure": "token_exchange_failed"})
        if exc.reason in ("provider unavailable",) or exc.reason.startswith("transport error"):
            raise _provider_unavailable() from None
        raise _provider_rejected() from None

    try:
        identity = validate_id_token(id_token, provider, expected_nonce=consumed.nonce)
    except TokenValidationError as exc:
        logger.warning("auth_login_failed", extra={"auth_failure": type(exc).__name__})
        raise unauthorized() from None

    user = get_or_create_user_for_external_identity(identity.issuer, identity.subject)
    session_record, raw_token = issue_session(user.id)

    logger.info(
        "auth_login_succeeded",
        extra={
            "issuer": identity.issuer,
            "user_id": str(user.id),
            "session_id": str(session_record.id),
        },
    )
    response = RedirectResponse(url=config.post_login_path, status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(response, config, raw_token)
    response.delete_cookie(
        key=config.login_transaction_cookie_name,
        path="/auth",
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
    )
    return response


# --- POST /auth/logout ----------------------------------------------------------


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(session: CoreSession = Depends(get_current_session)) -> Response:
    """Revokes the *current* session only (the existing, idempotent
    `revoke_session`) and clears the cookie. Requires a valid session --
    an unauthenticated or already-revoked credential gets the same 401
    every other route returns, and learns nothing about other sessions."""
    config = _config()
    revoke_session(session.id)
    logger.info(
        "auth_logout", extra={"user_id": str(session.user_id), "session_id": str(session.id)}
    )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_cookie(response, config, config.cookie_name)
    return response


# --- GET /auth/me ---------------------------------------------------------------


class CurrentUserResponse(BaseModel):
    user_id: uuid.UUID


@router.get("/me", response_model=CurrentUserResponse)
async def me(actor_id: uuid.UUID = Depends(get_current_actor)) -> CurrentUserResponse:
    """The minimum a frontend needs: the stable internal user id. No
    token, hash, provider claim, or tenant list is exposed -- which
    tenants this user may act in is answered per tenant by the existing
    membership-checked `/v1/tenants/{tenant_id}/...` routes."""
    return CurrentUserResponse(user_id=actor_id)
