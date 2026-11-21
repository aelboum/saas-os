"""The OIDC Authorization Code Flow routes (P2.2). See `saas_os/api/auth/__init__.py`
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

    POST /auth/logout/redirect               (ADR-0064; an HTML form post)
        same-origin check, always             (403 otherwise)
        revoke_session_for_logout(cookie)     (committed first; takes the ID token)
        clear the cookie; 303 -> end_session_endpoint?client_id&
            post_logout_redirect_uri&id_token_hint, or the local path

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
tenant exists, so the tenant-keyed chain in `saas_os/api/dependencies.py` cannot
apply; they use the *same* `saas_os.infra.ratelimit.enforce_rate_limit()` with a
`auth:<client address>` key and the same fail-closed 503 on backend
failure. No second limiter.

**CSRF**: the callback is protected by the single-use, cookie-bound
`state`. Logout is a `POST`: when its credential is the session cookie, the
request must come from this application's own origin
(`saas_os/api/dependencies.py`, docs/ADR/0044-...) -- `SameSite=Lax` alone
does not stop a sibling subdomain; when its credential is an explicit
`Authorization` header, no origin is required.

**Audit**: `saas_os.core.audit_log` requires a tenant on every row
(`saas_os/core/audit_log/models.py`: no tenant-less audit table exists, and
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

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from saas_os.api.auth.config import (
    AuthHttpConfig,
    get_auth_http_config,
    resolve_client_address,
)
from saas_os.api.dependencies import (
    get_current_actor,
    get_current_session,
    require_same_origin_browser_post,
    revoke_cookie_session_for_logout,
)
from saas_os.api.errors import service_unavailable, unauthorized
from saas_os.api.route_policy import public_route
from saas_os.core.identity import (
    InactiveUserError,
    OIDCConfigurationError,
    begin_login_transaction,
    consume_login_transaction,
    get_identity_provider,
    get_or_create_user_for_external_identity,
    issue_session,
    revoke_session,
)
from saas_os.core.identity.errors import (
    LoginTransactionInvalidError,
    OIDCExchangeError,
    TokenValidationError,
)
from saas_os.core.identity.models import Session as CoreSession
from saas_os.infra.ratelimit import (
    RateLimitBackendError,
    RateLimitExceededError,
    enforce_rate_limit,
    get_ratelimit_config,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_SESSION_COOKIE_MAX_AGE_SECONDS = (
    12 * 60 * 60
)  # matches saas_os.core.identity.sessions' default lifetime
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
    return resolve_client_address(request, trust_proxy_headers=config.trust_proxy_headers)


async def _enforce_auth_rate_limit(
    request: Request, config: AuthHttpConfig = Depends(_config)
) -> None:
    """Pre-authentication rate limit for `/auth/login` and `/auth/callback`
    -- the existing limiter, keyed by client address (module docstring).
    Fails closed (503) exactly like `saas_os.api.dependencies._enforce_rate_limit_for_route`."""
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


@router.get(
    "/login",
    include_in_schema=True,
    status_code=status.HTTP_303_SEE_OTHER,
    dependencies=[Depends(public_route("OIDC login entry: the caller has no session yet"))],
)
async def login(
    request: Request, _rate_limited: None = Depends(_enforce_auth_rate_limit)
) -> Response:
    config = _config()
    try:
        identity_provider = get_identity_provider()
    except (OIDCConfigurationError, LookupError) as exc:
        logger.error("auth_login_failed", extra={"auth_failure": type(exc).__name__})
        raise _auth_not_configured() from None

    started = begin_login_transaction()
    url = identity_provider.build_authorization_url(
        redirect_uri=config.redirect_uri,
        state=started.state,
        nonce=started.nonce,
        code_challenge=started.code_challenge,
    )
    logger.info(
        "auth_login_started",
        extra={
            "issuer": identity_provider.get_config().issuer,
            "login_transaction_id": str(started.transaction_id),
        },
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


@router.get(
    "/callback",
    status_code=status.HTTP_303_SEE_OTHER,
    dependencies=[
        Depends(
            public_route(
                "OIDC callback: authenticated in-handler by the login transaction, "
                "state and ID token, not by a session"
            )
        )
    ],
)
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
        identity_provider = get_identity_provider()
    except (OIDCConfigurationError, LookupError) as exc:
        logger.error("auth_login_failed", extra={"auth_failure": type(exc).__name__})
        raise _auth_not_configured() from None

    try:
        id_token = identity_provider.exchange_authorization_code(
            code=code,
            code_verifier=consumed.code_verifier,
            redirect_uri=config.redirect_uri,
        )
    except OIDCExchangeError as exc:
        logger.warning("auth_login_failed", extra={"auth_failure": "token_exchange_failed"})
        if exc.reason in ("provider unavailable",) or exc.reason.startswith("transport error"):
            raise _provider_unavailable() from None
        raise _provider_rejected() from None

    try:
        identity = identity_provider.validate_id_token(id_token, expected_nonce=consumed.nonce)
    except TokenValidationError as exc:
        logger.warning("auth_login_failed", extra={"auth_failure": type(exc).__name__})
        raise unauthorized() from None

    user = get_or_create_user_for_external_identity(identity.issuer, identity.subject)
    try:
        # ADR-0046: only an email the provider verified is kept, on the
        # session, for accepting an invitation addressed to it.
        session_record, raw_token = issue_session(
            user.id,
            verified_email=identity.email if identity.email_verified else None,
            # ADR-0049: what the provider asserted about this login.
            multi_factor=identity.multi_factor,
            provider_authenticated_at=identity.authenticated_at,
            # ADR-0064: kept (encrypted) only when the browser logout will
            # send it to the provider as `id_token_hint`.
            id_token_hint=id_token if config.post_logout_redirect_uri is not None else None,
        )
    except InactiveUserError:
        # ADR-0031: an inactive user authenticates at the IdP but never
        # becomes an application actor -- no session is issued.
        logger.warning("auth_login_failed", extra={"auth_failure": "inactive_user"})
        raise unauthorized() from None

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


# --- POST /auth/logout/redirect (ADR-0064) --------------------------------------


@router.post(
    "/logout/redirect",
    status_code=status.HTTP_303_SEE_OTHER,
    dependencies=[
        Depends(
            public_route(
                "browser logout: a missing or stale session is still logged out; "
                "same-origin is enforced in-handler for every request"
            )
        )
    ],
)
async def logout_redirect(request: Request) -> Response:
    """ADR-0064: the browser logout, posted by an ordinary HTML form.

    1. Same-origin check (ADR-0044) on every request, cookie or not: 403
       otherwise, and nothing changes.
    2. The session the cookie names, if not yet revoked (valid, or expired:
       its provider session may still be alive), is revoked and its stored
       ID token taken out of the row, in one committed transaction -- before
       anything else happens, so nothing that follows (an unreachable
       provider, a failed discovery) can leave it usable.
    3. The cookie is cleared on every outcome.
    4. With `OIDC_POST_LOGOUT_REDIRECT_URI` configured and an
       `end_session_endpoint` discovered: 303 to the provider, which ends its
       own session for this client and returns the browser to that URI.
       Otherwise: 303 to the same-origin local path.

    The ID token appears only in that `Location` header -- never in a log,
    a body, or a script-readable value. Idempotent: a repeat with no valid
    session still clears the cookie and redirects; it revokes nothing."""
    require_same_origin_browser_post(request)
    config = _config()
    logger.info("auth_logout_initiated", extra={"logout_route": "redirect"})
    revocation = await revoke_cookie_session_for_logout(request.cookies.get(config.cookie_name))

    id_token_hint: str | None = None
    if revocation is not None:
        id_token_hint = revocation.id_token_hint
        logger.info(
            "auth_logout_local_completed",
            extra={"user_id": str(revocation.user_id), "session_id": str(revocation.session_id)},
        )
    else:
        logger.info("auth_logout_local_completed", extra={"logout_session": "none"})

    destination = config.post_logout_local_path
    if config.post_logout_redirect_uri is not None:
        try:
            end_session_url = get_identity_provider().build_end_session_url(
                post_logout_redirect_uri=config.post_logout_redirect_uri,
                id_token_hint=id_token_hint,
            )
        except (OIDCConfigurationError, LookupError) as exc:
            # Discovery failed: the provider is unreachable or misconfigured.
            # The SaaS-OS session is already revoked; only the provider's
            # session survives, as it would have before ADR-0064.
            logger.warning(
                "auth_logout_idp_unavailable", extra={"auth_failure": type(exc).__name__}
            )
            end_session_url = None
        if end_session_url is not None:
            destination = end_session_url
            logger.info(
                "auth_logout_idp_redirected",
                extra={"logout_id_token_hint": id_token_hint is not None},
            )
        else:
            logger.info("auth_logout_local_only", extra={"logout_reason": "no_end_session"})

    response = RedirectResponse(url=destination, status_code=status.HTTP_303_SEE_OTHER)
    _clear_cookie(response, config, config.cookie_name)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
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
