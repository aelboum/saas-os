"""`api/auth` -- the browser/client authentication HTTP surface (P2.2):
OIDC Authorization Code Flow login, callback, logout, and the current-user
read.

Orchestration only. Every security-relevant step is an existing,
already-tested `core.identity` primitive -- login transactions
(`begin_login_transaction`/`consume_login_transaction`), ID-token
validation (`validate_id_token`, unchanged RS256/ES256 allowlist and
algorithm-confusion defense), user mapping
(`get_or_create_user_for_external_identity`, keyed on issuer+subject),
session issuance/revocation (`issue_session`/`revoke_session`, hashed at
rest). This package inserts no session rows, parses no tokens, trusts no
caller-supplied user or tenant id, and adds no second authentication or
session mechanism: the cookie it sets carries the very same session
secret `api.dependencies.get_current_actor()` has always validated via
`Authorization: Bearer`, now readable from a cookie too.

Authentication establishes identity only. Tenant authority still comes
exclusively from `api.dependencies.get_tenant_context()`'s membership
check and `core.rbac.can()` -- a freshly logged-in user with no
membership reaches no tenant route (404, non-enumerating), exactly as
before P2.2.

Routes (mounted at the app root, outside `/v1`, like `api/health.py`):

    GET  /auth/login      -> 303 to the provider (state + nonce + PKCE S256)
    GET  /auth/callback   -> validates, exchanges, issues session, 303 home
    POST /auth/logout     -> revokes the current session, clears the cookie
    GET  /auth/me         -> {"user_id": ...} for the current session
"""

from api.auth.routes import router

__all__ = ["router"]
