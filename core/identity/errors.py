"""Typed errors for `core/identity` (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2).

Every error here carries only identifying metadata (a claim *name*, a
subject, a session id) -- never a raw token, a signing key, or a secret
value (docs/SECURITY.md: "no credential or token value ever logged").
"""

from __future__ import annotations

import uuid


class TokenValidationError(ValueError):
    """Base class for all ID token verification failures
    (`core/identity/oidc.py`). Never includes the raw token string."""


class MalformedTokenError(TokenValidationError):
    def __init__(self) -> None:
        super().__init__("ID token is malformed (not a well-formed JWT).")


class UnknownSigningKeyError(TokenValidationError):
    def __init__(self, kid: str | None) -> None:
        self.kid = kid
        super().__init__(f"No JWKS key found matching kid={kid!r}.")


class InvalidSignatureError(TokenValidationError):
    def __init__(self) -> None:
        super().__init__("ID token signature verification failed.")


class InvalidIssuerError(TokenValidationError):
    def __init__(self) -> None:
        super().__init__("ID token issuer does not match the expected issuer.")


class InvalidAudienceError(TokenValidationError):
    def __init__(self) -> None:
        super().__init__("ID token audience does not match the expected client.")


class TokenExpiredError(TokenValidationError):
    def __init__(self) -> None:
        super().__init__("ID token has expired.")


class InvalidNonceError(TokenValidationError):
    def __init__(self) -> None:
        super().__init__("ID token nonce does not match the expected value.")


class MissingSubjectError(TokenValidationError):
    def __init__(self) -> None:
        super().__init__("ID token is missing a required 'sub' claim.")


class UnsupportedAlgorithmError(TokenValidationError):
    def __init__(self, alg: str | None) -> None:
        self.alg = alg
        super().__init__(f"ID token uses an unsupported/unsafe algorithm: {alg!r}.")


class UserNotFoundError(LookupError):
    def __init__(self, user_id: uuid.UUID) -> None:
        self.user_id = user_id
        super().__init__(f"User {user_id} not found.")


class SessionNotFoundError(LookupError):
    def __init__(self) -> None:
        super().__init__("Session not found.")


class SessionExpiredError(ValueError):
    def __init__(self, session_id: uuid.UUID) -> None:
        self.session_id = session_id
        super().__init__(f"Session {session_id} has expired.")


class SessionRevokedError(ValueError):
    def __init__(self, session_id: uuid.UUID) -> None:
        self.session_id = session_id
        super().__init__(f"Session {session_id} has been revoked.")


class LoginTransactionInvalidError(ValueError):
    """P2.2: an OIDC callback could not be bound to a valid, unexpired,
    unused login transaction -- missing, unknown, expired, already
    consumed, or a `state` that does not match. One error for every case,
    deliberately (an attacker probing the callback must not learn which
    check failed). Never carries the state, nonce, or verifier value."""

    def __init__(self) -> None:
        super().__init__("Login transaction is missing, expired, already used, or mismatched.")


class OIDCExchangeError(RuntimeError):
    """P2.2: the server-side authorization-code -> token exchange with the
    OIDC provider failed (network error, non-2xx response, or a response
    without an ID token). Carries only a short, fixed classification --
    never the authorization code, the provider's response body, a token,
    or the client secret."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"OIDC token exchange failed: {reason}.")


class DuplicateExternalIdentityError(ValueError):
    """Raised if the same (issuer, subject) is ever linked to two
    different platform users -- should be structurally prevented by the
    unique constraint; this is defense in depth for the race-condition
    path (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 security review)."""

    def __init__(self, issuer: str, subject: str) -> None:
        self.issuer = issuer
        self.subject = subject
        super().__init__(f"External identity ({issuer!r}, {subject!r}) is already linked.")


class ServiceAccountNotFoundError(LookupError):
    """Raised when a `service_account_id` does not resolve within the
    given tenant -- deliberately the same error whether the service
    account truly doesn't exist or belongs to a different tenant, so this
    lookup itself never confirms or denies another tenant's data (mirrors
    `core/rbac/errors.py::RoleNotFoundError`, architecture research Phase
    E)."""

    def __init__(self, tenant_id: uuid.UUID, service_account_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.service_account_id = service_account_id
        super().__init__(f"Service account {service_account_id} not found in tenant {tenant_id}.")


class DuplicateServiceAccountNameError(ValueError):
    def __init__(self, tenant_id: uuid.UUID, name: str) -> None:
        self.tenant_id = tenant_id
        self.name = name
        super().__init__(f"Service account {name!r} already exists in tenant {tenant_id}.")
