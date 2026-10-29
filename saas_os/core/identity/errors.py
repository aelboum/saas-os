"""Typed errors for `saas_os/core/identity` (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2).

Every error here carries only identifying metadata (a claim *name*, a
subject, a session id) -- never a raw token, a signing key, or a secret
value (docs/SECURITY.md: "no credential or token value ever logged").
"""

from __future__ import annotations

import uuid


class TokenValidationError(ValueError):
    """Base class for all ID token verification failures
    (`saas_os/core/identity/oidc.py`). Never includes the raw token string."""


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


class InactiveUserError(PermissionError):
    """Raised when a session would be issued to, or validated for, a user
    whose `is_active` is `False` (Foundation Authority & Evidence,
    ADR-0031): an inactive user is never an authenticated application
    actor. Checked live on every validation, so deactivation takes effect
    on the very next request for every existing session."""

    def __init__(self, user_id: uuid.UUID) -> None:
        self.user_id = user_id
        super().__init__(f"User {user_id} is not active.")


class SessionRetentionConfigurationError(ValueError):
    """RA-12-5: raised when a `saas_os/core/identity` session-retention environment
    variable holds an invalid value. Mirrors
    `saas_os.core.tenancy.errors.TenancyConfigurationError` exactly. Never carries
    a secret -- every session-retention tunable is a plain, non-secret
    operational value."""


class SessionRetentionBatchInvariantError(RuntimeError):
    """Raised if a single `saas_os.core.identity.session_retention` cleanup batch
    ever deletes more rows than its own configured batch size -- a defensive
    invariant, not an expected operational condition. Carries only counts
    (never a session id or token hash) -- see
    `saas_os.core.identity.session_retention._delete_one_batch()`'s own docstring
    for why this check exists."""


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
    path (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 security review).

    The message names neither the issuer nor the subject, which identify a
    person at the provider: an unhandled error is written, with its
    message and chain, to the API middleware's `unhandled_request_error`
    line and the request span. Both stay available as attributes."""

    def __init__(self, issuer: str, subject: str) -> None:
        self.issuer = issuer
        self.subject = subject
        super().__init__("External identity is already linked.")


class ServiceAccountNotFoundError(LookupError):
    """Raised when a `service_account_id` does not resolve within the
    given tenant -- deliberately the same error whether the service
    account truly doesn't exist or belongs to a different tenant, so this
    lookup itself never confirms or denies another tenant's data (mirrors
    `saas_os/core/rbac/errors.py::RoleNotFoundError`, architecture research Phase
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


# --- Invitation / membership lifecycle (architecture research: universal
# multi-tenant tenancy, Phase G) --------------------------------------------


class InvalidServiceAccountNameError(ValueError):
    """A service-account name the database cannot store (a control
    character). Raised before any write; the message never repeats the
    value."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Invalid service account name: {reason}.")


class InvalidExternalIdentityError(ValueError):
    """An `(issuer, subject)` pair the database cannot store or look up (a
    control character). Raised before any read or write; the message never
    repeats the value."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Invalid external identity: {reason}.")


class InvalidInvitationEmailError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Invalid invitation email: {reason}.")


class DuplicateInvitationError(ValueError):
    """Raised when a pending invitation already exists for this
    `(tenant_id, invited_email)` pair -- the real guard is the database's
    own partial unique index (`uq_invitations_live_unique`); this is
    defense in depth for the race-condition path, mirroring
    `DuplicateServiceAccountNameError`.

    The message does not repeat the email address (see
    `DuplicateExternalIdentityError`); it stays available as
    `invited_email`."""

    def __init__(self, tenant_id: uuid.UUID, invited_email: str) -> None:
        self.tenant_id = tenant_id
        self.invited_email = invited_email
        super().__init__(
            f"A pending invitation for this email already exists in tenant {tenant_id}."
        )


class InvitationNotFoundError(LookupError):
    def __init__(self, tenant_id: uuid.UUID, invitation_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.invitation_id = invitation_id
        super().__init__(f"Invitation {invitation_id} not found in tenant {tenant_id}.")


class InvitationAlreadyAcceptedError(ValueError):
    """Raised by `revoke_invitation()` -- an already-consumed invitation
    can never be revoked (`ck_invitations_not_accepted_and_revoked`)."""

    def __init__(self, invitation_id: uuid.UUID) -> None:
        self.invitation_id = invitation_id
        super().__init__(f"Invitation {invitation_id} has already been accepted.")


class InvitationNotAuthorizedError(PermissionError):
    """Raised when the requesting actor lacks the dedicated "manage
    invitations in this tenant" capability (architecture research Phase G
    section 9: "invitation creation/revocation must be tenant-scoped and
    authorized"). Covers both `create_invitation()` and
    `revoke_invitation()` -- a caller must not be able to distinguish "you
    may not manage invitations here" from any other reason, mirroring
    `saas_os/core/api_keys/errors.py::ApiKeyNotAuthorizedError`'s own
    non-distinguishing discipline."""

    def __init__(self, actor_user_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        self.actor_user_id = actor_user_id
        self.tenant_id = tenant_id
        super().__init__(
            f"User {actor_user_id} is not authorized to manage invitations in tenant {tenant_id}."
        )


class InvitationInvalidError(ValueError):
    """Raised by `accept_invitation()` for every failure mode -- unknown
    token, expired, revoked, or already accepted -- deliberately merged
    into one error (this class's own docstring: a bearer secret used in a
    URL must not let a caller probing it learn *why* a given token no
    longer works, mirroring `LoginTransactionInvalidError`). Never carries
    the raw token."""

    def __init__(self) -> None:
        super().__init__("Invitation is missing, expired, revoked, or already accepted.")


class MembershipNotFoundError(LookupError):
    def __init__(self, tenant_id: uuid.UUID, membership_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.membership_id = membership_id
        super().__init__(f"Membership {membership_id} not found in tenant {tenant_id}.")


class LastTenantAdministratorError(ValueError):
    """Raised when a mutation would leave a tenant that has an
    administrator with none (docs/ADR/0043-...,
    `saas_os/core/rbac/administrators.py`): suspending or revoking a
    membership, removing a role, revoking a permission, creating a deny
    grant or revoking a delegation. Nobody inside the tenant could restore
    anyone's access afterwards. Carries identifiers only."""

    def __init__(self, tenant_id: uuid.UUID, membership_id: uuid.UUID | None = None) -> None:
        self.tenant_id = tenant_id
        # The membership being suspended or revoked; `None` when the change
        # was to a role, a permission grant, a deny grant or a delegation.
        self.membership_id = membership_id
        super().__init__(f"Tenant {tenant_id} would be left without an active administrator.")


class InvalidMembershipTransitionError(ValueError):
    """Raised when a membership status transition is not permitted --
    e.g. reactivating a `REVOKED` membership, or accepting an invitation
    for a user whose existing membership is `SUSPENDED`/`REVOKED`
    (architecture research Phase G: "do not silently reactivate a revoked
    membership ... prefer fail-closed behavior where the correct
    semantics are ambiguous")."""

    def __init__(self, membership_id: uuid.UUID, from_status: str, to_status: str) -> None:
        self.membership_id = membership_id
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(
            f"Membership {membership_id} cannot transition from {from_status!r} to {to_status!r}."
        )


class InvalidUserStateError(ValueError):
    """A user is already in the state a platform operation would move it
    to (ADR-0045 section 11): deactivating an inactive user, reactivating
    an active one. Nothing changed. Carries identifiers only."""

    def __init__(self, user_id: uuid.UUID, state: str) -> None:
        self.user_id = user_id
        self.state = state
        super().__init__(f"User {user_id} is already {state}.")


class DeactivationRetryError(RuntimeError):
    """`deactivate_user` was rolled back on every attempt because a
    membership of the user appeared while it ran (ADR-0045 section 11c,
    step 6). Nothing changed: the user is still active and no credential
    was revoked. Retryable."""

    def __init__(self, user_id: uuid.UUID) -> None:
        self.user_id = user_id
        super().__init__(
            f"User {user_id} could not be deactivated: its tenant memberships changed "
            "while the operation ran. Nothing changed; retry."
        )
