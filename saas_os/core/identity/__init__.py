"""`saas_os/core/identity` -- users, external OIDC identities, sessions, and tenant
membership (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2;
docs/ADR/0005-identity-build-vs-buy.md).

Owns:
- the User entity (`core.users`) and ExternalIdentity linkage
  (`core.external_identities`) -- both global, `saas_os/core/identity/models.py`;
- OIDC ID token validation, standards-based and provider-agnostic
  (`saas_os/core/identity/oidc.py`, `saas_os/core/identity/provider.py`);
- platform session issuance/validation/revocation, hashed-at-rest
  (`saas_os/core/identity/sessions.py`), and the bounded, scheduled physical
  cleanup of expired/revoked session rows (RA-12-5,
  `saas_os/core/identity/session_retention.py`) -- distinct from the immediate,
  identity-scoped session deletion `saas_os/core/identity/erasure.py` performs;
- tenant membership linkage (`core.tenant_memberships`, RLS-protected,
  `saas_os/core/identity/models.py`);
- the `ServiceAccount` entity (`core.service_accounts`, RLS-protected,
  tenant-scoped machine identity -- architecture research Phase E)
  and its `ServiceAccountStatus` lifecycle (`ACTIVE`/`DISABLED`).
- `TenantMembership`'s own explicit `MembershipStatus` lifecycle
  (`ACTIVE`/`SUSPENDED`/`REVOKED`) and the `Invitation` entity
  (`core.invitations`, tenant-owned, RLS-protected -- architecture research
  Phase G: "Invitation / Membership Lifecycle"; Privacy Architecture Audit
  finding PRIV-01).

Does NOT own: authorization/permissions (saas_os/core/rbac, Phase 3.3), audit
logging (core/audit-log, Phase 3.4), any HTTP/API surface (`saas_os/api/auth`
owns the OIDC login/callback/logout routes and calls into this module), or a
service account's *role assignments* (`saas_os/core/rbac`'s `ServiceAccountRole`,
mirroring how `saas_os/core/rbac` owns `MembershipRole` for ordinary users, not
this module).

`saas_os/core/identity` never imports sqlalchemy directly (pyproject.toml's "Only
saas_os/infra/db may import SQLAlchemy or psycopg directly" contract) and never
reads a secret from `os.environ` directly (docs/ADR/0012-secrets-management.md)
-- OIDC provider configuration flows through `saas_os.infra.secrets` like every
other credential.
"""

from saas_os.core.identity.config import SessionRetentionConfig, get_session_retention_config
from saas_os.core.identity.errors import (
    DuplicateExternalIdentityError,
    DuplicateInvitationError,
    DuplicateServiceAccountNameError,
    InactiveUserError,
    InvalidAudienceError,
    InvalidInvitationEmailError,
    InvalidIssuerError,
    InvalidMembershipTransitionError,
    InvalidNonceError,
    InvalidSignatureError,
    InvitationAlreadyAcceptedError,
    InvitationInvalidError,
    InvitationNotAuthorizedError,
    InvitationNotFoundError,
    LastTenantAdministratorError,
    LoginTransactionInvalidError,
    MalformedTokenError,
    MembershipNotFoundError,
    MissingSubjectError,
    OIDCExchangeError,
    ServiceAccountNotFoundError,
    SessionExpiredError,
    SessionNotFoundError,
    SessionRetentionConfigurationError,
    SessionRevokedError,
    TokenExpiredError,
    TokenValidationError,
    UnknownSigningKeyError,
    UnsupportedAlgorithmError,
    UserNotFoundError,
)
from saas_os.core.identity.invitation_status import InvitationStatus, compute_invitation_status
from saas_os.core.identity.login_transactions import (
    ConsumedLogin,
    StartedLogin,
    begin_login_transaction,
    consume_login_transaction,
    purge_expired_login_transactions,
)
from saas_os.core.identity.models import (
    ExternalIdentity,
    Invitation,
    LoginTransaction,
    MembershipStatus,
    ServiceAccount,
    ServiceAccountStatus,
    Session,
    TenantMembership,
    User,
)
from saas_os.core.identity.oidc import (
    OIDCIdentityProvider,
    VerifiedIdentity,
    build_authorization_url,
    exchange_authorization_code,
    get_identity_provider,
    validate_id_token,
)
from saas_os.core.identity.provider import (
    IdentityProvider,
    OIDCConfigurationError,
    OIDCFlowEndpoints,
    OIDCProviderConfig,
    get_oidc_client_secret,
    get_oidc_flow_endpoints,
    get_oidc_provider_config,
)
from saas_os.core.identity.service import (
    LockedMembership,
    accept_invitation,
    add_tenant_membership,
    create_invitation,
    create_service_account,
    create_user,
    disable_service_account,
    enable_service_account,
    find_external_identity,
    find_user_id_for_external_identity_in_transaction,
    get_invitation,
    get_membership,
    get_or_create_user_for_external_identity,
    get_or_create_user_id_for_external_identity_in_transaction,
    get_service_account,
    get_user,
    link_external_identity,
    list_invitations_for_tenant,
    list_service_accounts,
    list_tenant_members,
    lock_membership,
    lock_service_account_status,
    lock_user_is_active,
    reactivate_membership,
    revoke_invitation,
    revoke_membership,
    suspend_membership,
)
from saas_os.core.identity.session_retention import (
    SESSION_CLEANUP_JOB_FUNCTIONS,
    SESSION_CLEANUP_JOB_NAME,
    SessionCleanupResult,
    cleanup_expired_sessions,
)
from saas_os.core.identity.sessions import issue_session, revoke_session, validate_session

__all__ = [
    "User",
    "ExternalIdentity",
    "Session",
    "TenantMembership",
    "MembershipStatus",
    "Invitation",
    "InvitationStatus",
    "compute_invitation_status",
    "ServiceAccount",
    "ServiceAccountStatus",
    "LoginTransaction",
    "VerifiedIdentity",
    "OIDCProviderConfig",
    "OIDCFlowEndpoints",
    "OIDCConfigurationError",
    "IdentityProvider",
    "OIDCIdentityProvider",
    "get_identity_provider",
    "get_oidc_provider_config",
    "get_oidc_flow_endpoints",
    "get_oidc_client_secret",
    "validate_id_token",
    "build_authorization_url",
    "exchange_authorization_code",
    "StartedLogin",
    "ConsumedLogin",
    "begin_login_transaction",
    "consume_login_transaction",
    "purge_expired_login_transactions",
    "LoginTransactionInvalidError",
    "OIDCExchangeError",
    "create_user",
    "get_user",
    "find_external_identity",
    "link_external_identity",
    "get_or_create_user_for_external_identity",
    "get_or_create_user_id_for_external_identity_in_transaction",
    "find_user_id_for_external_identity_in_transaction",
    "add_tenant_membership",
    "get_membership",
    "LockedMembership",
    "lock_user_is_active",
    "lock_membership",
    "lock_service_account_status",
    "list_tenant_members",
    "suspend_membership",
    "reactivate_membership",
    "revoke_membership",
    "MembershipNotFoundError",
    "InvalidMembershipTransitionError",
    "LastTenantAdministratorError",
    "create_invitation",
    "get_invitation",
    "list_invitations_for_tenant",
    "revoke_invitation",
    "accept_invitation",
    "InvalidInvitationEmailError",
    "DuplicateInvitationError",
    "InvitationNotFoundError",
    "InvitationAlreadyAcceptedError",
    "InvitationInvalidError",
    "InvitationNotAuthorizedError",
    "create_service_account",
    "get_service_account",
    "list_service_accounts",
    "disable_service_account",
    "enable_service_account",
    "ServiceAccountNotFoundError",
    "DuplicateServiceAccountNameError",
    "issue_session",
    "validate_session",
    "revoke_session",
    "SessionRetentionConfig",
    "get_session_retention_config",
    "SessionRetentionConfigurationError",
    "SessionCleanupResult",
    "cleanup_expired_sessions",
    "SESSION_CLEANUP_JOB_FUNCTIONS",
    "SESSION_CLEANUP_JOB_NAME",
    "TokenValidationError",
    "MalformedTokenError",
    "UnknownSigningKeyError",
    "InvalidSignatureError",
    "InvalidIssuerError",
    "InvalidAudienceError",
    "TokenExpiredError",
    "InvalidNonceError",
    "MissingSubjectError",
    "UnsupportedAlgorithmError",
    "SessionNotFoundError",
    "SessionExpiredError",
    "SessionRevokedError",
    "InactiveUserError",
    "DuplicateExternalIdentityError",
    "UserNotFoundError",
]
