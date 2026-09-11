"""`core/identity` -- users, external OIDC identities, sessions, and tenant
membership (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2;
docs/ADR/0005-identity-build-vs-buy.md).

Owns:
- the User entity (`core.users`) and ExternalIdentity linkage
  (`core.external_identities`) -- both global, `core/identity/models.py`;
- OIDC ID token validation, standards-based and provider-agnostic
  (`core/identity/oidc.py`, `core/identity/provider.py`);
- platform session issuance/validation/revocation, hashed-at-rest
  (`core/identity/sessions.py`);
- tenant membership linkage (`core.tenant_memberships`, RLS-protected,
  `core/identity/models.py`);
- the `ServiceAccount` entity (`core.service_accounts`, RLS-protected,
  tenant-scoped machine identity -- architecture research Phase E)
  and its `ServiceAccountStatus` lifecycle (`ACTIVE`/`DISABLED`).

Does NOT own: authorization/permissions (core/rbac, Phase 3.3), audit
logging (core/audit-log, Phase 3.4), any HTTP/API surface (Phase 8), or a
service account's *role assignments* (`core/rbac`'s `ServiceAccountRole`,
mirroring how `core/rbac` owns `MembershipRole` for ordinary users, not
this module).

`core/identity` never imports sqlalchemy directly (pyproject.toml's "Only
infra/db may import SQLAlchemy or psycopg directly" contract) and never
reads a secret from `os.environ` directly (docs/ADR/0012-secrets-management.md)
-- OIDC provider configuration flows through `infra.secrets` like every
other credential.
"""

from core.identity.errors import (
    DuplicateExternalIdentityError,
    DuplicateServiceAccountNameError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidNonceError,
    InvalidSignatureError,
    LoginTransactionInvalidError,
    MalformedTokenError,
    MissingSubjectError,
    OIDCExchangeError,
    ServiceAccountNotFoundError,
    SessionExpiredError,
    SessionNotFoundError,
    SessionRevokedError,
    TokenExpiredError,
    TokenValidationError,
    UnknownSigningKeyError,
    UnsupportedAlgorithmError,
    UserNotFoundError,
)
from core.identity.login_transactions import (
    ConsumedLogin,
    StartedLogin,
    begin_login_transaction,
    consume_login_transaction,
    purge_expired_login_transactions,
)
from core.identity.models import (
    ExternalIdentity,
    LoginTransaction,
    ServiceAccount,
    ServiceAccountStatus,
    Session,
    TenantMembership,
    User,
)
from core.identity.oidc import (
    VerifiedIdentity,
    build_authorization_url,
    exchange_authorization_code,
    validate_id_token,
)
from core.identity.provider import (
    OIDCConfigurationError,
    OIDCFlowEndpoints,
    OIDCProviderConfig,
    get_oidc_client_secret,
    get_oidc_flow_endpoints,
    get_oidc_provider_config,
)
from core.identity.service import (
    add_tenant_membership,
    create_service_account,
    create_user,
    disable_service_account,
    enable_service_account,
    find_external_identity,
    get_membership,
    get_or_create_user_for_external_identity,
    get_service_account,
    get_user,
    link_external_identity,
    list_service_accounts,
    list_tenant_members,
)
from core.identity.sessions import issue_session, revoke_session, validate_session

__all__ = [
    "User",
    "ExternalIdentity",
    "Session",
    "TenantMembership",
    "ServiceAccount",
    "ServiceAccountStatus",
    "LoginTransaction",
    "VerifiedIdentity",
    "OIDCProviderConfig",
    "OIDCFlowEndpoints",
    "OIDCConfigurationError",
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
    "add_tenant_membership",
    "get_membership",
    "list_tenant_members",
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
    "DuplicateExternalIdentityError",
    "UserNotFoundError",
]
