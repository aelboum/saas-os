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
  `core/identity/models.py`).

Does NOT own: authorization/permissions (core/rbac, Phase 3.3), audit
logging (core/audit-log, Phase 3.4), or any HTTP/API surface (Phase 8).

`core/identity` never imports sqlalchemy directly (pyproject.toml's "Only
infra/db may import SQLAlchemy or psycopg directly" contract) and never
reads a secret from `os.environ` directly (docs/ADR/0012-secrets-management.md)
-- OIDC provider configuration flows through `infra.secrets` like every
other credential.
"""

from core.identity.errors import (
    DuplicateExternalIdentityError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidNonceError,
    InvalidSignatureError,
    LoginTransactionInvalidError,
    MalformedTokenError,
    MissingSubjectError,
    OIDCExchangeError,
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
    create_user,
    find_external_identity,
    get_membership,
    get_or_create_user_for_external_identity,
    get_user,
    link_external_identity,
    list_tenant_members,
)
from core.identity.sessions import issue_session, revoke_session, validate_session

__all__ = [
    "User",
    "ExternalIdentity",
    "Session",
    "TenantMembership",
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
