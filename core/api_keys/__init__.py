"""`core/api_keys` -- API key issuance, scoping, rotation, and revocation
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.1; docs/ARCHITECTURE.md section 4:
"API key issuance, scoping, rotation, revocation").

The physical directory/package name uses an underscore
(`core/api_keys/`), not the hyphen `docs/ARCHITECTURE.md` section 3's
diagram uses (`core/api-keys/`) -- a hyphen is not valid inside a Python
dotted import path, the same reason `core/audit-log/` maps to the
`core.audit_log` import name (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4).

Owns:
- the `ApiKey` entity (`core.api_keys`, `core/api_keys/models.py`) --
  global (like `core.sessions`), not RLS-scoped, for the same structural
  reason: a bearer credential must be resolvable before its tenant is
  known. A composite foreign key to `core.tenant_memberships` (human-owned
  key) or, architecture research Phase E, `core.service_accounts`
  (machine-owned key) is this table's RLS-equivalent integrity guarantee
  instead.
- `create_api_key()`, `validate_api_key()`, `get_api_key()`,
  `list_api_keys()`, `revoke_api_key()`, `rotate_api_key()`
  (`core/api_keys/service.py`; Phase 4.1) plus, for machine credentials
  (Phase E), the explicitly `can()`-gated `create_service_account_api_key()`
  and `revoke_service_account_api_key()`.

"Scoping" (the roadmap's own word for this phase's objective) means: a key
resolves to a `(tenant_id, user_id)` pair usable exactly the way a
validated session already is -- a caller then evaluates
`core.rbac.can(actor_id=user_id, tenant_id=tenant_id, ...)` for
authorization, the same chokepoint every other principal in this
platform uses. `core/api_keys` does not implement its own parallel
permission-grant mechanism.

Does NOT own: authentication middleware or any HTTP/API surface (Phase 8
-- "a revoked key is rejected by the auth chokepoint" is this phase's own
roadmap entry's *deferred* test, explicitly gated on that middleware
existing), authorization decisions (core/rbac), or audit-log storage
(core/audit_log) -- it calls that module's published `record()` for the
two cases the roadmap and docs/SECURITY.md section 8 require, nothing more.

`core/api_keys` never imports sqlalchemy directly (pyproject.toml's "Only
infra/db may import SQLAlchemy or psycopg directly" contract).
"""

from core.api_keys.errors import (
    ApiKeyNotAuthorizedError,
    ApiKeyNotFoundError,
    ExpiredApiKeyError,
    InactiveServiceAccountError,
    InvalidApiKeyError,
    InvalidApiKeyNameError,
    RevokedApiKeyError,
    ServiceAccountRequiredError,
    TenantMembershipRequiredError,
)
from core.api_keys.models import ApiKey
from core.api_keys.service import (
    create_api_key,
    create_service_account_api_key,
    get_api_key,
    list_api_keys,
    revoke_api_key,
    revoke_service_account_api_key,
    rotate_api_key,
    validate_api_key,
)

__all__ = [
    "ApiKey",
    "create_api_key",
    "create_service_account_api_key",
    "validate_api_key",
    "get_api_key",
    "list_api_keys",
    "revoke_api_key",
    "revoke_service_account_api_key",
    "rotate_api_key",
    "ApiKeyNotFoundError",
    "InvalidApiKeyError",
    "InvalidApiKeyNameError",
    "RevokedApiKeyError",
    "ExpiredApiKeyError",
    "InactiveServiceAccountError",
    "ApiKeyNotAuthorizedError",
    "ServiceAccountRequiredError",
    "TenantMembershipRequiredError",
]
