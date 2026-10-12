"""Permissions the opt-in capability routers gate on (docs/ADR/0040-...).

Each router's route policy is `saas_os.api.dependencies.require_permission`
with one of the pairs below. Where a Core function already enforces a
permission, the route uses that same pair -- the route adds no second
policy, it only refuses earlier. Three pairs are new, because the Core
function behind them has no authorization of its own and an HTTP route
would otherwise be its only gate:

- `membership:read` and `invitation:read` -- Core's list functions take no
  caller (`saas_os.core.identity.list_tenant_members`,
  `list_invitations_for_tenant`).
- `api_key:self_manage` -- `saas_os.core.api_keys.create_api_key` lets any
  active member issue a key to themselves, with no permission. Over HTTP
  that capability is default-deny: a tenant grants `api_key:self_manage`
  to the roles whose members may hold keys. It covers a member's *own*
  keys only; Core still decides every mutation.

`membership`, `invitation` and `api_key` are authority resources
(`saas_os.core.rbac.authorization.AUTHORITY_RESOURCES`), so a
support-access session can never satisfy any of these, whatever the
action.

`require_permission` evaluates a permission but does not create it.
`register_capability_permissions()` puts every pair in the shared
catalog so a tenant's roles can be granted them; call it once per
deployment, after migrations. It grants nothing.
"""

from __future__ import annotations

from saas_os.core.rbac import register_permission

MEMBERSHIP = "membership"
INVITATION = "invitation"
API_KEY = "api_key"  # pragma: allowlist secret -- a permission resource name
BILLING_SUBSCRIPTION = "billing.subscription"
BILLING_ACCOUNT = "billing.account"

READ = "read"
CREATE = "create"
REVOKE = "revoke"
SUSPEND = "suspend"
REACTIVATE = "reactivate"
SELF_MANAGE = "self_manage"
CANCEL = "cancel"

CAPABILITY_PERMISSIONS: tuple[tuple[str, str], ...] = (
    (MEMBERSHIP, READ),
    (MEMBERSHIP, SUSPEND),
    (MEMBERSHIP, REACTIVATE),
    (MEMBERSHIP, REVOKE),
    (INVITATION, READ),
    (INVITATION, CREATE),
    (INVITATION, REVOKE),
    (API_KEY, SELF_MANAGE),
    (BILLING_SUBSCRIPTION, READ),
    (BILLING_SUBSCRIPTION, CREATE),
    (BILLING_SUBSCRIPTION, CANCEL),
    (BILLING_ACCOUNT, READ),
)


def register_capability_permissions() -> None:
    """Idempotent. Registers every pair the capability routers gate on."""
    for resource, action in CAPABILITY_PERMISSIONS:
        register_permission(resource, action)
