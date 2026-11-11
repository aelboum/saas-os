"""The platform-permission vocabulary
(docs/ADR/0045-installation-scoped-platform-authority.md section 4).

A closed enumeration with exactly thirty members: eight oversight,
twenty-one operations, one authority (four `platform.ai_*` members were added
by ADR-0054 Phase AI-C, decision O2/Q9, `platform.ai_usage:read` by
Phase AI-D with its read operation, `platform.outbox:replay` by the
ADR-0045 amendment of 2026-10-31, `platform.webhook_secret:reencrypt` by
the proposed ADR-0045 amendment of 2026-11-01 (finding F7),
`platform.permission_grant:apply` by the ADR-0045 amendment of 2026-11-01,
ADR 0060, and `platform.security_retention:report` and
`platform.security_retention_hold:manage` by the ADR-0045 amendment of
2026-11-02, owner decision A of that day: least-privilege permissions for
security-record retention, neither implied by nor implying
`platform.permission_grant:apply`, and `platform.ai_tenant_hold:manage` by
the ADR-0054 amendment of 2026-11-09, owner decision of that day: a
permission of its own, not implied by `platform.ai_policy:manage`, to place
or release the platform hold on one tenant's AI, and
`platform.ai_budget:manage` by the ADR-0054 amendment of 2026-11-10 (Gap
21b, owner decisions of 2026-11-09): set plan AI budgets, raise one
tenant's budget by an override, and release a reservation whose outcome is
unknown). It is deliberately *not* stored in
`core.permissions`, so a platform permission can never be attached to a
tenant role, delegated, denied, or satisfied by support access.

Holding one permission implies no other. There is no permission for tenant
purge, identity erasure, migrations, backup, owner bootstrap or recovery:
those are infrastructure operations and are never granted to a person.

Adding a member is a reviewed decision with three consequences that tests
pin: the `ck_platform_grants_permission` CHECK in a new migration, a row
in `saas_os.core.platform_authority.operations.PLATFORM_OPERATIONS`, and an
explicit placement in exactly one of the bootstrap literals
(`saas_os/api/platform_bootstrap.py`). A new permission is never granted to
an existing operator automatically.
"""

from __future__ import annotations

import enum


class PlatformPermission(enum.StrEnum):
    # --- Oversight (read-only, data-minimized) --------------------------------
    TENANT_READ = "platform.tenant:read"
    USER_READ = "platform.user:read"
    OPERATOR_READ = "platform.operator:read"
    AUDIT_READ = "platform.audit:read"
    BILLING_READ = "platform.billing:read"
    FEATURE_FLAG_READ = "platform.feature_flag:read"
    AI_CONFIG_READ = "platform.ai_config:read"
    AI_USAGE_READ = "platform.ai_usage:read"
    # --- Operations (platform or tenant-lifecycle state; no tenant data) ------
    TENANT_CREATE = "platform.tenant:create"
    TENANT_SUSPEND = "platform.tenant:suspend"
    TENANT_REACTIVATE = "platform.tenant:reactivate"
    TENANT_MOVE = "platform.tenant:move"
    TENANT_DELETE = "platform.tenant:delete"
    USER_DEACTIVATE = "platform.user:deactivate"
    USER_REACTIVATE = "platform.user:reactivate"
    SESSION_REVOKE = "platform.session:revoke"
    API_KEY_REVOKE = "platform.api_key:revoke"  # pragma: allowlist secret
    FEATURE_FLAG_DEFINE = "platform.feature_flag:define"
    FEATURE_FLAG_OVERRIDE = "platform.feature_flag:override"
    AI_PROVIDER_MANAGE = "platform.ai_provider:manage"
    AI_ENDPOINT_TRUST_MANAGE = "platform.ai_endpoint_trust:manage"
    AI_POLICY_MANAGE = "platform.ai_policy:manage"
    AI_TENANT_HOLD_MANAGE = "platform.ai_tenant_hold:manage"
    AI_BUDGET_MANAGE = "platform.ai_budget:manage"
    OUTBOX_REPLAY = "platform.outbox:replay"
    WEBHOOK_SECRET_REENCRYPT = "platform.webhook_secret:reencrypt"  # pragma: allowlist secret
    PERMISSION_GRANT_APPLY = "platform.permission_grant:apply"
    # Security-record retention (ADR-0045 amendment of 2026-11-02): the
    # read-only eligibility report (and the attribution of a manual
    # deletion of expired rows), and placing or releasing a legal hold.
    SECURITY_RETENTION_REPORT = "platform.security_retention:report"
    SECURITY_RETENTION_HOLD_MANAGE = "platform.security_retention_hold:manage"
    # --- Authority (who holds platform authority) -----------------------------
    AUTHORITY_MANAGE = "platform.authority:manage"


# The capability that makes an operator a *platform owner*: whoever can
# manage platform authority can grant every other platform permission, so
# it is the one a deployment cannot recover from inside once nobody holds
# it (ADR-0045 section 3; the last-active-platform-owner invariant).
OWNER_PERMISSION = PlatformPermission.AUTHORITY_MANAGE

PLATFORM_PERMISSION_VALUES: frozenset[str] = frozenset(p.value for p in PlatformPermission)
