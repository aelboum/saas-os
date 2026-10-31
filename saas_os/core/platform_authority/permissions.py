"""The platform-permission vocabulary
(docs/ADR/0045-installation-scoped-platform-authority.md section 4).

A closed enumeration with exactly twenty-four members: eight oversight,
fifteen operations, one authority (four `platform.ai_*` members were added
by ADR-0054 Phase AI-C, decision O2/Q9, `platform.ai_usage:read` by
Phase AI-D with its read operation, and `platform.outbox:replay` by the
ADR-0045 amendment of 2026-10-31). It is deliberately *not* stored in
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
    API_KEY_REVOKE = "platform.api_key:revoke"  # pragma: allowlist secret -- a permission name
    FEATURE_FLAG_DEFINE = "platform.feature_flag:define"
    FEATURE_FLAG_OVERRIDE = "platform.feature_flag:override"
    AI_PROVIDER_MANAGE = "platform.ai_provider:manage"
    AI_ENDPOINT_TRUST_MANAGE = "platform.ai_endpoint_trust:manage"
    AI_POLICY_MANAGE = "platform.ai_policy:manage"
    OUTBOX_REPLAY = "platform.outbox:replay"
    # --- Authority (who holds platform authority) -----------------------------
    AUTHORITY_MANAGE = "platform.authority:manage"


# The capability that makes an operator a *platform owner*: whoever can
# manage platform authority can grant every other platform permission, so
# it is the one a deployment cannot recover from inside once nobody holds
# it (ADR-0045 section 3; the last-active-platform-owner invariant).
OWNER_PERMISSION = PlatformPermission.AUTHORITY_MANAGE

PLATFORM_PERMISSION_VALUES: frozenset[str] = frozenset(p.value for p in PlatformPermission)
