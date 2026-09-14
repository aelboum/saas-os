"""Retention classification for tenant-related Core data (PRIV-03 Phase P4).

Code metadata, not a runtime engine: this module declares what the purge
architecture *does* with each table once a tenant is purged
(`core/tenancy/service.py::purge_tenant()`), so the decision is explicit,
reviewable, and testable against the implementation -- it never executes
anything. There is no retention period here: no legal or financial
retention window has been decided, and this module must not invent one.

Classes
-------
SECURITY_RETAIN    Security/forensic evidence. Never deleted by purge; the
                   runtime role cannot delete it at all where the schema
                   revokes DELETE (`core.audit_log`). Survives the tenant's
                   operational data and references the tombstone.
FINANCIAL_RETAIN   Financial/accounting evidence. Retained as-is by purge
                   until an externally decided retention policy exists.
                   No provider-side cancellation is performed by purge.
OPERATIONAL_PURGE  Tenant-owned operational/configuration data with no
                   retention value once the tenant is closed. Emptied by
                   one of `PURGE_STEPS`; credentials are revoked/disabled
                   before removal. A row that immutable audit evidence
                   references (`delegation_grants`, `service_accounts`) is
                   the one exception -- kept revoked/disabled, because the
                   audit row's `NO ACTION` foreign key forbids its deletion
                   and audit evidence is never deleted to make room.
DEFERRED_POLICY    Deliberately untouched by purge because the required
                   architectural/policy decision has not been made:
                   usage events (no rollup/aggregation-then-delete
                   mechanism exists; only read-time `aggregate_usage()`),
                   billing provider cancellation (an actor-bearing,
                   provider-calling operation, not a purge step), and every
                   AI Control Plane table (P5 owns drain and disposition).
GLOBAL_IDENTITY    Not tenant-owned. A user may belong to many tenants;
                   purging one tenant never touches these.
TOMBSTONE          The `core.tenants` row itself: retained forever as the
                   `PURGED` tombstone so every retained foreign key stays
                   valid, the lifecycle stays reconstructible, the tenant
                   id can never be reused, and the hierarchy
                   (`parent_id`/`tenant_ancestry`) keeps its shape.
                   Minimized to `name = "purged-<id>"` -- the only
                   customer-identifying column it has.
"""

from __future__ import annotations

import enum
from types import MappingProxyType


class RetentionClass(enum.StrEnum):
    SECURITY_RETAIN = "security_retain"
    FINANCIAL_RETAIN = "financial_retain"
    OPERATIONAL_PURGE = "operational_purge"
    DEFERRED_POLICY = "deferred_policy"
    GLOBAL_IDENTITY = "global_identity"
    TOMBSTONE = "tombstone"


# Every table that carries a tenant id or that a tenant purge must reason
# about, and what the purge architecture does with it. Keyed by
# schema-qualified table name; values are the class above. The mapping is
# read-only on purpose -- a classification is a reviewed decision, not
# runtime state.
RETENTION_CLASSIFICATION: MappingProxyType[str, RetentionClass] = MappingProxyType(
    {
        # --- retained evidence ------------------------------------------------
        "core.audit_log": RetentionClass.SECURITY_RETAIN,
        "core.support_access_requests": RetentionClass.SECURITY_RETAIN,
        "core.billing_subscriptions": RetentionClass.FINANCIAL_RETAIN,
        # --- the tombstone and its structure ---------------------------------
        "core.tenants": RetentionClass.TOMBSTONE,
        "core.tenant_ancestry": RetentionClass.TOMBSTONE,
        # --- operational data emptied by PURGE_STEPS ---------------------------
        "core.api_keys": RetentionClass.OPERATIONAL_PURGE,
        "core.notifications": RetentionClass.OPERATIONAL_PURGE,
        "core.webhook_replay_records": RetentionClass.OPERATIONAL_PURGE,
        "core.webhook_subscriptions": RetentionClass.OPERATIONAL_PURGE,
        "core.membership_roles": RetentionClass.OPERATIONAL_PURGE,
        "core.role_permissions": RetentionClass.OPERATIONAL_PURGE,
        "core.service_account_roles": RetentionClass.OPERATIONAL_PURGE,
        "core.deny_grants": RetentionClass.OPERATIONAL_PURGE,
        # audit-referenced delegation grants are kept revoked, not deleted
        "core.delegation_grants": RetentionClass.OPERATIONAL_PURGE,
        "core.roles": RetentionClass.OPERATIONAL_PURGE,
        "core.invitations": RetentionClass.OPERATIONAL_PURGE,
        # audit-referenced service accounts are kept disabled, not deleted
        "core.service_accounts": RetentionClass.OPERATIONAL_PURGE,
        "core.tenant_memberships": RetentionClass.OPERATIONAL_PURGE,
        "core.feature_flag_tenant_overrides": RetentionClass.OPERATIONAL_PURGE,
        "core.idempotency_records": RetentionClass.OPERATIONAL_PURGE,
        # --- deferred: a decision is still required ---------------------------
        "core.usage_events": RetentionClass.DEFERRED_POLICY,
        "control_plane.approval_requests": RetentionClass.DEFERRED_POLICY,
        "self_learning.experiments": RetentionClass.DEFERRED_POLICY,
        "self_learning.adaptations": RetentionClass.DEFERRED_POLICY,
        "self_learning.canaries": RetentionClass.DEFERRED_POLICY,
        # --- global identity and catalogs: never tenant-owned -----------------
        "core.users": RetentionClass.GLOBAL_IDENTITY,
        "core.external_identities": RetentionClass.GLOBAL_IDENTITY,
        "core.sessions": RetentionClass.GLOBAL_IDENTITY,
        "core.login_transactions": RetentionClass.GLOBAL_IDENTITY,
        "core.permissions": RetentionClass.GLOBAL_IDENTITY,
        "core.billing_plans": RetentionClass.GLOBAL_IDENTITY,
        "core.feature_flags": RetentionClass.GLOBAL_IDENTITY,
    }
)

# Which purge step (`core.tenancy.PURGE_STEPS`) empties each
# OPERATIONAL_PURGE table -- the link that keeps this classification honest
# against the implementation (asserted by tests/core/tenancy/
# test_retention_classification.py).
PURGE_STEP_FOR_TABLE: MappingProxyType[str, str] = MappingProxyType(
    {
        "core.api_keys": "api_keys",
        "core.notifications": "notifications",
        "core.webhook_replay_records": "webhooks",
        "core.webhook_subscriptions": "webhooks",
        "core.membership_roles": "authorization",
        "core.role_permissions": "authorization",
        "core.service_account_roles": "authorization",
        "core.deny_grants": "authorization",
        "core.delegation_grants": "authorization",
        "core.roles": "authorization",
        "core.invitations": "invitations",
        "core.service_accounts": "service_accounts",
        "core.tenant_memberships": "memberships",
        "core.feature_flag_tenant_overrides": "feature_flag_overrides",
        "core.idempotency_records": "idempotency_records",
    }
)


def retention_class_for(table: str) -> RetentionClass:
    """The declared class for a schema-qualified table name; `KeyError`
    for a table this classification has never reviewed -- deliberately
    not a default, so an unclassified tenant-owned table is loud."""
    return RETENTION_CLASSIFICATION[table]


def tables_in(retention_class: RetentionClass) -> frozenset[str]:
    return frozenset(
        table for table, cls in RETENTION_CLASSIFICATION.items() if cls is retention_class
    )
