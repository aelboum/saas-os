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
                   operational data and references the tombstone. Retained
                   evidence lends no authority: a support-access grant is
                   revoked (`revoked_at` set, row kept) before the purge
                   passes run (PRIV-03 P6, `core/rbac/service.py::
                   revoke_tenant_support_access()`), and the support
                   authorization path refuses a closed tenant regardless.
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
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
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
        # Billing Foundation v2 Phase 2 (ADR-0029): the payer/payee records
        # a retained subscription references, and the provider-reference
        # index resolving it -- retained with it, never purge targets.
        "core.billing_merchant_accounts": RetentionClass.FINANCIAL_RETAIN,
        "core.billing_plan_offers": RetentionClass.FINANCIAL_RETAIN,
        # Phase 5.3 step 4: read models derived from (and retained with)
        # the subscriptions they project.
        "core.billing_seller_subscriptions": RetentionClass.FINANCIAL_RETAIN,
        "core.billing_payer_subscriptions": RetentionClass.FINANCIAL_RETAIN,
        "core.billing_accounts": RetentionClass.FINANCIAL_RETAIN,
        "core.billing_provider_refs": RetentionClass.FINANCIAL_RETAIN,
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
        # RE-1: unpublished events of a closed tenant are never published
        # and may carry tenant data
        "core.outbox_events": RetentionClass.OPERATIONAL_PURGE,
        # RE-5: consumer-idempotency records -- emptied with the outbox
        "core.outbox_consumptions": RetentionClass.OPERATIONAL_PURGE,
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
        "core.outbox_events": "outbox",
        "core.outbox_consumptions": "outbox",
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


# --- RA-12-1: proactive enforcement against the real schema -----------------
#
# `retention_class_for()` above only ever fails when *called* for a specific
# table -- nothing forces every tenant-scoped table the schema actually
# contains to be looked up. `audit_retention_classification()` below is the
# proactive check: given the schema Alembic's migrations actually produce
# (`infra.db.migrations.schema_inventory.schema_at_head()` -- a database-free
# replay of every migration's own `upgrade()`, never SQLAlchemy ORM metadata,
# since `infra/db/migrations/env.py`'s `target_metadata = None` means the ORM
# is not this repository's source of truth for what a real database
# contains), it proves every table carrying a `tenant_id` column has exactly
# one `RETENTION_CLASSIFICATION` entry, and that no entry names a table the
# schema no longer produces.

TENANT_ID_COLUMN = "tenant_id"

# Tables the migrations still produce but that `RETENTION_CLASSIFICATION`
# deliberately no longer tracks, for an explicit, reviewed reason (e.g. a
# table renamed or intentionally retired from tenant-purge scope while the
# table itself still physically exists for a documented transitional
# reason). Empty today -- every classified table is a real, current table
# (see tests/core/tenancy/test_retention_classification.py). Kept as a
# named, reviewable allowlist rather than folding a one-off exception into
# `audit_retention_classification()` itself, so a future genuinely-justified
# entry has one obvious, visible place to be added and reviewed.
STALE_TABLE_ALLOWLIST: frozenset[str] = frozenset()


@dataclass(frozen=True)
class RetentionInventoryViolation:
    """One thing `audit_retention_classification()` found wrong.
    `kind` is one of `"unclassified"` (a tenant-scoped table the schema
    produces has no `RETENTION_CLASSIFICATION` entry), `"stale"` (an entry
    names a table the schema no longer produces and it is not on
    `STALE_TABLE_ALLOWLIST`), or `"duplicate"` (the same table name appears
    more than once in the classification entries with different classes)."""

    kind: str
    table: str
    detail: str


def audit_retention_classification(
    schema: Mapping[str, AbstractSet[str]],
    classification_entries: Sequence[tuple[str, RetentionClass]],
) -> tuple[RetentionInventoryViolation, ...]:
    """Diff `schema` (schema-qualified table name -> its column names, the
    shape `infra.db.migrations.schema_inventory.schema_at_head()` returns)
    against `classification_entries` -- deliberately a *sequence* of
    `(table, class)` pairs, not the already-built `RETENTION_CLASSIFICATION`
    mapping itself: a real duplicate key in that mapping's own dict literal
    would already have silently collapsed to "whichever entry came last"
    before any Python code could ever inspect it, so the one place a
    duplicate is still observable is the raw sequence of entries a caller
    passes here (e.g. `list(RETENTION_CLASSIFICATION.items())`, which is
    duplicate-free today precisely because it already went through this
    check in `tests/core/tenancy/test_retention_classification.py`).

    A table counts as tenant-scoped when it carries a column literally
    named `tenant_id` -- the same column every Row-Level Security policy
    and every `tenant_session_scope()` call in this codebase compares
    against `current_setting('app.tenant_id')`; a table participating in
    tenant isolation with no `tenant_id` column of its own would need an
    RLS policy shape this codebase does not have today, so this predicate
    covers every tenant-scoped table the current architecture can produce.

    Returns every violation found, empty if none. Never raises on its own
    -- the caller (a test) decides how to fail.
    """
    seen: dict[str, RetentionClass] = {}
    violations: list[RetentionInventoryViolation] = []
    for table, cls in classification_entries:
        if table in seen and seen[table] is not cls:
            violations.append(
                RetentionInventoryViolation(
                    kind="duplicate",
                    table=table,
                    detail=f"classified as both {seen[table].value!r} and {cls.value!r}",
                )
            )
        seen[table] = cls

    tenant_scoped_tables = {
        table for table, columns in schema.items() if TENANT_ID_COLUMN in columns
    }
    for table in sorted(tenant_scoped_tables - set(seen)):
        violations.append(
            RetentionInventoryViolation(
                kind="unclassified",
                table=table,
                detail="has a tenant_id column but no RETENTION_CLASSIFICATION entry",
            )
        )
    for table in sorted(set(seen) - set(schema) - STALE_TABLE_ALLOWLIST):
        violations.append(
            RetentionInventoryViolation(
                kind="stale",
                table=table,
                detail="classified but no longer produced by the migrations",
            )
        )
    return tuple(violations)
