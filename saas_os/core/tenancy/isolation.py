"""Table isolation classification (Foundation Enforcement, FE-2;
docs/ADR/0030-foundation-enforcement.md).

Every table SaaS OS's own migrations produce is classified exactly once by
how its rows are isolated between tenants:

    TENANT_OWNED  Rows belong to one tenant, named by the table's
                  `tenant_id` column. Protected by the canonical tenant
                  Row-Level Security policy (`saas_os.infra.db.rls.
                  tenant_rls_statements()`), ENABLE + FORCE -- proven for
                  every such table by
                  `tests/infra/db/test_rls_coverage_sweep_integration.py`.
    GLOBAL        Not tenant-owned and deliberately not RLS-scoped: the
                  tenant registry itself, global identity, global catalogs,
                  and the few documented global-by-design tables that must
                  be resolvable before a tenant is known. Every entry
                  carries the reason it is exempt.
    SYSTEM        Infrastructure bookkeeping with no tenant meaning at all
                  (migration version tracking). Every entry carries its
                  reason too.

This is a separate axis from `saas_os/core/tenancy/retention.py`'s
`RETENTION_CLASSIFICATION`, which says what a tenant purge does with a
table; this registry says how a table's rows are isolated at all. Neither
substitutes for the other (a GLOBAL table can still be retained or purged,
and a TENANT_OWNED table can be either).

`audit_isolation_classification()` is the static half of the proof: given
the schema the migrations actually produce
(`saas_os.infra.db.migrations.schema_inventory.schema_at_head()`, a database-free
replay of every migration, plus the Alembic version table, which Alembic
creates itself), it rejects missing tables, stale entries, duplicate
entries, GLOBAL/SYSTEM entries without a reason, and a table carrying a
`tenant_id` column that is not TENANT_OWNED without an explicit exception
reason. `tests/core/tenancy/test_isolation_classification.py` runs it.

Names are plain schema-qualified strings, as in the retention map -- this
module imports nothing from `control_plane` or any product. Consumer-owned
tables (e.g. a reference consumer's own schema) are classified by the
consumer, never here.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from types import MappingProxyType


class IsolationClass(enum.StrEnum):
    TENANT_OWNED = "tenant_owned"
    GLOBAL = "global"
    SYSTEM = "system"


@dataclass(frozen=True)
class TableIsolation:
    """One table's classification. `reason` is required for GLOBAL and
    SYSTEM (why the table is exempt from tenant RLS) and must be empty for
    TENANT_OWNED (nothing to justify)."""

    isolation: IsolationClass
    reason: str = ""


TENANT_ID_COLUMN = "tenant_id"

# Created by Alembic itself (`saas_os/infra/db/migrations/env.py` pins
# `version_table="alembic_version_saas_os"`), not by any migration's
# `op.create_table()`, so `schema_at_head()` never lists it.
ALEMBIC_VERSION_TABLE = "public.alembic_version_saas_os"

_T = TableIsolation(IsolationClass.TENANT_OWNED)


def _global(reason: str) -> TableIsolation:
    return TableIsolation(IsolationClass.GLOBAL, reason)


ISOLATION_ENTRIES: tuple[tuple[str, TableIsolation], ...] = (
    # --- TENANT_OWNED: canonical tenant RLS ---------------------------------
    ("control_plane.approval_requests", _T),
    ("core.audit_log", _T),
    ("core.billing_accounts", _T),
    ("core.billing_merchant_accounts", _T),
    ("core.billing_plan_offers", _T),
    ("core.billing_seller_subscriptions", _T),
    ("core.billing_payer_subscriptions", _T),
    ("core.billing_subscriptions", _T),
    ("core.delegation_grants", _T),
    ("core.deny_grants", _T),
    ("core.feature_flag_tenant_overrides", _T),
    ("core.idempotency_records", _T),
    ("core.invitations", _T),
    ("core.membership_roles", _T),
    ("core.notifications", _T),
    ("core.outbox_consumptions", _T),
    ("core.outbox_events", _T),
    ("core.role_permissions", _T),
    ("core.roles", _T),
    ("core.service_account_roles", _T),
    ("core.service_accounts", _T),
    ("core.support_access_requests", _T),
    ("core.tenant_memberships", _T),
    ("core.usage_events", _T),
    ("core.webhook_replay_records", _T),
    ("core.webhook_subscriptions", _T),
    ("self_learning.adaptations", _T),
    ("self_learning.canaries", _T),
    ("self_learning.experiments", _T),
    # --- GLOBAL: deliberately not tenant-RLS-scoped ----------------------------
    ("core.tenants", _global("the tenant registry itself: a tenant cannot scope itself")),
    (
        "core.tenant_ancestry",
        _global(
            "tenant hierarchy structure derived from core.tenants.parent_id; part of the "
            "registry, not tenant-owned business data (its tenant_id names the node)"
        ),
    ),
    ("core.users", _global("global identity: a user may belong to many tenants")),
    ("core.external_identities", _global("global identity: the IdP (issuer, subject) mapping")),
    ("core.sessions", _global("global identity: a user session exists before any tenant")),
    (
        "core.login_transactions",
        _global("pre-authentication OIDC state: exists before any user or tenant is known"),
    ),
    ("core.permissions", _global("global permission catalog shared by every tenant")),
    ("core.feature_flags", _global("global feature-flag definition catalog")),
    (
        "core.billing_plans",
        _global(
            "owner-scoped billing catalog; visibility is the application-level eligibility "
            "predicate (ADR-0022 amendment), which RLS cannot express"
        ),
    ),
    (
        "core.api_keys",
        _global(
            "bearer credential resolved by hash before the caller's tenant is known; "
            "its tenant_id is an explicit query predicate (ADR-0022)"
        ),
    ),
    (
        "core.billing_provider_refs",
        _global(
            "provider references resolved to their tenant before that tenant is known "
            "(ADR-0022 amendment, ADR-0029); the resolved row is re-read under RLS"
        ),
    ),
    # --- SYSTEM -------------------------------------------------------------------
    (
        ALEMBIC_VERSION_TABLE,
        TableIsolation(
            IsolationClass.SYSTEM, "Alembic migration version bookkeeping; no tenant meaning"
        ),
    ),
)

ISOLATION_CLASSIFICATION: MappingProxyType[str, TableIsolation] = MappingProxyType(
    dict(ISOLATION_ENTRIES)
)


def isolation_class_for(table: str) -> IsolationClass:
    """`KeyError` for a table never classified -- deliberately no default."""
    return ISOLATION_CLASSIFICATION[table].isolation


def tables_with_isolation(isolation: IsolationClass) -> frozenset[str]:
    return frozenset(
        table for table, entry in ISOLATION_CLASSIFICATION.items() if entry.isolation is isolation
    )


@dataclass(frozen=True)
class IsolationInventoryViolation:
    """One thing `audit_isolation_classification()` found wrong. `kind` is
    one of `"unclassified"`, `"stale"`, `"duplicate"`, `"missing_reason"`,
    `"unexpected_reason"`, `"tenant_owned_without_tenant_key"`, or
    `"tenant_keyed_not_tenant_owned"`."""

    kind: str
    table: str
    detail: str


def audit_isolation_classification(
    schema: Mapping[str, AbstractSet[str]],
    entries: Sequence[tuple[str, TableIsolation]],
    *,
    system_tables: AbstractSet[str] = frozenset({ALEMBIC_VERSION_TABLE}),
) -> tuple[IsolationInventoryViolation, ...]:
    """Diff `schema` (schema-qualified table -> its columns, as
    `schema_at_head()` returns) plus `system_tables` (tables that exist
    without a migration creating them) against `entries` -- a *sequence*,
    so a duplicate entry is still observable. A table that carries a
    `tenant_id` column but is not TENANT_OWNED is a violation unless its
    entry is GLOBAL/SYSTEM *with* a reason -- the reason is the explicit
    exception. Returns violations sorted by (kind, table); empty means the
    registry is complete and consistent."""
    violations: list[IsolationInventoryViolation] = []
    seen: dict[str, TableIsolation] = {}
    for table, entry in entries:
        if table in seen:
            violations.append(
                IsolationInventoryViolation(
                    "duplicate", table, f"classified more than once ({seen[table]} and {entry})"
                )
            )
            continue
        seen[table] = entry

    known_tables = set(schema) | set(system_tables)
    for table in sorted(known_tables - set(seen)):
        violations.append(
            IsolationInventoryViolation(
                "unclassified", table, "produced by the migrations but not classified"
            )
        )
    for table in sorted(set(seen) - known_tables):
        violations.append(
            IsolationInventoryViolation("stale", table, "classified but not in the schema")
        )

    for table, entry in seen.items():
        has_reason = bool(entry.reason.strip())
        if entry.isolation is IsolationClass.TENANT_OWNED:
            if has_reason:
                violations.append(
                    IsolationInventoryViolation(
                        "unexpected_reason", table, "TENANT_OWNED needs no exemption reason"
                    )
                )
            columns = schema.get(table)
            if columns is not None and TENANT_ID_COLUMN not in columns:
                violations.append(
                    IsolationInventoryViolation(
                        "tenant_owned_without_tenant_key",
                        table,
                        "TENANT_OWNED but has no tenant_id column for the RLS policy",
                    )
                )
        elif not has_reason:
            violations.append(
                IsolationInventoryViolation(
                    "missing_reason", table, f"{entry.isolation.value} requires a reason"
                )
            )
        if (
            entry.isolation is not IsolationClass.TENANT_OWNED
            and TENANT_ID_COLUMN in schema.get(table, frozenset())
            and not has_reason
        ):
            violations.append(
                IsolationInventoryViolation(
                    "tenant_keyed_not_tenant_owned",
                    table,
                    "has a tenant_id column but is not TENANT_OWNED and gives no reason",
                )
            )

    return tuple(sorted(violations, key=lambda v: (v.kind, v.table)))
