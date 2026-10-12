"""PRIV-03 Phase P4 -- the retention classification is code metadata, so
these pure unit tests keep it honest against the purge implementation:
every table a purge step empties is classified OPERATIONAL_PURGE and maps
to a real `PURGE_STEPS` entry, every retained/deferred/global table is
never a purge target, and the classification cannot be mutated at
runtime. No database needed.

RA-12-1 (privacy re-audit finding 1): the tests below this line close the
gap those tests above leave open -- `retention_class_for()` only ever
fails when *called* for a specific table, so a future migration could add
a tenant-scoped table with nobody ever calling it for that name. These
prove every tenant-scoped table the migrations actually produce (replayed
statically, no database needed -- `saas_os.infra.db.migrations.schema_inventory`)
has exactly one `RETENTION_CLASSIFICATION` entry, that no entry names a
table the schema no longer produces, and that a duplicate classification
entry cannot silently collapse into "whichever came last."
"""

from __future__ import annotations

import pytest

from saas_os.core.tenancy import (
    PURGE_STEP_FOR_TABLE,
    PURGE_STEPS,
    RETENTION_CLASSIFICATION,
    RetentionClass,
    retention_class_for,
    tables_in,
)
from saas_os.core.tenancy.retention import STALE_TABLE_ALLOWLIST, audit_retention_classification
from saas_os.infra.db.migrations.schema_inventory import schema_at_head


def test_every_operational_purge_table_maps_to_a_real_purge_step() -> None:
    operational = tables_in(RetentionClass.OPERATIONAL_PURGE)
    assert operational == frozenset(PURGE_STEP_FOR_TABLE)
    assert set(PURGE_STEP_FOR_TABLE.values()) <= set(PURGE_STEPS)
    # Every purge step empties at least one classified table.
    assert set(PURGE_STEP_FOR_TABLE.values()) == set(PURGE_STEPS)


def test_retained_tables_are_exactly_the_p3_retained_set() -> None:
    assert tables_in(RetentionClass.SECURITY_RETAIN) == {
        "core.audit_log",
        "core.support_access_requests",
        # ADR-0045: platform authority and platform evidence (global).
        "core.platform_operators",
        "core.platform_grants",
        "core.platform_audit_log",
    }
    # Billing Foundation v2 Phase 2 (ADR-0029): payer/payee records and the
    # provider-reference index are retained with the subscriptions that
    # reference them.
    assert tables_in(RetentionClass.FINANCIAL_RETAIN) == {
        "core.billing_subscriptions",
        "core.billing_merchant_accounts",
        "core.billing_accounts",
        "core.billing_provider_refs",
        # Phase 5.3 step 2 (Catalog v2): offers are commercial records.
        "core.billing_plan_offers",
        # Phase 5.3 step 4: read models retained with their subscriptions.
        "core.billing_seller_subscriptions",
        "core.billing_payer_subscriptions",
    }
    assert tables_in(RetentionClass.TOMBSTONE) == {"core.tenants", "core.tenant_ancestry"}


def test_deferred_tables_are_usage_and_ai_control_plane_only() -> None:
    assert tables_in(RetentionClass.DEFERRED_POLICY) == {
        "core.usage_events",
        "control_plane.approval_requests",
        "self_learning.experiments",
        "self_learning.adaptations",
        "self_learning.canaries",
    }


def test_global_identity_tables_are_never_tenant_owned() -> None:
    assert tables_in(RetentionClass.GLOBAL_IDENTITY) == {
        "core.users",
        "core.external_identities",
        "core.sessions",
        "core.login_transactions",
        "core.permissions",
        "core.billing_plans",
        "core.feature_flags",
    }


def test_no_retained_deferred_or_global_table_is_a_purge_target() -> None:
    purge_targets = frozenset(PURGE_STEP_FOR_TABLE)
    for cls in (
        RetentionClass.SECURITY_RETAIN,
        RetentionClass.FINANCIAL_RETAIN,
        RetentionClass.DEFERRED_POLICY,
        RetentionClass.GLOBAL_IDENTITY,
        RetentionClass.TOMBSTONE,
    ):
        assert tables_in(cls).isdisjoint(purge_targets), cls


def test_every_table_has_exactly_one_class_and_the_classes_partition_the_map() -> None:
    union: set[str] = set()
    for cls in RetentionClass:
        tables = tables_in(cls)
        assert union.isdisjoint(tables), cls
        union |= tables
    assert union == set(RETENTION_CLASSIFICATION)


def test_unreviewed_table_is_loud_not_defaulted() -> None:
    with pytest.raises(KeyError):
        retention_class_for("core.some_future_table")


def test_classification_is_read_only() -> None:
    with pytest.raises(TypeError):
        RETENTION_CLASSIFICATION["core.audit_log"] = RetentionClass.OPERATIONAL_PURGE  # type: ignore[index]
    with pytest.raises(TypeError):
        PURGE_STEP_FOR_TABLE["core.audit_log"] = "api_keys"  # type: ignore[index]


# --- RA-12-1: proactive enforcement against the real (migration-derived) schema


def test_every_real_tenant_scoped_table_has_a_retention_classification() -> None:
    """The actual regression guard: every table the migrations produce at
    head that carries a `tenant_id` column must be in
    `RETENTION_CLASSIFICATION`, and no entry may name a table that no
    longer exists. Fails loudly -- not a skip -- for a future migration
    that adds a tenant-scoped table nobody classified, with no database
    and no Docker required."""
    violations = audit_retention_classification(
        schema_at_head(), list(RETENTION_CLASSIFICATION.items())
    )
    assert violations == (), violations


def test_an_unclassified_tenant_scoped_table_is_detected() -> None:
    """Proves the guard actually fires: a synthetic schema carrying a
    brand-new tenant-scoped table absent from the real
    `RETENTION_CLASSIFICATION` must be reported as unclassified. Uses a
    synthetic schema dict, not a real migration or model file -- nothing
    tracked is touched."""
    schema = dict(schema_at_head())
    schema["core.some_future_tenant_table"] = frozenset({"id", "tenant_id", "created_at"})

    violations = audit_retention_classification(schema, list(RETENTION_CLASSIFICATION.items()))

    assert len(violations) == 1
    (violation,) = violations
    assert violation.kind == "unclassified"
    assert violation.table == "core.some_future_tenant_table"


def test_a_classification_naming_a_nonexistent_table_is_detected() -> None:
    """An entry that outlives its table (renamed, dropped, or simply
    mistyped) must be reported, not silently accepted -- unless it is on
    the explicit, reviewed `STALE_TABLE_ALLOWLIST` (empty today; see that
    constant's own docstring)."""
    stale_table = "core.a_table_that_was_never_actually_created"
    assert stale_table not in STALE_TABLE_ALLOWLIST
    entries = [*RETENTION_CLASSIFICATION.items(), (stale_table, RetentionClass.OPERATIONAL_PURGE)]

    violations = audit_retention_classification(schema_at_head(), entries)

    assert len(violations) == 1
    (violation,) = violations
    assert violation.kind == "stale"
    assert violation.table == stale_table


def test_a_duplicate_classification_entry_with_conflicting_classes_is_detected() -> None:
    """A real `RETENTION_CLASSIFICATION` dict literal cannot itself hold a
    duplicate key -- Python collapses it to "whichever assignment came
    last" before any test ever runs. `audit_retention_classification()`
    takes the raw sequence of `(table, class)` pairs for exactly this
    reason: passing the same table twice, classified two different ways,
    must be visible here as a conflict rather than have already vanished
    by the time this function receives it."""
    entries = [
        ("core.audit_log", RetentionClass.SECURITY_RETAIN),
        ("core.audit_log", RetentionClass.OPERATIONAL_PURGE),
    ]

    violations = audit_retention_classification(schema_at_head(), entries)

    duplicate_violations = [v for v in violations if v.kind == "duplicate"]
    assert len(duplicate_violations) == 1
    assert duplicate_violations[0].table == "core.audit_log"


def test_a_duplicate_entry_with_the_same_class_twice_is_not_a_conflict() -> None:
    """Naming the same table twice with the *same* class is redundant, not
    contradictory -- only a genuine disagreement about a table's class is
    a `"duplicate"` violation."""
    entries = [
        ("core.audit_log", RetentionClass.SECURITY_RETAIN),
        ("core.audit_log", RetentionClass.SECURITY_RETAIN),
    ]

    violations = audit_retention_classification(schema_at_head(), entries)

    assert not any(v.kind == "duplicate" for v in violations)


# --- ADR-0045: platform-authority tables -------------------------------------

_PLATFORM_TABLES = (
    "core.platform_operators",
    "core.platform_grants",
    "core.platform_audit_log",
)


def test_platform_authority_tables_are_security_retained() -> None:
    """All three are covered, each as SECURITY_RETAIN: platform authority
    and platform evidence are never deleted by a tenant purge."""
    for table in _PLATFORM_TABLES:
        assert retention_class_for(table) is RetentionClass.SECURITY_RETAIN, table


def test_platform_authority_tables_exist_in_the_schema_and_are_not_tenant_scoped() -> None:
    """The entries name real tables (not stale), and those tables carry no
    `tenant_id` column -- they are global, so no tenant purge reasons
    about them as tenant-owned data."""
    schema = schema_at_head()
    for table in _PLATFORM_TABLES:
        assert table in schema, table
        assert "tenant_id" not in schema[table], table


def test_no_purge_step_and_no_automatic_deletion_targets_a_platform_table() -> None:
    """No deletion behaviour is introduced: no purge step is mapped to a
    platform table, and the purge implementation never names one."""
    assert not set(_PLATFORM_TABLES) & set(PURGE_STEP_FOR_TABLE)
    assert not set(_PLATFORM_TABLES) & tables_in(RetentionClass.OPERATIONAL_PURGE)
    from pathlib import Path

    tenancy_service = Path(__file__).resolve().parents[3] / "saas_os/core/tenancy/service.py"
    source = tenancy_service.read_text(encoding="utf-8")
    for table in _PLATFORM_TABLES:
        assert table.split(".", 1)[1] not in source, table
