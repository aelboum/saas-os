"""Foundation Enforcement FE-2 -- the table isolation classification
registry (`saas_os/core/tenancy/isolation.py`) against the schema SaaS OS's own
migrations actually produce (`schema_at_head()`, replayed statically: no
database needed). Separate from the retention classification tests --
retention and isolation are different axes.
"""

from __future__ import annotations

import pytest

from saas_os.core.tenancy import RETENTION_CLASSIFICATION
from saas_os.core.tenancy.isolation import (
    ALEMBIC_VERSION_TABLE,
    ISOLATION_CLASSIFICATION,
    ISOLATION_ENTRIES,
    IsolationClass,
    TableIsolation,
    audit_isolation_classification,
    isolation_class_for,
    tables_excluding_tenant_context,
    tables_with_isolation,
)
from saas_os.infra.db.migrations.schema_inventory import schema_at_head


def _kinds(violations) -> list[tuple[str, str]]:  # type: ignore[no-untyped-def]
    return [(v.kind, v.table) for v in violations]


def test_the_real_registry_covers_the_whole_schema_with_no_violations() -> None:
    assert audit_isolation_classification(schema_at_head(), ISOLATION_ENTRIES) == ()


def test_every_migrated_table_plus_the_version_table_is_classified() -> None:
    assert set(ISOLATION_CLASSIFICATION) == set(schema_at_head()) | {ALEMBIC_VERSION_TABLE}
    assert len(ISOLATION_ENTRIES) == len(ISOLATION_CLASSIFICATION)  # no collapsed duplicates


def test_alembic_version_table_is_system() -> None:
    assert isolation_class_for("public.alembic_version_saas_os") is IsolationClass.SYSTEM


def test_every_non_tenant_classification_has_a_reason_and_tenant_owned_has_none() -> None:
    for table, entry in ISOLATION_CLASSIFICATION.items():
        if entry.isolation is IsolationClass.TENANT_OWNED:
            assert entry.reason == "", table
        else:
            assert entry.reason.strip(), table


def test_every_tenant_owned_table_has_a_tenant_id_column() -> None:
    schema = schema_at_head()
    for table in tables_with_isolation(IsolationClass.TENANT_OWNED):
        assert "tenant_id" in schema[table], table


def test_tenant_keyed_exceptions_are_exactly_the_documented_global_tables() -> None:
    schema = schema_at_head()
    keyed_non_tenant = {
        table
        for table, columns in schema.items()
        if "tenant_id" in columns
        and ISOLATION_CLASSIFICATION[table].isolation is not IsolationClass.TENANT_OWNED
    }
    assert keyed_non_tenant == {
        "core.api_keys",
        "core.billing_provider_refs",
        "core.tenant_ancestry",
    }


def test_isolation_is_not_the_retention_classification() -> None:
    """Separate registries: the alembic version table has a retention
    meaning of none, and retention classes are not isolation classes."""
    assert ALEMBIC_VERSION_TABLE not in RETENTION_CLASSIFICATION
    assert not set(IsolationClass) & {c.value for c in RETENTION_CLASSIFICATION.values()}


def test_unclassified_table_is_detected() -> None:
    schema = dict(schema_at_head())
    schema["core.some_future_table"] = frozenset({"id", "tenant_id"})
    assert _kinds(audit_isolation_classification(schema, ISOLATION_ENTRIES)) == [
        ("unclassified", "core.some_future_table")
    ]


def test_stale_entry_is_detected() -> None:
    entries = [*ISOLATION_ENTRIES, ("core.retired", TableIsolation(IsolationClass.GLOBAL, "x"))]
    assert _kinds(audit_isolation_classification(schema_at_head(), entries)) == [
        ("stale", "core.retired")
    ]


def test_duplicate_entry_is_detected() -> None:
    entries = [*ISOLATION_ENTRIES, ("core.users", TableIsolation(IsolationClass.TENANT_OWNED))]
    assert ("duplicate", "core.users") in _kinds(
        audit_isolation_classification(schema_at_head(), entries)
    )


@pytest.mark.parametrize("isolation", [IsolationClass.GLOBAL, IsolationClass.SYSTEM])
def test_non_tenant_entry_without_reason_is_detected(isolation: IsolationClass) -> None:
    entries = [
        (table, entry) for table, entry in ISOLATION_ENTRIES if table != "core.permissions"
    ] + [("core.permissions", TableIsolation(isolation, "   "))]
    assert ("missing_reason", "core.permissions") in _kinds(
        audit_isolation_classification(schema_at_head(), entries)
    )


def test_tenant_keyed_table_classified_global_without_reason_is_detected() -> None:
    entries = [
        (table, entry) for table, entry in ISOLATION_ENTRIES if table != "core.notifications"
    ] + [("core.notifications", TableIsolation(IsolationClass.GLOBAL))]
    found = _kinds(audit_isolation_classification(schema_at_head(), entries))
    assert ("tenant_keyed_not_tenant_owned", "core.notifications") in found
    assert ("missing_reason", "core.notifications") in found


def test_tenant_owned_table_without_tenant_key_is_detected() -> None:
    entries = [(table, entry) for table, entry in ISOLATION_ENTRIES if table != "core.users"] + [
        ("core.users", TableIsolation(IsolationClass.TENANT_OWNED))
    ]
    assert ("tenant_owned_without_tenant_key", "core.users") in _kinds(
        audit_isolation_classification(schema_at_head(), entries)
    )


def test_tenant_owned_entry_with_a_reason_is_detected() -> None:
    entries = [(table, entry) for table, entry in ISOLATION_ENTRIES if table != "core.roles"] + [
        ("core.roles", TableIsolation(IsolationClass.TENANT_OWNED, "why"))
    ]
    assert ("unexpected_reason", "core.roles") in _kinds(
        audit_isolation_classification(schema_at_head(), entries)
    )


def test_registry_is_read_only() -> None:
    with pytest.raises(TypeError):
        ISOLATION_CLASSIFICATION["core.roles"] = TableIsolation(IsolationClass.GLOBAL, "x")  # type: ignore[index]


# --- tenant-context exclusion policy marker (ADR-0045) -----------------------


def test_exactly_the_platform_authority_tables_exclude_tenant_context() -> None:
    assert tables_excluding_tenant_context() == {
        "core.platform_operators",
        "core.platform_grants",
        "core.platform_audit_log",
        # ADR-0053: the digest records name tenants and their row counts.
        "core.audit_digests",
    }


def test_platform_authority_tables_are_global_and_carry_no_tenant_id_column() -> None:
    """They are not tenant-owned: no `tenant_id` column, so neither the
    tenant policy nor the tenant-keyed exception rule applies to them."""
    schema = schema_at_head()
    for table in tables_excluding_tenant_context():
        assert isolation_class_for(table) is IsolationClass.GLOBAL, table
        assert "tenant_id" not in schema[table], table
    assert "target_tenant_id" in schema["core.platform_audit_log"]


@pytest.mark.parametrize("isolation", [IsolationClass.TENANT_OWNED, IsolationClass.SYSTEM])
def test_exclusion_marker_on_a_non_global_table_is_detected(isolation: IsolationClass) -> None:
    reason = "" if isolation is IsolationClass.TENANT_OWNED else "x"
    entries = [(t, e) for t, e in ISOLATION_ENTRIES if t != "core.notifications"] + [
        ("core.notifications", TableIsolation(isolation, reason, excludes_tenant_context=True))
    ]
    assert ("exclusion_policy_on_non_global", "core.notifications") in _kinds(
        audit_isolation_classification(schema_at_head(), entries)
    )
