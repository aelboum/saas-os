"""PRIV-03 Phase P4 -- the retention classification is code metadata, so
these pure unit tests keep it honest against the purge implementation:
every table a purge step empties is classified OPERATIONAL_PURGE and maps
to a real `PURGE_STEPS` entry, every retained/deferred/global table is
never a purge target, and the classification cannot be mutated at
runtime. No database needed.
"""

from __future__ import annotations

import pytest

from core.tenancy import (
    PURGE_STEP_FOR_TABLE,
    PURGE_STEPS,
    RETENTION_CLASSIFICATION,
    RetentionClass,
    retention_class_for,
    tables_in,
)


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
    }
    assert tables_in(RetentionClass.FINANCIAL_RETAIN) == {"core.billing_subscriptions"}
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
