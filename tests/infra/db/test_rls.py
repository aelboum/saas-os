"""`infra.db.rls.tenant_rls_statements()` tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.1) -- pure string generation, no database needed.
"""

from __future__ import annotations

from infra.db.rls import tenant_rls_statements


def test_enables_row_level_security() -> None:
    statements = tenant_rls_statements("widgets", schema="product_x")
    assert any("ENABLE ROW LEVEL SECURITY" in s for s in statements)


def test_forces_row_level_security_for_the_table_owner() -> None:
    """Non-vacuous: without FORCE ROW LEVEL SECURITY, Postgres exempts the
    table owner (the role migrations/the app connect as) from every
    policy, silently making RLS a no-op for application traffic. This
    test fails if that statement is ever accidentally removed.
    """
    statements = tenant_rls_statements("widgets", schema="product_x")
    assert any("FORCE ROW LEVEL SECURITY" in s for s in statements)


def test_creates_a_policy_keyed_on_the_tenant_column() -> None:
    statements = tenant_rls_statements("widgets", schema="product_x")
    policy_statements = [s for s in statements if "CREATE POLICY" in s]
    assert len(policy_statements) == 1
    assert "tenant_id" in policy_statements[0]
    assert "current_setting('app.tenant_id', true)" in policy_statements[0]


def test_policy_normalizes_an_empty_setting_to_null_not_a_cast_error() -> None:
    """PostgreSQL resets a custom GUC to an empty string (not NULL) once
    a session has used set_config(..., is_local=true) on it at least once
    -- casting '' directly to uuid raises a database error instead of
    failing safely. NULLIF must wrap the empty-string case before the
    ::uuid cast.
    """
    statements = tenant_rls_statements("widgets", schema="product_x")
    policy_statements = [s for s in statements if "CREATE POLICY" in s]
    assert "NULLIF(current_setting('app.tenant_id', true), '')::uuid" in policy_statements[0]


def test_custom_tenant_column_is_used_in_the_policy() -> None:
    """The session variable name (`app.tenant_id`) stays fixed regardless
    of the column name (it's the RLS session-context key, not a schema
    detail) -- only the column being compared against it changes.
    """
    statements = tenant_rls_statements("widgets", schema="product_x", tenant_column="org_id")
    policy_statements = [s for s in statements if "CREATE POLICY" in s]
    assert "org_id = NULLIF(current_setting" in policy_statements[0]
    assert "tenant_id = NULLIF(current_setting" not in policy_statements[0]


def test_table_and_schema_are_quoted_in_every_statement() -> None:
    statements = tenant_rls_statements("widgets", schema="product_x")
    for statement in statements:
        assert '"product_x"."widgets"' in statement


def test_works_without_an_explicit_schema() -> None:
    statements = tenant_rls_statements("widgets")
    for statement in statements:
        assert '"widgets"' in statement
        assert '"."' not in statement
