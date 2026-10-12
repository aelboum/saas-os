"""`saas_os.infra.db.rls.tenant_rls_statements()` tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.1) -- pure string generation, no database needed.
"""

from __future__ import annotations

from saas_os.infra.db.rls import tenant_context_exclusion_statements, tenant_rls_statements


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


# --- tenant-context exclusion policy (ADR-0045 section 9b) -------------------


def test_exclusion_enables_and_forces_row_level_security() -> None:
    statements = tenant_context_exclusion_statements("platform_grants", schema="core")
    assert statements[0] == 'ALTER TABLE "core"."platform_grants" ENABLE ROW LEVEL SECURITY'
    assert statements[1] == 'ALTER TABLE "core"."platform_grants" FORCE ROW LEVEL SECURITY'
    assert len(statements) == 3


def test_exclusion_policy_admits_only_an_unbound_or_empty_tenant_context() -> None:
    policy = tenant_context_exclusion_statements("platform_grants", schema="core")[2]
    assert policy == (
        'CREATE POLICY "platform_grants_no_tenant_context" ON "core"."platform_grants" '
        "USING (NULLIF(current_setting('app.tenant_id', true), '') IS NULL)"
    )


def test_exclusion_policy_never_casts_so_a_malformed_value_cannot_raise() -> None:
    """Fail closed without an error: the tenant policy casts to uuid; this
    one only tests for NULL, so a non-UUID value simply hides the rows."""
    policy = tenant_context_exclusion_statements("platform_grants", schema="core")[2]
    assert "::uuid" not in policy
    assert "WITH CHECK" not in policy  # USING governs writes as well


def test_exclusion_policy_is_a_different_policy_from_the_tenant_policy() -> None:
    assert tenant_context_exclusion_statements("t") != tenant_rls_statements("t")
    assert '"t_no_tenant_context"' in tenant_context_exclusion_statements("t")[2]
