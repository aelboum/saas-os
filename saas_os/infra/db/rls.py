"""PostgreSQL Row-Level Security DDL for tenant-owned tables
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.1; docs/ADR/0002-multi-tenancy-isolation-model.md,
docs/MULTI-TENANCY.md section 2: "PostgreSQL Row-Level Security (RLS)
policies on every tenant-owned table as defense in depth, keyed on a
session-level tenant_id").

`tenant_rls_statements()` returns the DDL a migration executes to enable
RLS on one tenant-owned table, scoped by the session variable
`app.tenant_id` that `saas_os.infra.db.tenant_session_scope()` sets. This is a
reusable primitive for *any future* tenant-owned table's migration --
`saas_os/infra/db` generates the SQL text here; it does not execute DDL itself
(that stays Alembic's job, per each module owning its own migrations,
docs/DATA-ARCHITECTURE.md section 2).

`FORCE ROW LEVEL SECURITY` is not optional: PostgreSQL's default RLS
behavior exempts the table's *owner* (typically the same role the
application connects as) from every policy -- without `FORCE`, RLS would
be silently bypassed for all application traffic, making the "defense in
depth" guarantee a no-op. This is deliberately not left to each migration
author to remember. Note that `FORCE` never applies to a superuser or a
role with `BYPASSRLS` -- there is no override for those; the application's
runtime database role must be neither (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.1 implementation notes).

The policy wraps `current_setting('app.tenant_id', true)` in
`NULLIF(..., '')` before casting to `uuid` -- found empirically while
testing this module: once a session has used `set_config('app.tenant_id',
..., true)` (transaction-local) at least once and that transaction ends,
PostgreSQL resets the custom parameter to an *empty string*, not back to
fully unset/NULL, for the rest of that session/connection. Casting `''`
directly to `uuid` raises a database error (`invalid input syntax for
type uuid`) rather than failing safely -- exactly the wrong failure mode
for a connection-pooled application, where a later untenanted query can
land on a connection a tenant-scoped query previously used. `NULLIF`
normalizes both "never set" and "reset after use" to a real `NULL`, so
the comparison is always a clean "no match" (zero rows), never an error.
"""

from __future__ import annotations


def tenant_rls_statements(
    table: str, *, schema: str | None = None, tenant_column: str = "tenant_id"
) -> list[str]:
    """DDL statements enabling tenant-scoped RLS on `table`. `table` and
    `schema` are trusted identifiers supplied by migration authors (never
    user input) -- there is no parameterization concern here, the same
    way `op.create_table(...)` itself trusts its caller's identifiers.
    """
    qualified = f'"{schema}"."{table}"' if schema else f'"{table}"'
    policy_name = f"{table}_tenant_isolation"
    return [
        f"ALTER TABLE {qualified} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {qualified} FORCE ROW LEVEL SECURITY",
        f'CREATE POLICY "{policy_name}" ON {qualified} '
        f"USING ({tenant_column} = NULLIF(current_setting('app.tenant_id', true), '')::uuid)",
    ]


def tenant_context_exclusion_statements(table: str, *, schema: str | None = None) -> list[str]:
    """DDL statements enabling the *tenant-context exclusion* policy on
    `table` (docs/ADR/0045-installation-scoped-platform-authority.md
    section 9b; ADR-0002 and ADR-0030 amendments of 2026-10-12): the rows
    are visible and writable only in a transaction in which `app.tenant_id`
    is unset or empty. It is the mirror image of `tenant_rls_statements()`,
    for the few global tables (platform authority and platform evidence)
    that no tenant-scoped transaction may ever read or change.

    Behaviour for each state of `app.tenant_id`:

    - never set, or the empty string PostgreSQL resets a transaction-local
      setting to: visible and writable (`NULLIF` maps `''` to `NULL`);
    - a tenant's UUID (`tenant_session_scope()`, or inside
      `bind_tenant_scope()`): no rows, and every insert and update is
      rejected;
    - any other non-empty value: no rows, writes rejected. The expression
      compares for `NULL` and never casts, so it cannot raise.

    With no separate `WITH CHECK`, the `USING` expression governs writes as
    well as reads. `FORCE` is not optional, for the reason
    `tenant_rls_statements()` gives.

    **Defence in depth, not authorization.** `app.tenant_id` is set by
    application code and is not a credential: any code running as the
    application role can open an untenanted transaction or clear the
    variable, and then sees these rows. The policy cannot tell platform
    code from any other code. Who may use platform authority is decided in
    Core (`saas_os.core.platform_authority`), never here.

    `table` and `schema` are trusted identifiers supplied by migration
    authors, as for `tenant_rls_statements()`.
    """
    qualified = f'"{schema}"."{table}"' if schema else f'"{table}"'
    policy_name = f"{table}_no_tenant_context"
    return [
        f"ALTER TABLE {qualified} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {qualified} FORCE ROW LEVEL SECURITY",
        f'CREATE POLICY "{policy_name}" ON {qualified} '
        "USING (NULLIF(current_setting('app.tenant_id', true), '') IS NULL)",
    ]
