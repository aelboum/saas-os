# Raw SQL expressions and row-level security: threat model (finding F6)

**Status: assessment, 2026-11-01. Changes no code and no public API.** Prepared on `main` `6fd2dfd`. Finding F6 of the universal platform assessment (pull request #187) observed that SQLAlchemy's `.op("<raw SQL>")` can embed SQL such as `set_config('app.tenant_id', ...)`. This document asks whether that is a vulnerability in SaaS OS, who could exploit it, and whether a narrow mitigation is justified. It is kept apart from the R1 code changes on purpose.

## 1. How tenant isolation is enforced

- Each tenant-scoped transaction sets the PostgreSQL setting `app.tenant_id` with `SELECT set_config('app.tenant_id', :tenant_id, true)` (`saas_os/infra/db/session.py`; transaction-local, bound as a parameter).
- Every tenant-owned table has forced RLS with the canonical policy `USING (<tenant column> = NULLIF(current_setting('app.tenant_id', true), '')::uuid)` (`saas_os/infra/db/rls.py`), swept by `tests/infra/db/test_rls_coverage_sweep_integration.py`.
- The application role has no `BYPASSRLS` and owns no `SECURITY DEFINER` function (same sweep).

PostgreSQL lets any role set a custom (dotted) setting such as `app.tenant_id`. **So any SQL the application role executes can change which tenant its RLS predicate admits.** RLS here defends against a missing or wrong `WHERE` clause; it is not a boundary against SQL text chosen by code running in the process.

## 2. The existing fence

- `saas_os.infra.db` exports no `func` and no `text` (CP-07 J-INFRA-05, PRIV-03 RA-01; `saas_os/infra/db/orm.py`), pinned by `tests/infra/test_db_public_surface_unit.py` and `tests/infra/db/test_func_export_removed_integration.py`.
- `docs/CONSUMER-GUIDE.md` section 7: product code outside `migrations/` does not import `sqlalchemy` or `psycopg`. Enforced for this repository's `products` by import-linter, and for the scaffold and the reference consumer by AST tests (`tests/test_consumer_scaffold_unit.py`, `tests/test_reference_consumer_route_security_integration.py`). It is not enforced in an external product unless that product copies the test.

## 3. Ways around the fence that need no forbidden import

| Construct | Reached through | Raw SQL? | Checked 2026-11-01 |
|---|---|---|---|
| `Column.op("<operator>")` / `.bool_op(...)` | Any mapped column attribute of any model | Yes: the operator string is emitted verbatim | Compiled (no database): `Role.name.op("... (SELECT set_config('app.tenant_id','t',false)) ...")(Role.name)` renders that SQL |
| `Session.connection().exec_driver_sql("<sql>")` | `Session`, exported by `saas_os.infra.db` | Yes | `Connection.exec_driver_sql` and `Session.connection` exist in the installed SQLAlchemy |
| `Index(..., postgresql_where="<sql>")` | Exported `Index` | DDL only, at `CREATE INDEX` | Not executable through a session (as `orm.py` already notes) |

## 4. Use of these constructs today

- `saas_os/`, `examples/` and `products/`: no `.op(`, `.bool_op(`, `exec_driver_sql` or `literal_column` (search of 2026-11-01). Raw SQL execution exists only inside `saas_os/infra/`, with constant statements and bound parameters: in `saas_os/infra/db` (for example `session.py`, `role_guard.py`, `platform_config.py`, the backup module and the migration environment) and in `saas_os/infra/health/readiness.py`, whose readiness probe runs `text("SELECT 1")` (corrected 2026-11-02; the first version said `saas_os/infra/db` only).
- No code path in SaaS OS passes request, job or event data into an operator string, a column name or a SQL text. The opt-in routers take integers for paging (`saas_os/api/v1/_common.py`) and values that are compared as bound parameters (usage metrics: `UsageEvent.metric == metric` in `saas_os/core/usage/service.py`); none chooses a column, an operator or SQL text.

**There is no path in SaaS OS by which runtime input reaches raw SQL.** F6 is not a vulnerability in the package as shipped.

## 5. Attackers and capabilities

| Attacker | Needs | Gains through raw SQL | Already has without it |
|---|---|---|---|
| Remote tenant user | A product route that builds an operator or SQL text from request input | Cross-tenant reads and writes on that route's connection (SQL injection, including `set_config`) | Nothing |
| Malicious or compromised product code or dependency | Code execution in the API or worker process | Anything the application role can do | The `DATABASE_URL` credential in the same process: it can open its own connection, so the fence adds nothing against it |
| Careless product developer | Writes `.op(user_input)` or `exec_driver_sql(f"...")` | Turns the first row into a real vulnerability | n/a |

The realistic risk is therefore the first row: **a product introducing SQL injection through an operator or raw statement built from input.** That is a product defect, but SaaS OS's guidance currently implies the import fence is enough ("This keeps every query on the path RLS is enforced on"), which it is not.

## 6. What the fence is worth

Against accidental misuse, real: it removed the two generic constructors (`func.<anything>`, `text`) that made `set_config` one obvious call away. Against deliberate or injected SQL, none: section 3's constructs need no forbidden import. Making it a real boundary would need a database-level design (for example a tenant setting that only a trusted function can change, or per-tenant roles), which is a broad architectural change and is **not** recommended on this evidence.

## 7. Recommendation (narrow; no public API change)

1. **Document the threat model** in `docs/MULTI-TENANCY.md` and `docs/CONSUMER-GUIDE.md` section 7: RLS protects against missing predicates, not against SQL text chosen at run time; products must never build `.op()`, `.bool_op()`, `exec_driver_sql()` or `postgresql_where` text from input.
2. **Extend the existing AST checks** (the scaffold's and the reference consumer's, which products copy) to refuse `.op(`, `.bool_op(` and `exec_driver_sql(` whose argument is not a string literal, and `literal_column` outright. Test-only and example-only; no package change.
3. **Add the same check for SaaS OS's own code** as an architecture test (outside `saas_os/infra/db`), so the package keeps the property section 4 records.
4. **Severity:** INFO for SaaS OS (no reachable path); the product-side risk it guards against would be MEDIUM to HIGH where it exists.

Items 2 and 3 are additive tests. No generic SQL abstraction is proposed, and `func`/`text` stay unexported.

*Update 2026-11-02:* the owner decided on 2026-11-01 to add test-only checks; they are in pull request #191 (open, not merged). How #191 differs from items 1 to 3:

- **Item 1:** #191 adds the rule to `docs/CONSUMER-GUIDE.md` section 7 only; `docs/MULTI-TENANCY.md` is not changed.
- **Item 2:** #191 does not extend the scaffold's or the reference consumer's AST tests. It adds one architecture test, `tests/architecture/test_raw_sql_guardrails.py`, which scans `saas_os`, `examples`, `products` and `scripts`, and the guide tells products to copy it.
- **Item 3:** the boundary is `saas_os/infra/` rather than `saas_os/infra/db`: `text()` is refused outside `saas_os/infra/` and Alembic migrations, and inside them only static text is accepted. The `.op()`/`.bool_op()` rule is stricter than item 2 (a literal of operator symbols only, not any string literal). It adds two rules not recommended here: `.execute()` of a formatted string is refused (migrations excepted), and a migration that formats SQL must validate the identifier it formats. `tests/` is not scanned.
