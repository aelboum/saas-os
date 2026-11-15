# ADR-0063: Database-enforced restrictions on audit subject lookup

Status: Accepted (2026-11-15, owner): option A for phase P3. Proposed the same day under owner decision O11 of 2026-11-03; the evaluation below is kept as written, and its recommendation (option B) was not taken.
Date: 2026-11-15
Supersedes / Superseded by: none. Option A amends no ADR: ADR-0030's no-`SECURITY DEFINER` rule and ADR-0045 section 9a's single application principal stay as they are (*was:* "If option B is accepted, this ADR narrowly amends ADR-0030 for the named functions only, and adds a database identity on the ADR-0056 pattern").
Related: ADR-0002 (tenant isolation), ADR-0030 (RLS sweep; no `SECURITY DEFINER`), ADR-0031 (same-transaction audit; return only after commit), ADR-0045 (platform authority; sections 9a and 9b), ADR-0053 (audit digests), ADR-0056 (a dedicated database identity), `docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md` (sections 4.3 to 4.10), `docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md` (O11), `docs/architecture/AUDIT-RAW-IDENTITY-INVENTORY.md`.

## Context

### The decision this ADR answers

O11 (owner, 2026-11-03): "API/code enforcement plus architecture tests are acceptable temporarily; before the final phase an ADR evaluating database-enforced lookup restrictions must be prepared." The decision record reads "the final phase" as P3, the tenant scope, and lists nine things the ADR must evaluate. Sections 1 to 9 below answer them in that order.

### The mechanism today (`main` at `9bbdb43`, after P1 and P2)

- A platform audit row about a user stores a random reference (`target_type` `user_subject`), not the user id. `core.platform_audit_subject_links` maps each reference to its user (`user_id`, NULL once unlinked) and to one UTC day (`subject_day`). Erasure and expiry set `user_id` to NULL; a `BEFORE UPDATE` trigger allows only the live-to-unlinked transition, for every role.
- Grants on the platform link table (migration `e2b7c4d9a1f6`): the application role has `SELECT`, `INSERT` and `UPDATE (user_id, unlinked_at, unlink_reason)`, and no `DELETE`. The migrations role owns it. The expiry command (P2) runs as the migrations role.
- The designed lookup routes (`POST /platform/audit-subjects/resolve` and `/list`, proposal section 4.5) are **not built**. The interim control is `tests/architecture/test_audit_subject_link_boundary.py`: only a pinned list of modules may import the link models or name the tables, with a negative control.
- P3 adds the tenant tables (`core.audit_subject_links`, `core.audit_subject_erasures`, `core.audit_identity_holds`) under the tenant RLS policy, and makes every tenant audit write that names a user call get-or-create in its own transaction (lifting the D2 gate).

## 1. Who can resolve a reference today, and what that exposes

| Who | Can resolve a live reference? | Can resolve an unlinked one? |
|---|---|---|
| Application-role code in an allowlisted module | Yes (by design: get-or-create, erasure, expiry planning) | No: the user id is gone from the row |
| Application-role code anywhere else | Yes, with `SELECT`; only the architecture test and review stop it | No |
| Anyone holding the application credential (SQL injection on that connection, a stolen `DATABASE_URL`, code execution in the API or worker) | Yes, for every live link, and nothing is recorded | No |
| The migrations role | Yes (owner) | No |
| A platform operator through the API | Not yet: the lookup routes are not built | No |

Measured against what the inventory says still remains after P1 and P2, the marginal exposure of `SELECT` on the links is smaller than it first looks:

- Anyone with the application credential can already read `core.users`, `core.external_identities` (identity-provider issuer and subject), `core.sessions.verified_email`, the actor ids in audit rows (TA-1 and PA-1, the O1 temporary exception), and, until P3, the raw `initiated_by.user_id` in tenant audit rows (D2's gate).
- Erasure and expiry remove the mapping physically (`user_id` NULL). No database privilege restores it, so neither option below changes what happens *after* erasure.

What `SELECT` uniquely exposes is **unaudited resolution of live references**: turning a reference in an audit row into a person without the attempt and completion rows that the designed lookup writes. After P3 removes the raw tenant `initiated_by` ids, the link tables become the main remaining source for that resolution, so the gap grows with P3.

## 2. Options

### Option A: status quo (API and code discipline, plus architecture tests)

The application role keeps `SELECT` (and, in P3, the same grants on the tenant tables). The architecture test extends to the tenant tables.

- Advantages: nothing new to deploy; no `SECURITY DEFINER`; get-or-create stays plain SQL in the caller's transaction (ADR-0031); proven by P1 and P2.
- Disadvantages: a holder of the application credential resolves every live reference silently; the boundary is a source-code scan, so code that builds SQL dynamically or runs outside the scanned tree is not covered.

### Option B: `SECURITY DEFINER` functions, plus a lookup role

- The application role loses all table privileges on the link tables, and `UPDATE` on them.
- Get-or-create and erasure become `SECURITY DEFINER` functions owned by the table owner, with a pinned `search_path`, `EXECUTE` granted only to the application role, and a check that the tenant argument equals `app.tenant_id`.
- Resolve and list run on a separate **lookup role** (ADR-0056 precedent): `SELECT` on the link tables and `INSERT` on the two audit logs, nothing else, used only inside the lookup transaction.
- Expiry stays on the migrations role.

- Advantages: the application credential can no longer read the links. Through get-or-create, a credential holder can map a user to **today's** reference only, never to a past day's. Resolution needs the lookup credential, and every sanctioned resolution is audited.
- Disadvantages: it amends ADR-0030 and changes the integration tests that assert no `SECURITY DEFINER` function exists (`tests/core/tenancy/test_tenant_purge_integration.py`, `test_purge_audit_integration.py`). It adds a role, a credential and a connection pool to the API process. It puts a function call into every audited write that names a user (P3's hot path).

### Option B': option B without the lookup role

Definer functions for get-or-create and erasure, plus a definer *resolve* function that writes its own audit rows.

- Not viable. A function cannot commit independently, so its audit rows commit or roll back with the caller's transaction. A caller that reads the value and then rolls back has resolved the reference with no evidence. That breaks ADR-0031's rule that the value leaves only after its evidence is durable (see section 6).

### Option C: a role that owns the link tables

A dedicated owner role, with no application-role grants.

- Not viable on its own. Get-or-create must run in the audit write's own transaction and connection (ADR-0031, section 3), and a second role means a second connection. It is the ownership half of option B, not an alternative to it.

### Option D: column-level privileges or views

For example, `SELECT (subject_ref)` only, or a view that hides `user_id`.

- Not viable, as verified in section 4.
  - Get-or-create's conflict target and its re-read (step 3b) need `SELECT` on `user_id`. Erasure's `UPDATE ... WHERE user_id = :u` does too.
  - A role that can filter on `user_id` can map a user to their references. That is the same exposure in the other direction.
  - A view does not help either: a plain view runs with its owner's rights, so it is a definer mechanism without the pinned `search_path` safeguard.

## 3. ADR-0031: get-or-create in the audit write's own transaction

Both A and B keep it.

- Option B's definer function runs in the caller's transaction and connection. It is a function call, not a new session.
- Verified (section 4, Q5d): a rollback of the caller's transaction discards the row the definer function inserted.

## 4. PostgreSQL 16 privilege questions (verified)

**Method.** Each question was checked on PostgreSQL 16.15 (`postgres:16-alpine`, the CI image), in a throwaway database on the disposable test container. Roles were non-superuser and `NOBYPASSRLS`, and the table had the proposed shape with `ENABLE` and `FORCE ROW LEVEL SECURITY`. This is preliminary evidence, not repository tests; section 9 lists the tests that would pin each result.

| Question | Result |
|---|---|
| Q1. `INSERT ... ON CONFLICT (tenant_id, user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING` with `INSERT` only | **Refused** (`permission denied`), with or without `RETURNING`. An arbiter (conflict target) needs `SELECT` on its columns. |
| Q1, with `INSERT` and `SELECT (subject_ref)` | Targeted form: **refused**. Untargeted `ON CONFLICT DO NOTHING RETURNING subject_ref`: **works**, and returns zero rows on a conflict. |
| Q1, re-read step 3b (`WHERE user_id = :u`) with `SELECT (subject_ref)` only | **Refused.** A `WHERE` on a column needs `SELECT` on it. So get-or-create cannot work under column privileges alone (option D). |
| Q2. A `SECURITY DEFINER` function owned by the table owner, under `FORCE ROW LEVEL SECURITY` | The policy **applies to the definer**: it sees tenant A's rows under `app.tenant_id` A, none under B, and none when unset. A definer function owned by a non-`BYPASSRLS` owner does not escape RLS. |
| Q3. `search_path` | An unpinned definer function resolved an unqualified table name to the **caller's temporary table** (`pg_temp`, searched first for relations). Here it failed only because the owner could not read that table; a hijacked function or a table the caller grants would run. With `SET search_path = core, pg_catalog, pg_temp` (temporary schema last), the same function used the real table. Pinning, with `pg_temp` last and schema-qualified names, is required. |
| Q4. `BYPASSRLS` | None of the roles has it. The existing role validation (`validate_application_role()`, ADR-0056 D3's `validate_platform_config_role()`) already refuses `BYPASSRLS`. Option B's owner and lookup role must be checked the same way. |
| Q5. Option B's get-or-create with no table privilege for the caller | Works: it creates on the first call and returns the same reference on the second. A call naming another tenant than `app.tenant_id` is refused (`42501`). A direct `SELECT` by the caller is refused. |

## 5. Erasure and expiry

- **Expiry** already runs as the migrations role (`saas_os.core.audit_identity.expiry`, `migrations_role_session_scope`), so both options leave it unchanged.
- **Erasure** runs as the application role today: `erase_platform_audit_subject` updates `user_id` to NULL inside the user-erasure transaction.
  - Option A: unchanged.
  - Option B: erasure becomes a definer function (`erase_audit_subject(tenant_id, user_id)` and its platform twin) that runs the same one-way update under the same subject lock. The `BEFORE UPDATE` trigger stays.

## 6. Lookup evidence across two connections

The designed lookup (proposal, section 4.5) commits an attempt row first, then authorizes, reads and writes the completion row in one transaction, and returns only after commit.

- Option A: both transactions run on the application connection.
- Option B:
  - The attempt row is written on the application connection and commits first. If it cannot commit, nothing is read.
  - The second transaction runs on the lookup-role connection. It authorizes against the platform tables (column `SELECT`, as in ADR-0056 D2), reads the link and inserts the tenant and platform completion rows, then commits.
  - So the lookup role needs `INSERT` on `core.audit_log` and `core.platform_audit_log`, and the authorization reads.
  - This is why option B' fails: without a separate committing transaction there is no durable evidence before the value leaves.
- A permission refusal is still recorded by `recording_platform_refusal` on the application connection.

## 7. Deployment cost (option B)

- **Roles.**
  - An owner for the link tables: the migrations role stays the owner, so no new owner role.
  - A lookup role, `saas_os_audit_lookup`, created `NOLOGIN` by the migration with the same safeguards as ADR-0056 D5.
  - An init script `saas_os/infra/db/init/03-create-audit-lookup-role.sh`, on the pattern of `02-create-platform-config-role.sh`.
  - Configuration: `AUDIT_LOOKUP_DATABASE_URL` through `SecretsProvider`, with no fallback to `DATABASE_URL`.
- **Process separation is weaker than in ADR-0056.**
  - The AI configuration credential is held only by an operator command. The lookup routes are HTTP routes, so the API process must hold the lookup credential.
  - Code execution in the API process therefore still reaches it.
  - What option B removes is SQL injection on the application connection, a stolen `DATABASE_URL`, and the worker (which never holds it).
- **Pools.** One small pool in the API process, used only by the two lookup routes.
- **Backups.** No change: the same database, and roles are cluster objects (the runbook adds the role to the restore checklist).
- **Hot path.** One extra function call per audited write that names a user. It replaces three statements with one call, so there is no extra round trip.

## 8. The amendment option B needs

- ADR-0030's rule becomes: "no `SECURITY DEFINER` function exists in a SaaS-OS schema, except the audit subject functions named in ADR-0063."
- Each such function:
  - is owned by the migrations role, which is never `BYPASSRLS` or superuser;
  - has `SET search_path = pg_catalog, pg_temp` and schema-qualified names;
  - has `EXECUTE` revoked from `PUBLIC` and granted to the application role only;
  - checks its tenant argument against `app.tenant_id`.
- The purge integration tests' "no `SECURITY DEFINER`" assertion becomes "exactly this allowlist, each with a pinned `search_path`".

## 9. Tests that would prove the chosen option

**For option A (extended to P3):**
- The architecture test covers the tenant tables, with its negative control.
- A privilege test pins the exact grants on all six tables (no `DELETE` for the application role; `UPDATE` only on the three unlink columns).
- The RLS cross-tenant tests from proposal section 4.3 item 6, with both negative controls.

**For option B, in addition:**
1. As the application role: `SELECT`, `INSERT`, `UPDATE` and `DELETE` on each link table are refused. Negative control: restore the grant and the test fails.
2. The definer get-or-create:
   - is idempotent within a day;
   - refuses a tenant argument that differs from `app.tenant_id`;
   - is rolled back with its caller;
   - is subject to RLS. Negative control: an owner with `BYPASSRLS` makes the cross-tenant test fail.
3. `search_path`: a caller-created temporary table and a caller-schema function do not change the result. Negative control: drop the `SET search_path` clause and the test fails.
4. `pg_proc` allowlist: every `prosecdef` function is on the list and has a pinned `proconfig`.
5. The lookup role:
   - its role validation refuses `BYPASSRLS`, superuser, ownership, and membership in the application role;
   - the API refuses to start the lookup routes without the credential;
   - the worker refuses to start with it;
   - the attempt row is committed before the read, and a failure of the lookup connection leaves an attempt row with no completion and no value returned.
6. Erasure through the definer function unlinks exactly that tenant's live links for the user and nothing in another tenant.

## Recommendation

This is a recommendation, separate from the facts above; the owner decides.

**Option B, implemented as part of P3, for the tenant tables and, in the same phase, retrofitted to the platform tables.**

- **Why now.** P3 removes the raw tenant `initiated_by` ids, which leaves the link tables as the main way to turn audit rows back into people. Adding the privilege boundary when the tenant tables are created avoids changing grants on populated tables later.
- **Why not A.** Option A leaves unaudited resolution open to any holder of the application credential. Section 1 shows that today's marginal exposure is small only because raw ids still sit elsewhere, and P3 removes most of them.
- **What B does not fix.** Code execution in the API process still reaches the lookup credential (section 7). That residual should be recorded in the ledger as LOW.

If the owner prefers to keep P3 smaller, the fallback is **option A for P3**, with the section 9 option A tests and a ledger row (MEDIUM after P3, since the gap grows when the raw ids go). Option B then becomes its own phase before `--apply` (O9) is enabled.

## Decision

**Option A for P3 (owner, 2026-11-15).** The owner's answer to "pick option B or A for ADR-0063" was "A".

What this decides:

- P3's tenant link tables get the same grants as the platform tables (proposal, section 4.3): the application role keeps `SELECT`, `INSERT` and `UPDATE (user_id, unlinked_at, unlink_reason)`, with no `DELETE`. No `SECURITY DEFINER` function and no lookup role are added.
- P3 must ship the option A tests of section 9: the architecture test extended to the tenant tables with its negative control, a privilege test that pins the grants on all six tables, and the cross-tenant RLS tests with both negative controls.
- The residual, unaudited resolution of live references by any holder of the application credential, is recorded in the deferred-issue ledger (`docs/P-ROADMAP.md`) as LOW now and MEDIUM once P3 removes the raw tenant `initiated_by` ids.

What this does not decide:

- Whether option B is built later, and when. The fallback text above suggested making B its own phase before `--apply` (O9) is enabled; that remains a recommendation, recorded in the ledger row, not a decision.
- O11's interim character. Option A was accepted "temporarily" on 2026-11-03; this decision makes it the design for P3 as well. Reopening it needs a new owner decision, with this ADR's evaluation as the starting point.

## What Would Be Difficult to Change Later

- **Grants on populated tables.** Moving from A to B after P3 means revoking privileges on tables written by every audited request, during a deployment. B first is cheaper than B later.
- **The `SECURITY DEFINER` exception.** Once allowed, it is a precedent. The allowlist test (section 9, item 4) keeps it from spreading silently.
- **A credential in the API process.** Removing it later means rebuilding the lookup path around a different process boundary.

## Related

- ADR-0030: the rule option B amends.
- ADR-0031: same-transaction audit, and return only after commit (sections 3 and 6).
- ADR-0045 section 9a: one database principal for application code; section 9b: tenant-context exclusion.
- ADR-0056: the precedent for a second database identity (sections 6 and 7).
- `docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md`, O11: the gate and the nine items.
- `tests/architecture/test_audit_subject_link_boundary.py`: the interim control.
