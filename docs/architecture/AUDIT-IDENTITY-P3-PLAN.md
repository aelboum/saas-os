# Audit identity phase P3: implementation plan (tenant scope)

**Status: Approved (owner, 2026-11-15: "Approve P3 plan"), with every recommendation of section 4 (Q1 to Q5) as written. Proposed the same day.** Nothing in it is implemented yet. Approving it authorizes implementation only; publication (commit, push, PRs, merge, release) follows the usual rules, and you merge each PR that has code or a migration.

**Implementation status (2026-11-15).** P3a is implemented and merged (PR #274, `58b26a4`, 2026-11-15): migration M1 (`c7e3a9f2b4d8`), tenant get-or-create (`saas_os.core.audit_log.subjects`), the writer changes (D2 lift, OD-3) and the tenant erasure step. Two findings from P3a:

- **Added to P3a's scope:** `saas_os/core/permission_grants/apply.py` recorded the operator's raw id (`operator_user_id`) in tenant audit rows. The deferred-issue ledger assigned it to P3 ("key to be decided with the tenant tables"), and this plan missed it. P3a records `operator_user_subject_ref` instead.
- **For P3c:** the P2 hold-evidence trigger cannot be copied as it is to the tenant hold table. A tenant hold is written in a tenant-bound transaction, where `core.platform_audit_log` is invisible (the tenant-context exclusion policy, ADR-0045 section 9b), so a trigger there cannot see the platform audit row that placed the hold. P3c must choose another evidence design, for example the tenant audit row written in the same transaction. M1 therefore creates the tenant hold table without an evidence trigger; nothing writes it until P3c.

**P3b (2026-11-16).** Implemented and merged (PR #276, `8197fad`): migration M2 (`d4f8b2e6a9c1`) builds `ix_audit_log_initiated_by_subject_ref` and `ix_audit_log_owner_user_subject_ref` `CONCURRENTLY` in an autocommit block, drops an invalid leftover first, accepts an index built beforehand, and fails naming an index of that name with another definition. One change from section 3's M2 text: the downgrade drops the indexes with a plain `DROP INDEX` in the run's transaction, not `CONCURRENTLY`, because an autocommitted drop survives a downgrade that an earlier revision refuses (the P3a downgrade refuses while its tables hold rows), leaving the stamp at M2 without the indexes. The cost is an ACCESS EXCLUSIVE lock on `core.audit_log` until the downgrade run commits.

**P3c (2026-11-16).** Implemented and merged (PR #278, `e5c6ec4`): tenant holds through the P2 routes with an optional scope (Q2), the place-only command's `--tenant`, migration M3 (`e1f5a8c3b7d9`, the tenant hold evidence trigger), and the tenant expiry plan, report job and migrations-role command (`--tenant`, one tenant per transaction; `--apply` stays disabled, O9); ADR-0045 amendment of 2026-11-16. Two findings:

- **Correction of the "For P3c" note above.** It was mistaken: a tenant hold is changed in one transaction of ADR-0045 section 9c, and the tenant binding is restored to `''` before commit, so the deferred trigger runs with no tenant bound and can read the platform audit log. P3c therefore keeps scope item 5 and acceptance criterion 5 as written: the P2 trigger, plus the condition that the platform row names the hold's tenant (owner, 2026-11-16: "Plan as approved"). A hold committed while a tenant is still bound is refused, so the check fails closed. The note is kept as written above, as the record of what P3a assumed.
- **The record bound reads a third key.** P3a added `operator_user_subject_ref` (`apply.py`), which section 3's two M2 indexes do not cover. The tenant record bound reads it too, through the tenant's rows of `ix_audit_log_tenant_created_at`, as the platform scope reads its unindexed `user_subject_ref` key; it is rare (permission grant applications). The plan refuses only when one of the two M2 indexes is missing or invalid. A third index is recorded in the ledger as a possible follow-up.

**Basis.**
- The design: `docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md`, sections 4.3 to 4.12 and section 8.
- The decisions: `docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md` (D1 to D8, O1 to O11, OD-1 to OD-3).
- The field inventory: `docs/architecture/AUDIT-RAW-IDENTITY-INVENTORY.md` (TA-3, TA-5, section 9).
- [ADR-0063](../ADR/0063-database-enforced-audit-subject-lookup.md): option A, accepted 2026-11-15.
- The platform scope, already merged: P1 (`40992fe`) and P2 (`9bbdb43`).

## 1. What P3 does

Today a tenant audit row cannot name a user as its initiator. The D2 gate (PR #201) refuses it, so no raw user id is stored, but no initiator is recorded either. P3 adds the tenant half of the reference mechanism. After it:

- A user initiator is recorded as a per-tenant, per-UTC-day random reference (`initiated_by: {"type": "user", "subject_ref": ...}`), and the D2 gate is lifted for that shape only (TA-3).
- Tenant API-key revocation rows written by a platform operation record the key owner as a tenant reference under `owner_user_subject_ref`, no longer as `owner_user_id` (TA-5, platform-marked rows only; OD-3).
- Erasure unlinks a user's references in each tenant it is given. Expiry deletes them after the two-year rule, and legal holds can cover tenant references.

The ids of whoever performed the action (`actor_user_id`, O1) and the other tenant fields of inventory phases P4 and P5 are **not** part of P3.

## 2. Scope

### In scope

1. **Three tenant tables** (proposal, sections 4.3 and 4.9):
   - `core.audit_subject_links`, `core.audit_subject_erasures` and `core.audit_identity_holds`;
   - tenant RLS through `tenant_rls_statements()` (`ENABLE` plus `FORCE`);
   - the one-way `BEFORE UPDATE` triggers on links and holds (not `SECURITY DEFINER`, pinned `search_path`);
   - the hold-evidence constraint trigger of P2, `b6d2f8a4c1e7`'s pattern, which requires the matching platform audit row;
   - retention class `SECURITY_RETAIN`;
   - grants exactly as proposal section 4.3, under ADR-0063 option A: the application role keeps `SELECT`, `INSERT`, and `UPDATE` of the unlink and release columns only, with no `DELETE`.
2. **Tenant get-or-create** (`audit_subject_ref(session, *, tenant_id, user_id)`, proposal section 4.4):
   - called in the audit write's own transaction and tenant-bound session;
   - shared subject lock, then the erasure-marker check, then the live link or a born-unlinked reference;
   - READ COMMITTED enforced, with one retry, then `AuditSubjectLinkUnavailableError`.
3. **Writers.**
   - **D2 lift.** `record_in_transaction` and `record_system_action_in_transaction` accept a user `Initiator` and convert it to the `subject_ref` shape.
   - The metadata gates G1 to G4 and G6 keep refusing every other user-id shape at any depth. G3 learns exactly one new allowed shape, `{"type": "user", "subject_ref": <uuid>}`, which a caller cannot supply directly because the writer builds it.
   - `Initiator.from_metadata()` reads both the legacy shape and the reference shape.
   - **OD-3.** `record_platform_key_revocations` writes `owner_user_subject_ref` instead of `owner_user_id`. Tenant-internal revocations are unchanged: they belong to phase P4.
4. **Erasure** (proposal, section 4.6). In each tenant step of `erase_user_identity()` (`_erase_membership_in_tenant`):
   - insert the tenant marker;
   - unlink the user's live links not covered by an active tenant hold;
   - add counts to the existing erasure rows, never reference values.

   The step is idempotent, so a rerun completes any unfinished tenants.
5. **Tenant legal holds.** The P2 hold routes gain a tenant scope (section 4, Q2): place, release and list for `{"tenant_id": ...}`.
   - They use the same permission as P2 (`platform.security_retention_hold:manage`), the same evidence trigger and the same attempt, change and completion order.
   - The tenant audit row is written in the tenant transaction.
   - The place-only operator command gains the same scope.
6. **Tenant expiry and report** (proposal, sections 4.8 and 4.10):
   - the P2 plan, report job and migrations-role command extend to one transaction per tenant;
   - the record bound uses the new index;
   - `--apply` stays disabled (O9).
7. **The `core.audit_log` index** for the record bound: a partial expression index built `CONCURRENTLY` (section 3).
8. **ADR-0063 option A tests** and the proposal section 8 checks for the tenant tables (section 5).
9. **Docs:**
   - an ADR-0045 amendment for the route change;
   - the consumer guide (D2 lifted: a product may pass a user initiator again);
   - `CHANGELOG.md` release notes: the new `initiated_by` shape, the `owner_user_subject_ref` key on platform-marked revocation rows, and the index deployment step;
   - the runbooks (erasure, holds, expiry);
   - the inventory, proposal and ledger status.

### Out of scope

- **The lookup routes** (`/platform/audit-subjects/resolve` and `/list`), for both platform and tenant scopes. The ledger records them as a separate approval (P-ROADMAP, the P1 row). See Q1.
- **Phase P4:** TA-2 (erasure rows' `resource_id`), TA-4 (`membership.create`), TA-5's tenant-internal rows and TA-6. Each needs a per-field owner decision.
- **Phase P5:** actor ids (TA-1, PA-1, O1), digest format v2 (ADR-0053).
- **`--apply`** (O9).
- **Any rewrite of rows written before P3** (D5: they keep their shape and do not expire).
- **ADR-0063 option B.**

## 3. Migrations

Two migrations, deployed in order.

### M1: tenant tables

- **What it creates.** The three tables, their indexes, RLS, triggers, the evidence constraint trigger, and the grants narrowed from `e99c76057719`'s defaults.
- **Locks.**
  - New, empty tables only, plus the foreign keys. Adding `REFERENCES core.tenants` and `REFERENCES core.users` takes `SHARE ROW EXCLUSIVE` on `core.tenants` and `core.users` while the constraint is added. On new, empty tables that is momentary, but it blocks writes to those two tables for that instant.
- **Data.** Purely additive. Existing code runs unchanged with or without M1.
- **Downgrade.**
  - Refuses while any row exists in the three tables (the PR #198 and P1 pattern), because dropping links destroys the only way to resolve references already written.
  - Otherwise it drops everything and restores the grants.

### M2: expression index on `core.audit_log`

Proposed:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_audit_log_initiated_by_subject_ref
    ON core.audit_log (tenant_id, ((metadata -> 'initiated_by') ->> 'subject_ref'))
    WHERE (metadata -> 'initiated_by') ->> 'subject_ref' IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_audit_log_owner_user_subject_ref
    ON core.audit_log (tenant_id, (metadata ->> 'owner_user_subject_ref'))
    WHERE metadata ->> 'owner_user_subject_ref' IS NOT NULL;
```

- **Why partial.** Only rows written after P3 carry a reference, so the indexes stay small, and no legacy row is ever in them.
- **Why two.** The expiry record bound must see both reference keys. Two narrow partial indexes are simpler to verify than one `COALESCE` expression (to be confirmed by the query-plan check in section 5).
- **`CONCURRENTLY`.** A plain `CREATE INDEX` takes `SHARE` and blocks every audit insert for the whole table scan. `CONCURRENTLY` takes `SHARE UPDATE EXCLUSIVE`, so writes continue. It still scans the whole table, so the build time grows with the table, and it cannot run in a transaction block.
- **Implementation.**
  - Alembic `autocommit_block()`.
  - Afterwards, a check of `pg_index.indisvalid`. An invalid index left by a failed build is dropped `CONCURRENTLY`, and the migration fails with a message naming the index.
  - `IF NOT EXISTS` lets an operator pre-build the index during a quiet period; the migration then finds it and checks that it is valid.
  - This is **new in this repository**: the existing precedents (`d7e4b2a91c36`, `b3d6f8a1c5e7`) use a plain `CREATE INDEX` and only *suggest* a concurrent pre-build. See Q3.
- **Downgrade.** `DROP INDEX CONCURRENTLY IF EXISTS`, in `autocommit_block()`. No data is involved.
- **Deployment order.** M1, then M2, then the code that writes references. Code that writes references without M2 is correct but its expiry record bound would scan the table, so the code refuses to plan expiry for tenant scopes when the index is missing or invalid. Writes do not depend on the index.

## 4. Questions for the owner

Each question has a recommendation; the plan as written assumes the recommendations.

- **Q1. Lookup routes: in P3, or separate?**
  - *Recommendation: separate.* The ledger already records them as a separate approval, and they need their own ADR-0045 route-table amendment and the O4 register-eligibility checks.
  - Consequence: after P3, tenant references, like platform references today, can be resolved only by direct database access under the controls that ADR-0063 option A records. No API resolves them yet.
- **Q2. Tenant holds: extend the P2 routes, or add new ones?**
  - *Recommendation: extend.* `POST /audit-identity/holds` and `GET` take an optional `scope` (`"platform"` or `{"tenant_id": ...}`, default `"platform"`, so existing calls keep working). Release takes no scope, because the hold id determines it.
  - This keeps one route set and one permission. It is a compatible public API change, documented as an ADR-0045 amendment.
- **Q3. The index build: `CONCURRENTLY` inside the migration (new pattern), or the existing precedent?**
  - The existing precedent is a plain `CREATE INDEX IF NOT EXISTS` in the migration, plus a runbook step to pre-build it concurrently.
  - *Recommendation: `CONCURRENTLY` in the migration.* `core.audit_log` takes a write on every audited action, and with the precedent, a deployment that skips the runbook step blocks all audited writes for the whole scan.
- **Q4. How to split the work into pull requests.**
  - *Recommendation: three PRs, each validated and merged separately:*
    - **P3a:** M1, get-or-create, the writer changes (D2 lift, OD-3) and erasure.
    - **P3b:** M2, the index, on its own because it is an operational deployment step.
    - **P3c:** tenant holds, and tenant expiry and report.
  - P3a is useful on its own, because references are written and erasure works. P3c needs P3b for expiry.
- **Q5. Release.**
  - *Recommendation: one minor release after P3c (`0.Y.0`)*, because it has migrations and a new metadata shape that readers must handle.

## 5. Tests and validation

- **Verify on PostgreSQL 16** (proposal section 8; these become integration tests):
  - item 1, the partial unique arbiter under RLS, with a primary-key conflict still raising `23505` and the savepoint retry working;
  - item 2, `NULLS NOT DISTINCT` on the tenant active-hold index;
  - item 5, RLS on the three tables, including `ON CONFLICT DO NOTHING` under RLS;
  - item 6, the one-way triggers;
  - item 7, the lock levels, including M2's;
  - item 8, `json` expression indexability and its query plan;
  - item 13, the isolation-level refusal;
  - item 14, downgrade refusal;
  - item 15, grants;
  - item 16, expiry query plans at volume.
- **Cross-tenant isolation** (proposal section 4.3, item 6): a reference of tenant B looked up under tenant A is refused, also with the explicit predicate removed (RLS alone) and also with RLS disabled (the predicate alone).
- **ADR-0063 option A:**
  - the architecture test `test_audit_subject_link_boundary.py` extended to the tenant tables, with its negative control;
  - a privilege test pinning the grants on all six tables.
- **Gates still refuse:** every shape G1 to G6 refuses today is still refused, including a caller-supplied `subject_ref` shape in metadata. Negative control: remove the writer's conversion and the raw `user_id` shape is refused, not stored.
- **Erasure:**
  - a tenant's links are unlinked and held ones kept;
  - other tenants are untouched;
  - a later write after erasure gets a born-unlinked reference;
  - partial erasure plus a rerun completes the job;
  - lock order checked against product writers (deadlock-retry test).
- **OD-3:** a platform user deactivation writes `owner_user_subject_ref` in each tenant row and no `owner_user_id`. Negative control: the old writer is caught by the inventory test.
- **Expiry:**
  - the tenant record bound uses the index (plan check);
  - eligibility, holds and markers per tenant;
  - `--apply` refused.
- **Holds:** the tenant scope through the routes; the evidence trigger refuses a hold without its platform audit row; the denial matrix extended.
- **Gates on the final tree of each PR:** `scripts/check-backend.sh`; `scripts/check-integration.sh` (zero skips; CI's integration gate is the faster run); detect-secrets; and the migration, packaging and Docker gates in CI.

## 6. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| The M2 build on a large `core.audit_log` takes a long time, or fails part-way and leaves an invalid index | MEDIUM | `CONCURRENTLY` (writes continue); an `indisvalid` check, plus dropping the invalid index and failing; an optional pre-build; runbook timings |
| Get-or-create adds work to audited writes that name a user (an advisory lock and up to three statements) | LOW | Only writes with a user initiator, or OD-3 rows, take this path, and no Core path passes a user initiator today. Measured in the integration suite |
| Deadlock between the erasure step and product writers in a tenant | LOW | The lock order of proposal section 4.7; the conflict is retryable; a test covers it |
| Lifting D2 lets a consumer record user initiators, which then exist as references | INFO | This is the intended behaviour. The references are unlinked on erasure and expire under D7; the consumer guide says so |
| Unaudited resolution of live references by a holder of the application credential | LOW now, MEDIUM after P3 | Accepted under ADR-0063 option A; already in the ledger; revisit before O9 |
| A reader of platform-marked `api_key.revoke` rows expects `owner_user_id` | LOW | Release notes; readers handle both keys |

## 7. Acceptance criteria

1. No tenant audit row written after P3 stores a raw user id under `initiated_by`, or under `owner_user_id` in a platform-marked revocation row. A user initiator is stored as a reference, never refused, and never stored raw.
2. A reference resolves only inside its tenant; cross-tenant access is refused by RLS alone and by the predicate alone.
3. After erasure in a tenant, that tenant's references of the user resolve to nobody, except held ones. New writes get born-unlinked references.
4. The tenant expiry plan and report run per tenant using the index; `--apply` stays disabled.
5. Tenant holds can be placed, listed and released through the routes, with platform audit evidence enforced by the database.
6. Every test listed in section 5 passes, and the full gates pass on each PR's final tree.
7. The docs, ledger and release notes match the implementation.
