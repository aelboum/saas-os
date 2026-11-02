# Verifiable approval for deleting expired permission grant ledger rows

**Status: Design proposal; not implemented; requires the owner's approval.** Date: 2026-11-02. Nothing here is built. Until it is, deleting expired ledger rows is disabled (`saas_os.core.permission_grants.expiry._DELETION_ENABLED = False`; `LedgerDeletionDisabledError`, code `deletion_disabled`).

Related: ADR-0045 (platform authority; amendment of 2026-11-02, "Separation of duties"), `docs/RUNBOOKS.md` ("Granting legal-hold management", "Deleting expired permission grant ledger rows"), PR #198.

## 1. The rules this must satisfy (owner, 2026-11-02)

1. Deleting expired ledger rows needs a verifiable approval.
2. A person who releases a legal hold must not be able to authorise, on their own, the deletion of the same records.
3. The declared operator name of a command is not an authenticated identity and must not be treated as one.
4. No further runtime permission (the vocabulary stays at twenty-eight). No runtime `DELETE` on the ledger.
5. Deletion stays a manual migrations-role procedure, never part of an automatic purge.

## 2. Why the existing architecture cannot meet rules 1 and 2

| Step | Entry point today | Who is identified | Authenticated? |
|---|---|---|---|
| Retention report | `saas-os-operator permission-grant-ledger-retention --operator <id>` | declared user id | No: whoever holds the application database credential types it |
| Place / release a hold | `saas-os-operator hold-permission-grant-ledger` / `release-permission-grant-ledger-hold --operator <id>` | declared user id | No (same) |
| Delete expired rows | `python -m saas_os.ops.permission_grant_ledger_expiry --operator <id>` | declared user id | No: whoever holds the migrations credential types it |
| Grant or revoke platform permissions | platform-admin HTTP API (`saas_os/api/platform_admin/router.py`, `require_platform_permission`) | the OIDC-authenticated session's user | **Yes** |

Core checks that the *named* user may perform each operation (`authorize_platform_caller`); it cannot check that the person running the command is that user. A rule "approver ≠ releaser" evaluated over two declared ids is therefore defeated by one person who holds the credentials and declares a different eligible operator for each step. That is not separation of duties, so deletion is disabled rather than given a check that would only look like one.

## 3. Proposed control

The idea: the approval is the one step that must be authenticated, and it is recorded in a form the migrations-role procedure can verify but not forge without leaving evidence.

### 3.1 Approval through the authenticated platform-admin API

- New route `POST /platform/permission-grant-ledger/deletion-approvals` (platform-admin router), body: the eligible tenant ids, `eligible_ledger_rows`, `eligible_digest` and a ticket reason, all copied from a report.
- Authority: `platform.security_retention:report` (no new permission), via `require_platform_permission`, so the approver is the OIDC session's user, never a declared id.
- Core function `approve_permission_grant_ledger_deletion(...)`, one transaction:
  1. authorise the caller (person only; no system purpose);
  2. lock the scoped tenant rows `FOR UPDATE` in id order (the lock hold placement already takes);
  3. recompute eligibility, row count and digest with the database clock; refuse `confirmation_mismatch` unless both equal the request;
  4. **releaser rule:** refuse `approver_released_hold` if the caller's user id is the `actor_user_id` of the platform audit row named by `released_by_platform_audit_id` of *any* hold, active or released, on any tenant in scope (released holds are kept forever, so this is decidable);
  5. insert one row in a new table `core.permission_grant_ledger_deletion_approvals` and one platform audit row (`platform.permission_grant_ledger.deletion_approve`) in the same transaction.

The hold release itself must then also be authenticated for rule 2 to compare two authenticated identities. So the design moves hold placement and release to the same API (`POST .../holds`, `POST .../holds/{id}/release`, permission `platform.security_retention_hold:manage`), and retires the two `saas-os-operator` hold commands. A hold released before the change was released under a declared id, so the releaser rule cannot be trusted for it; decision 3 below proposes a conservative treatment that errs on the side of keeping rows.

### 3.2 The approval record

```sql
CREATE TABLE core.permission_grant_ledger_deletion_approvals (
    id uuid PRIMARY KEY,
    tenant_ids uuid[] NOT NULL,              -- sorted, distinct, 1..1000
    eligible_ledger_rows integer NOT NULL CHECK (eligible_ledger_rows > 0),
    eligible_digest char(64) NOT NULL CHECK (eligible_digest ~ '^[0-9a-f]{64}$'),
    approved_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,          -- approved_at + 72 hours
    approved_by_platform_audit_id uuid NOT NULL,
    consumed_at timestamptz NULL,
    consumed_by_platform_audit_id uuid NULL,
    CHECK ((consumed_at IS NULL) = (consumed_by_platform_audit_id IS NULL)),
    CHECK (expires_at > approved_at)
);
```

- Exclusion RLS policy (untenanted platform table), like `core.permission_grant_ledger_holds`.
- Runtime role: `SELECT`, `INSERT`; no `UPDATE`, no `DELETE`. Only the migrations role sets `consumed_*`.
- A `BEFORE UPDATE` trigger (the holds table's one-way pattern) refuses any change except setting `consumed_at` and `consumed_by_platform_audit_id` once, from null.
- The approver is the `actor_user_id` of `approved_by_platform_audit_id`; it is not duplicated in the table.

### 3.3 Consumption by the migrations-role procedure

`expire_permission_grant_ledger_rows(..., approval_id=...)` replaces `confirm_rows`/`confirm_digest`. In its one transaction, after locking the tenant rows:

1. lock the approval row `FOR UPDATE`; refuse `approval_not_found`, `approval_consumed`, `approval_expired` (database clock);
2. recompute eligibility, count and digest; refuse `confirmation_mismatch` unless they equal the approval's, and unless the scoped tenants are exactly `tenant_ids`;
3. re-apply the releaser rule against the approver (a hold placed and released after the approval changes the digest, so this is a second, independent check);
4. refuse `executor_is_approver` when the declared executor equals the approver. This is **not** a security control (the executor is declared); it stops an honest single-person run and is labelled as such;
5. delete, write the run and per-tenant platform rows (metadata gains `approval_id`), and set the approval's `consumed_*` to the run row: single use, in the deletion's transaction.

### 3.4 What is verifiable, and what is not

- Verifiable: the approver is an OIDC-authenticated operator holding the report permission; the approver did not release a hold on any tenant in scope (with 3.1's API-only holds); the approval names exactly the rows deleted; it is used once and within 72 hours; every step has a platform audit row in its own transaction, covered by the audit digests of ADR-0053.
- Not verifiable: who ran the migrations-role command. Whoever holds the migrations credential can also delete rows with plain SQL, bypassing all of this; as with `saas_os/core/platform_authority/bootstrap.py`, the procedure makes the legitimate path the audited one, it does not bind the credential holder. Detection relies on the audit digests and on comparing ledger row counts with approval and run records.

## 4. Alternatives considered

| Option | Real separation of duties? | Cost | Verdict |
|---|---|---|---|
| A. Keep deletion disabled (current) | n/a: nothing is deleted | Rows kept beyond two years | Safe default; meets the policy's "no uncontrolled deletion" |
| B. Compare declared ids (approver ≠ releaser) in the CLI | No: one credential holder declares both | Small | Rejected: looks like a control, is not one |
| C. Authenticated approval API + approval table (this design) | Yes, for approval and hold release | New routes, one table, migration, tests | Recommended when deletion is needed |
| D. Two-person database credential (split migrations secret, dual control in the secret store) | Partly: outside SaaS OS, no audit link to the rows | Operational, provider-specific | Complement to C, not a substitute |
| E. Signed approvals (operator signs the digest with a personal key registered out of band) | Yes, if key custody is personal | Key registry, signature verification, rotation | Heavier than C; reconsider if no HTTP route is acceptable |

## 5. Decisions needed before implementation

1. Accept HTTP routes for ledger retention (approval, hold placement and release), reversing "operator commands only" for these operations.
2. Approval validity window (proposed 72 hours).
3. Treatment of holds released through the operator command before the change (proposed: their tenants' rows need an approval by an operator who did not hold the report permission when the hold was released, or stay retained).
4. Whether the executor must also be distinct from the approver through an authenticated channel (would need option D or E).
5. Timing: implement now, or keep deletion disabled until the first tenant actually reaches two years after its purge (none can before 2028 on an installation that purges from now).
