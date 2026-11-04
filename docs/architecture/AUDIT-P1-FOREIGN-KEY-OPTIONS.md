# Audit identity phase P1: the `core.users` foreign key (options paper for an owner decision)

**Status: DECIDED by the owner on 2026-11-04 ("apply all recommendations"): option A, implemented as A1 (section 3). The options below are kept as the analysis; A2, A3, B, C, D and E are the rejected alternatives. SQL blocks are sketches that have not been run against PostgreSQL and are not validated DDL. Nothing is implemented; no schema, code, grant or runtime behaviour changes with this document.**

Context: P1 (platform scope of the audit reference mechanism) was blocked by O6 until the owner's decision of 2026-11-04 (section 3). The decision record (`docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md`) records O6 as decided, option (a), "record no target", and adds: "P1 remains blocked until the foreign-key implications are addressed". This paper sets out those implications and the ways to address them; the owner decided on 2026-11-04 (section 3).

Sources read: the decision record (D1 to D8, O2, O3, O6, O7, OD-1 to OD-3); the retention proposal (`docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md`, sections 4.2 to 4.8, 4.13, 8, 9); the inventory (`docs/architecture/AUDIT-RAW-IDENTITY-INVENTORY.md`, PA-2, PA-3, TA-3, TA-5, the P1 to P6 table); and the code on `main` at `99e0f24` (`saas_os/core/platform_authority/{service,audit,oversight}.py`, `saas_os/core/identity/{user_authority,erasure}.py`, `saas_os/core/platform_authority/models.py`, `saas_os/infra/db/rls.py`).

## 1. The exact problem

### 1.1 The constraint

The proposal (section 4.3) defines the platform link table with the same columns as the tenant table, minus `tenant_id`:

```sql
-- Proposal, not run, not validated DDL (proposal section 4.3).
CREATE TABLE core.platform_audit_subject_links (
    subject_ref    uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id        uuid        NULL REFERENCES core.users (id),  -- NULL once unlinked
    subject_day    date        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    unlinked_at    timestamptz NULL,
    unlink_reason  text        NULL,
    CONSTRAINT pk_platform_audit_subject_links PRIMARY KEY (subject_ref),
    -- unlink pairing and reason CHECKs as in the tenant table
);
CREATE UNIQUE INDEX uq_platform_audit_subject_links_live
    ON core.platform_audit_subject_links (user_id, subject_day)
    WHERE user_id IS NOT NULL;
```

Get-or-create (proposal section 4.4, platform variant) inserts `(user_id, subject_day)` in the audit write's own transaction (ADR-0031). For a `user_id` that names no row in `core.users`, the insert fails with SQLSTATE `23503` (`foreign_key_violation`). The proposal states the consequence itself: "For an audit write that is fail-closed (the change rolls back). For platform read attempts on an id that does not exist ... it would turn a 'not found' into an error".

### 1.2 Which writers can name a target user id that is not in `core.users`

`core.platform_audit_log.target_id` is a plain `varchar(255)` with no foreign key (`saas_os/core/platform_authority/models.py`); today any string is accepted. The only constraints on the table are `ck_platform_audit_log_actor_pairing`, `ck_platform_audit_log_actor_type`, `ck_platform_audit_log_outcome` and `ck_platform_audit_log_metadata_size`. **No constraint pairs `target_type` with `target_id`**, so `target_id IS NULL` is already legal for every `target_type`, and a new `target_type` value needs no migration of the audit table (PA-2: "No change to the audit table").

Inventory entry PA-2 lists the writers of `target_type = 'user'` rows (line references are the inventory's). Whether each can name a user that does not exist, from the code:

| # | Writer (call chain) | Row | Can the id name no user? |
|---|---|---|---|
| W1 | `enroll_operator` -> `_run` (`service.py:134`, called with `target_type="user"` at `:357`) -> `record_platform_refusal` | `denied`, target = requested `user_id` | **Yes.** `authority_transaction` authorizes the caller before `body` runs, so a caller who lacks `platform.authority:manage` is refused (`PlatformNotAuthorizedError`) with a target id that was never looked up. For an authorized caller, an unknown user raises `PlatformSubjectNotFoundError`, a `LookupError` and not a `PlatformRefusalError`, so `_run` writes no row for it (unchanged by P1). A refusal naming the caller (`_refuse_self`, `self_authority_change`) names an existing user. |
| W2 | `user_authority._run` -> `_record_outcome` (`user_authority.py:135`) -> `record_platform_refusal` | `denied` or `failure`, target = requested `user_id` | **Yes, by construction for one code.** `PlatformSubjectNotFoundError` is recorded under `_CODE_USER_NOT_FOUND`; the row exists to say the id named nobody. Permission refusals and failures can also carry an unchecked id. |
| W3 | `resolve_user` -> `run_oversight_read` (`oversight.py:174` attempt, `:189` completion, `:170` and `:203` refusals) -> `record_oversight_attempt` | attempt (fail closed, committed **before** anything is read), completion, refusals | **Yes.** The attempt row carries the requested id (`user_authority.py:444-445`) and is written in its own transaction before existence is known. For `GET /users/{user_id}` with a wrong id the completion row falls back to the requested id (`target_id if outcome.target_id is None`), then `PlatformSubjectNotFoundError` is raised. By external identity, `target_id` is already `None` and there is no id. |
| W4 | `_record_success` (`user_authority.py:170`): revoke sessions or API keys, deactivate, reactivate | `success`, in the operation's transaction | No. The operation has just read or changed that user row. |
| W5 | erasure refusal (`user_authority.py:299`) | `denied` | No. `unrevoked_operator_exists` is true only for an `core.platform_operators` row, whose `user_id` is a foreign key. |
| W6 | PA-3 operator events (`service.py:230, :260, :321, :446, :526`), `metadata["user_id"]` | `success` | No. `core.platform_operators.user_id` references `core.users`. |

So the unknown-id rows are the **refusal and failure rows of W1 and W2, and the attempt and completion rows of W3**. All three are evidence of something that did not succeed, and two of the three writers are best effort or run before existence is known:

- `record_platform_refusal` "never raises" and swallows every exception (`audit.py`, `except Exception: ... return False`). A `23503` inside it would **silently lose the denial row**. The docstring already records the same behaviour for an actor that does not exist ("the foreign key refuses it").
- `record_oversight_attempt` is fail closed. A `23503` there raises after the authorization, nothing is read, and the HTTP caller gets an error where it used to get a `404`.
- `core.users` has no RLS and no application path deletes a row from it (erasure keeps `core.users.id`: `erasure.py` module docstring; retention class `GLOBAL_IDENTITY`). Ids are `uuid.uuid4()` (`UUIDPrimaryKeyMixin`, `saas_os/infra/db/orm.py`). A user that exists therefore keeps existing, and the FK cannot fail for an existing user. An id that names no user at write time is almost surely never to name one (122 random bits, server-generated).

### 1.3 Why this matters

1. **Fail-closed evidence of refusals.** A refusal or denial must still be recorded (ADR-0031 section 3, as the writers' docstrings state it). The reference mechanism must not make that evidence disappear (W1, W2) or make the read fail (W3).
2. **No existence leak.** Whatever the writer does must not let a caller learn whether an arbitrary UUID is a user. The caller of a refused request gets only the refusal; any difference must stay in rows only audit readers see, and cost no more than the existing `resolve_user` already tells an authorized operator.
3. **Not turning an audit write into a failure.** An unknown id must not turn `GET /users/{id}` "not found" into an error (the proposal's own wording), and must not abort a mutation's transaction.
4. **Uniform shape.** A reader of `GET /platform/audit` must not take a reference for a user id (hence the new `target_type`, proposal section 4.4).

### 1.4 What O6(a) already decides, and what it leaves open

**Decided (owner, 2026-11-03, merge preparation; decision record, O6):** option (a), "record no target": the row stores nothing about the id asked for. The record accepts the cost: "(a) stores nothing about the id asked for, and loses which id was probed". Option (b), a dedicated `target_type`, was not taken (reason given: "a mistyped real id would be stored raw"). The record also states that P1 stays blocked until the foreign-key implications are addressed.

**Not decided by O6(a), and needed to unblock P1:**

- **O6-1. How the writer knows the id names no user.** The three possible mechanisms (an existence read, catching `23503`, or a caller that already knows) have different races and failure modes (section 2).
- **O6-2. Whether the foreign key stays.** The FK is the thing that raises `23503`; the proposal keeps it as the only database guarantee that a link names a real user.
- **O6-3. What "no target" is, column by column.** `target_type` is `NOT NULL`; "no target" can only mean `target_id IS NULL` (and no reference in metadata). Which `target_type` the row carries (`user`, as the external-identity lookup already does at `user_authority.py:444-445`, or `user_subject`) is not stated.
- **O6-4. The attempt row (W3).** The attempt is committed before the read, in a transaction of its own, so existence has to be decided inside `record_oversight_attempt`, or the attempt row records no target for every by-id lookup (which would also drop the evidence for existing users, against O2 and OD-2).
- **O6-5. The writer's behaviour if get-or-create fails for another reason** (isolation level other than `READ COMMITTED`, three primary-key collisions: proposal sections 4.2 and 4.4) inside the best-effort refusal writer.

Constraints from other decisions that every option must respect: O2 and OD-2 (an existing target, operators included, gets a reference, with no operator test), D1 (one live reference per user per UTC day), D3 (resolution only through the authenticated platform-admin API), D5 (no rewrite of legacy rows), D6, O7 (probes by non-operators are not recorded, so the caller classes that can reach these rows are authenticated operators).

## 2. Options

Shared assumptions: the platform link table is as in 1.1 unless an option changes it; "writer" means the platform target-user helper that P1 would add (proposal section 4.4, `platform_audit_subject_ref`), called by W1 to W3 and by PA-3 writers; every statement runs in the audit write's own transaction and connection (ADR-0031), under `READ COMMITTED`.

### Option A. Keep the FK; the writer decides existence and writes no target for an unknown user (O6(a) applied)

**A1: explicit existence check in the same transaction.**

```sql
-- Sketch, not run. Existence and a lock that blocks a concurrent delete.
SELECT 1 FROM core.users WHERE id = :user_id FOR KEY SHARE;
-- row found:  get-or-create as in proposal 4.4 (platform variant), then
--             target_type = 'user_subject', target_id = '<subject_ref>'
-- no row:     no link row; target_type = 'user', target_id = NULL
```

- **Schema.** None beyond the proposal. The platform link table keeps `user_id uuid NULL REFERENCES core.users (id)`. `FOR KEY SHARE` needs the `UPDATE` privilege on `core.users` (PostgreSQL maps row locks to `ACL_UPDATE`). The runtime role is expected to hold it: migration `e99c76057719` grants `SELECT, INSERT, UPDATE, DELETE` on new `core` tables by default privileges, and existing code already takes row locks on `core.users` (`identity/service.py`, `with_for_update(read=..., key_share=...)`). The grant on `core.users` itself is inferred, not verified here, and is to be checked in the P1 SQL review.
- **Writer logic.** One new helper returns `(target_type, target_id)`: `('user_subject', ref)` for an existing user, `('user', None)` for an unknown one. W1 to W3 call it instead of passing `str(user_id)`. W2's `PlatformSubjectNotFoundError` path already knows the answer and can pass `('user', None)` without a read. W3's `record_oversight_attempt` calls the helper inside its own transaction, after `authorize_platform_caller`, and the completion row uses the same decision, not the requested id.
- **Existence oracle and timing.** `core.users` has no RLS, so the read is visible to the application role in any session. The caller of a refused request sees only the refusal; the difference is in the stored row (reference versus no target), visible to audit readers, who learn only that some probe named an unknown user, never which id. Residual: an existing id costs an extra insert, a small timing difference inside a refusal path that includes the synchronous refusal row. This is the same information `resolve_user` already gives an authorized operator (200 versus 404). Whether to equalise the work is a detail the owner may want to set.
- **Race with user creation or deletion.** Deletion: no application path deletes a user, and `FOR KEY SHARE` also blocks one made by an operator with the migrations role until commit. Creation: the id is server-generated, so an id not yet existing cannot be created later by a caller; if it were, the row says "no target", which was true when written. The row is never wrong in the dangerous direction (a reference for a non-user).
- **Erasure and deletion of users.** The `core.users` row stays after erasure, so the FK holds; erasure unlinks live links (the one-way trigger, proposal 4.3) and records the marker. An unknown-id row has no link to unlink.
- **Id reuse.** Not applicable for ids chosen by `uuid4`. An id that never named a user never gets a link, so a later user with that id (only possible by a deliberate insert with a chosen id) has no pre-existing link to inherit.
- **D1 / D3 / D5 / D8.** D1: unaffected (unknown ids have no reference, so no daily uniqueness question). D3: nothing to resolve for a no-target row; no new lookup surface. D5: legacy rows unchanged; the legacy exception still includes raw ids of non-users already stored. D8: no link row, so nothing in expiry evidence.
- **Migration and compatibility.** The tables are new (P1). Readers of `GET /platform/audit` already must handle the new `target_type` `user_subject`; a row with `target_type = 'user'` and `target_id = NULL` is already produced today by the external-identity lookup, so it is a known shape, but for by-id probes it replaces a raw id and the release note must say so.
- **Tests and evidence.** Unknown id: W1 permission refusal, W2 `user_not_found`, W3 attempt, completion and `404` all write `target_id IS NULL` and no link row, and `GET /users/{id}` still returns `404`. Existing id: the same operations write a reference, equal across rows of one UTC day (D1). A non-existent id never produces `23503` from any writer (assertion on SQLSTATE absence plus the row count). The refusal row is written for an unknown id (it is not lost). A pin test enumerates every call with `target_type` `user` and fails on `str(user_id)`. Negative controls: remove the existence check (the unknown-id test fails with `23503`); write `str(user_id)` again (the pin test fails). Concurrency: two connections, one writing for a new user while the other probes the same id (no error, no wrong reference). A test that no probe changes the response body or status of the refused call.

**A2: let the database decide (catch `23503` in a savepoint).**

```sql
-- Sketch, not run: inside session.begin_nested(); on 23503 naming the
-- foreign-key constraint, roll back to the savepoint and use ('user', NULL).
INSERT INTO core.platform_audit_subject_links (user_id, subject_day)
VALUES (:user_id, (now() AT TIME ZONE 'UTC')::date)
ON CONFLICT (user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING
RETURNING subject_ref;
```

- Same schema, same outputs as A1; no separate read. The decision rests on SQLSTATE and the constraint name (`fk_...`), and it takes the existing savepoint of proposal section 4.2 (the same machinery as the collision retry). A savepoint rollback per unknown probe costs a failed statement and log noise at the server; the unknown-id path is rare and authenticated.
- Oracle, race, erasure, D-items: as A1. Difference: no extra read for existing ids (no timing difference from a read, but the failed insert path is slower for unknown ids). The `23503` SQLSTATE must be distinguished from other failures; any other error follows 1.4 O6-5.
- Tests: A1's list, with the negative control "remove the savepoint catch" (the unknown-id test fails with `23503`).

**A3: single-statement guard (no separate existence read, no savepoint).**

```sql
-- Sketch, not run, not validated DDL. Cannot raise 23503 for a missing user.
INSERT INTO core.platform_audit_subject_links (user_id, subject_day)
SELECT :user_id, (now() AT TIME ZONE 'UTC')::date
 WHERE EXISTS (SELECT 1 FROM core.users WHERE id = :user_id)
ON CONFLICT (user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING
RETURNING subject_ref;
-- then, if no row returned: SELECT subject_ref ... (same day, live) as in
-- proposal 4.4 step 3b; if that finds nothing, the user does not exist.
```

- Same schema and outputs as A1 and A2. The writer learns that the user is unknown when both statements return no row (an inserted or existing live link always returns one), so "unknown" is inferred from the absence of a link and not from a separate read.
- Trade-offs: no extra read and no failed statement or savepoint; but a no-row result on both statements must be told apart from a lost race (a conflicting insert that was rolled back between the statements), which needs the one retry of proposal 4.4 before concluding "unknown". The `EXISTS` subquery takes no row lock, so it does not block a concurrent delete the way `FOR KEY SHARE` does; the FK itself still locks the referenced row at insert time, and no application path deletes users. Reasoning about the plan with `ON CONFLICT` and the `EXISTS` guard must be confirmed in the SQL review (it is not validated here). Oracle, erasure, reuse and D-items as A1.
- Tests: A1's list, plus: an unknown id returns no link after the retry and never raises `23503`; a concurrent first write of an existing user returns one reference; negative control that removes the `EXISTS` guard (the unknown-id test fails with `23503`).

### Option B. Drop the FK; validate in code

```sql
-- Sketch, not run: the link column has no REFERENCES clause.
user_id uuid NULL  -- no foreign key
```

- **Writer logic.** The same existence check as A1 (code decides), but the database no longer enforces it.
- **Effect.** `23503` cannot occur, so W3 and the refusal writer need no fallback for it. The loss: the one guarantee that a live link names a real user moves into code. A code path that forgets the check (including a future writer) can store a link, and so a reference, for an id that names nobody, or for an id of the wrong type of value; the lookup (D3) would then return a `user_id` that exists nowhere. The proposal chose the FK for the same reason it chose RLS and the one-way trigger: defence in depth that holds when code is wrong.
- **Erasure and reuse.** Unchanged in practice (users are never deleted), but with no FK nothing would stop a future user deletion path from leaving live links that name a deleted user and are never unlinked.
- **Oracle, races, D-items, migration:** as A1, minus the FK lock. The proposal's section 8 item 7 lock analysis (`REFERENCES core.users` taking `SHARE ROW EXCLUSIVE` on `core.users` while added) no longer applies, which is a small advantage on an empty table, none in steady state.
- **Tests.** A1's list, plus a negative control that removes the code check and shows an unreferenced link is then stored, plus an architecture test that every link insert goes through the helper. The decision record's O11 interim test (only the get-or-create module names the tables) already narrows who can insert.
- **Does it need an owner decision beyond A?** Yes: it amends the schema stated in proposal 4.3 and removes a guarantee. It does not change any decided behaviour.

### Option C. Deferred or `NOT VALID` constraint

```sql
-- Sketches, not run.
ALTER TABLE core.platform_audit_subject_links
    ADD CONSTRAINT fk_platform_audit_subject_links_user
    FOREIGN KEY (user_id) REFERENCES core.users (id) NOT VALID;
-- or
    ... DEFERRABLE INITIALLY DEFERRED;
```

- **`NOT VALID`** exempts only the rows that already exist when the constraint is added; every new row and every update of `user_id` is still checked. On a new, empty table it changes nothing, and `23503` still occurs on every insert for an unknown id. It is not an option for this problem.
- **`DEFERRABLE INITIALLY DEFERRED`** moves the check to `COMMIT`. The statement succeeds, a savepoint cannot catch the error, and the failure surfaces when the audited transaction commits: the whole change (or the refusal's own transaction, whose swallow-all handler then loses the row) fails at the worst moment. `SET CONSTRAINTS ... IMMEDIATE` inside a savepoint would force the check early, which is A2 with extra steps.
- **Verdict.** Neither variant addresses the problem; recorded so that the owner need not ask. No further analysis is warranted.

### Option D. A separate "unresolved reference" value (a link row with no user)

```sql
-- Sketch, not run. Born-unlinked rows, like the erasure case 3c of proposal 4.4.
ALTER TABLE core.platform_audit_subject_links
    DROP CONSTRAINT ck_platform_audit_subject_links_unlink_reason;
ALTER TABLE core.platform_audit_subject_links
    ADD CONSTRAINT ck_platform_audit_subject_links_unlink_reason
    CHECK (unlink_reason IS NULL OR unlink_reason IN ('erasure', 'expiry', 'unresolved'));
INSERT INTO core.platform_audit_subject_links (user_id, subject_day, unlinked_at, unlink_reason)
VALUES (NULL, (now() AT TIME ZONE 'UTC')::date, now(), 'unresolved')
RETURNING subject_ref;
```

- **Effect.** An unknown id yields a fresh random reference that resolves to nothing, written as `target_type = 'user_subject'`, so every `user` target row looks alike to an audit reader, including erased subjects. The FK stays; the unlink pairing CHECK (`(user_id IS NULL) = (unlinked_at IS NOT NULL)`) and the one-way trigger (live to unlinked only) already admit such a row.
- **It still needs the existence decision** (A1 or A2), because inserting the id for an unknown user would hit the FK. It only changes what is written afterwards.
- **It does not implement O6(a).** O6(a) says "record no target"; this records a target (a reference). The record took (a) because a stored value for a probed id is the thing it declined; a reference that resolves to nothing stores no id, so it may satisfy the intent but not the words. Using it means the owner restates O6, so it is listed as an option, not as a refinement of (a).
- **Costs.** One link row per probe with nothing to deduplicate on (D1's one-reference-per-day key needs a `user_id`), so the table grows with each unknown probe (bounded by authentication and rate limit, not by the schema). An extra `unlink_reason` value, a CHECK change, and an expiry rule for such rows (the proposal's section 4.8 rule keys on records that carry the reference; a rule for references nobody can resolve must be written). The `unresolved` versus `erasure` reason is visible to anyone who can read the link table, which the O11 interim control limits to a few modules.
- **Oracle.** Better than A for audit readers (unknown and erased look the same); the same as A for timing; the lookup API (section 4.5) already answers `404 not_resolvable` for every unresolvable reference, so it gains no new answer.
- **Tests.** A1's list with the shape changed, plus: every unknown-id row has a reference whose link has `user_id IS NULL` and reason `unresolved`; unknown-id probes never create a live link; expiry handles the rows; a negative control that writes a live link for an unknown id fails.

### Option E (excluded by decisions, listed for completeness): write no target for every refusal and attempt row, whether or not the user exists

This needs no existence decision and has no oracle. It contradicts O2 and OD-2: "non-operator targets of failed/refused enrolments get random references" and every target user, operators included, gets a reference. It would also drop the target of every refused action against an existing user. It is not available without reopening O2 and OD-2.

### Comparison

| | A1 | A2 | A3 | B | C (either) | D | E |
|---|---|---|---|---|---|---|---|
| Implements O6(a) as worded | Yes | Yes | Yes | Yes | n/a | No (records a reference) | Contradicts O2 |
| `23503` can reach the caller | No | No (caught) | No (guarded) | Cannot occur | Yes / at commit | No | Cannot occur |
| FK stays (guarantee in DB) | Yes | Yes | Yes | **No** | Yes | Yes | Yes |
| Existence decision needed | Read | Failed insert | None (inferred from no row) | Read | n/a | Read or failed insert | None |
| New schema content | None | None | None | FK removed | FK flags | CHECK value + expiry rule | None |
| Table growth per unknown probe | None | None | None | None | n/a | One row | None |
| Needs the owner to restate a decision | No | No | No | Amends proposal 4.3 | n/a | Restates O6 | Restates O2, OD-2 |

## 3. Decision (owner, 2026-11-04) and the analysis behind it

**DECIDED (owner, 2026-11-04, "apply all recommendations"):** O6's foreign-key implications are addressed by **option A**, implemented as **A1**. The foreign key on `core.platform_audit_subject_links.user_id` stays; the platform writers decide existence in the audit write's transaction with `SELECT ... FOR KEY SHARE` on `core.users`; an unknown id is recorded as `target_type = 'user'` with `target_id` NULL and no link row. The O6-5 fallback is accepted as recommended: if get-or-create fails for a reason other than an unknown user, the best-effort refusal writer (`record_platform_refusal`) still records the denial with a NULL target, while the fail-closed writers (`record_platform_event_in_transaction`, `record_oversight_attempt`) still raise. The timing-equalisation work and the release-note sentence (by-id probes of unknown users no longer store the probed id) are left to P1's own review. The decision is recorded in the decision record (`AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md`, "O6 foreign-key decision"); the roadmap ledger row was updated with it.

**Rejected alternatives, one line each:**
- **A2** (catch `23503` in a savepoint): same outcome as A1, but the decision rests on a SQLSTATE and constraint name and costs a failed statement per probe.
- **A3** (single-statement `EXISTS` guard): same outcome, no row lock on the user, and the most SQL review (`EXISTS` with `ON CONFLICT`).
- **B** (drop the FK, validate in code): removes the only database guarantee that a link names a real user.
- **C** (`NOT VALID` or deferred FK): does not address the problem (new rows are still checked; deferral only moves the failure to commit).
- **D** (an unresolved-reference link row): records a reference, which restates O6(a), and grows the table per probe.
- **E** (no target for every refusal row): contradicts O2 and OD-2.

**Reasons for A1 (the recommendation, now adopted).**

1. It is O6(a) as worded and needs no restatement of O2, OD-2 or O6.
2. It keeps the only database guarantee that a link names a real user (1.2: no path deletes users, so the FK cannot fail for an existing one).
3. A `user_not_found` caller (W2) already knows the answer; only W1's permission-refusal rows and W3's attempt rows need the read, and W3's attempt read runs after authorization, in an operator-only path (O7). The refusal rows of W3 (`recording_platform_refusal`, for an enrolled operator who is not authorized) and W1 would also run the read; the caller's response is the same refusal either way, so the difference is at most timing (low severity).
4. The `('user', NULL)` shape exists today for the external-identity lookup (`user_authority.py:444-445`), so readers already handle it.

**Recorded in the ledger:** the roadmap ledger row for the retention of user ids was updated on 2026-11-04 with this decision.

## 4. What P1 would implement once decided (scope only)

Scope is the decision record and the inventory's P1 row; nothing in this paper adds to it.

- Platform link, erasure-marker and hold tables, with RLS (`tenant_context_exclusion_statements`), role grants and the one-way triggers (proposal 4.3); the FK treatment per the chosen option.
- The platform get-or-create helper in the audit write's transaction (proposal 4.4, with the lock of 4.7), and the existence decision of the chosen option.
- References for every PA-2 target (W1 to W3, W4, W5), operators included, with no operator test (OD-2), under `target_type = 'user_subject'`; and for PA-3 (`metadata["user_id"]` of operator events, as `user_subject_ref`).
- The lookup routes (D3, O4), the O11 interim architecture test, and the platform erasure step.
- The inventory pin test, with a pinned list of every platform operation and the target type it records.
- Release notes: the new `target_type`; raw ids in legacy rows (D5); OD-3's tenant rows stay raw until P3 (O3).

**Remaining blockers and dependencies for P1, after O6 is settled.** O3, O5 and O7 are decided (decision record, 2026-11-03, merge preparation) and none of them blocks P1: O3 puts the tenant scope, the lifting of TA-3's gate and OD-3's tenant references in P3; O5 makes product metadata keys a product obligation (no Core phase waits on it); O7 keeps ADR-0045's existing `404` chain (the lookup routes ship with it, probes by non-operators are not recorded). PR #198 (`platform.security_retention:report`), the register PR #203 (independent register eligibility) and the D2 gate PR #201 are **merged** into `main` (merge commits `09a69f0`, `31b72e2`, `021e487`, all in the history of `99e0f24`). What is still open and gates parts of P1, outside O6: an amendment of ADR-0045's route table for the subject-reference lookup routes (the table's retention section, around line 469, covers only the permission-grant retention routes); the SQL review of proposal section 8 (items 1, 3, 5, 9, 11, 12, 13), which must run before any DDL is final; and the release-note plan for `target_type = 'user_subject'`. The tables, the helper, the writers and the erasure step do not depend on the lookup routes.

## 5. What this paper does not claim

- No SQL here has been run; DDL sketches are labelled and unvalidated.
- The claim that no application path deletes `core.users` rows is from a search of `saas_os/` on `99e0f24` and the erasure module's documented behaviour; test fixtures and operator-level SQL are outside it.
- The claim that ids are server-generated is from `UUIDPrimaryKeyMixin` (`default=uuid.uuid4`); any path that inserts a user with a chosen id is not known to exist and has not been searched for beyond that mixin.
- Timing differences are described, not measured.
- Nothing here changes a decided item. Where an option would restate a decision (D, E), it says so.

## 6. Stale statements (fixed in the same PR, 2026-11-04)

The decision record said the D2 gate was "in PR #201 (open, not merged)" and listed #198 and the register PR as pending in its dependency rows; the retention proposal and the inventory said P1 remained blocked by O6. With the owner's decision of 2026-11-04, this PR updates the decision record (merged-PR status; the "O6 foreign-key decision" section; the O3, O5, O6 and O7 history is kept), the inventory and the proposal (P1 no longer blocked by O6), and the roadmap ledger row.
