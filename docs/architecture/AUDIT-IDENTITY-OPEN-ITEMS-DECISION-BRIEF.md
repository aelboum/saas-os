# Audit identity retention: decision record (owner decisions of 2026-11-02 and 2026-11-03)

**Status: Decision record. Items D1–D8, O1, O2, O4, O8, O9, O10, O11, OD-1, OD-2, OD-3, the hold route permission and the two-year rule are decided by the owner; O3, O5, O6 and O7 await the owner and are set out in one decision matrix under "Items awaiting the owner". Not implemented, except the D2 gate, which is in PR #201 (open, not merged).** Decisions D1–D8 and O1 were made on 2026-11-02 and D1–D8 were restated by the owner on 2026-11-03; O2, O4, O8, O9, O10 and O11 were decided on 2026-11-03; OD-1, OD-2, OD-3 and the hold route permission were decided on 2026-11-03 (final closure). The owner's 2026-11-03 text does **not** authorise implementing the reference and link-table schema or runtime: they stay design (`docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md`, the proposal) and need separate implementation approval. No schema, code, grant or runtime behaviour changes with this document. SQL mentioned here has not been run against PostgreSQL. Date: 2026-11-03.

Until 2026-11-03 this file was a decision brief that set out options and recommendations for O2, O4, O8, O9, O10 and O11 (commits `f752b90`, `50bd084`, `1e9e215`). Each entry keeps one line of that history. The raw user identifiers that remain outside the decided scope are inventoried, with a phased remediation design, in `docs/architecture/AUDIT-RAW-IDENTITY-INVENTORY.md` (the inventory).

**Dependencies outside this branch, referred to and not specified here.**
- **PR #198** (`feat/permission-grant-migrations`, not merged) adds four platform permissions, among them `platform.security_retention:report` (24 on this branch, 28 with #198).
- **The approver eligibility register** (PR #198's decision 13, option A, decided 2026-11-02) is being implemented with #198's authenticated retention API in a separate PR stacked on #198. This record uses one property of it, **independent register eligibility**, as PR #198's `docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md` section 4.5 defines it ("Eligibility at use", checked with the DB clock `t`): an `approver_enrolment` of the user with `eligible_from <= t < valid_until` (`eligible_from` is the enrolment time plus 120 days), not revoked, whose authorising designation is not revoked; and, read separately, an active operator holding `platform.security_retention:report` and not holding `platform.authority:manage`. That design is the authority for the definition; this record specifies nothing else about the register.
- **PR #201** (`feat/audit-d2-initiator-gate`, base `feat/system-actor-step1`, not merged) implements the D2 gate. On 2026-11-03 it is being extended to `record_platform_event_in_transaction` (`metadata["initiated_by"]`), with an audit of call sites and consumers. #201 is the authority for what it implements and for its evidence.

Facts verified on this branch (`feat/system-actor-step1`):

- Platform permissions: 24 values in `PlatformPermission` (`saas_os/core/platform_authority/permissions.py`), mirrored by the database CHECK `ck_platform_grants_permission` (`saas_os/infra/db/migrations/versions/c4a9e1f07b52_create_platform_authority_tables.py`).
- The only authenticated operator channel is the platform-admin router (`saas_os/api/platform_admin/router.py`) behind `require_platform_permission` (`saas_os/api/dependencies.py`). Operator commands take declared ids (`saas_os/ops/operator_cli.py`).
- No `SECURITY DEFINER` and no `BYPASSRLS` exist anywhere. There is one precedent for a second database role: the platform-configuration role of ADR-0056 (`platform_config_session_scope`, `saas_os/core/platform_authority/transactions.py`), guarded by `tests/architecture/test_platform_config_boundary.py`.
- Whether a user is an enrolled operator is decided by `unrevoked_operator_exists` (`saas_os/core/platform_authority/owners.py`), which tests for an operator row that is not revoked. It is the same test that refuses the erasure of an enrolled operator.

Each entry gives: the decision (the owner's words), the rationale (short), what the design does (proposal section), and the evidence and tests the item needs **when it is implemented**. None of those tests exists yet unless an entry says so.

## D1. Reference granularity

**Decision (2026-11-02; restated 2026-11-03):** "random user reference per user per UTC calendar day."

- **Rationale.** After expiry, a reference shows only that records of one day were made by the same subject. A shorter period would link nothing; a longer one links more.
- **Design.** One live reference per (scope, user, UTC day). Scope is one tenant, or the platform. The day is `(now() AT TIME ZONE 'UTC')::date` of the audit write's transaction. The value is `gen_random_uuid()` and is never derived from the user id (proposal, sections 4.2 and 4.4).
- **Evidence and tests.** Two writes on one UTC day give one reference, and writes either side of 00:00 UTC give two, in each case under session time zones of UTC−12 and UTC+14. Concurrent first writes give one reference (two connections). A primary-key collision is retried at most three times and is never merged into another subject. References of two tenants, or of a tenant and the platform, are never equal for one user.

## D2. No new user initiators in `initiated_by`

**Decision (2026-11-02, scope settled by O1 on 2026-11-02; restated 2026-11-03):** "reject new user initiators in `initiated_by`; the `actor_user_id` database requirement remains a temporary documented exception."

- **Rationale.** Until references exist, the only way not to store a raw initiator id is to refuse it. `actor_user_id` cannot be omitted while `ck_audit_log_actor_type_user_id_pairing` and `ck_platform_audit_log_actor_pairing` require it for user actors.
- **Design.** The gate is implemented in PR #201, not on this branch. The existing outbox storage of initiators and their rewrite on erasure are unchanged. Proposal, section 7.
- **Compatibility unit (owner, 2026-11-03).** #196 is never merged without #201. On this branch alone, user initiators are still accepted in audit records.
- **Scope of the gate.** The gate covers `initiated_by` only. For each other field holding a user id, the inventory states why the gate does not apply to it. Those fields mean something else (actor, target, resource owner, related party), and refusing them would refuse the audited action itself or remove required evidence.
- **Evidence and tests.** These are in PR #201, which is the authority for them: refusal before any insert in every writer and alternate path, no raw user initiator in any new audit row, and the outbox erasure tests unchanged.

## D3. Identity lookup

**Decision (2026-11-02; restated 2026-11-03):** "identity lookup only through the authenticated platform-admin API; every lookup audited."

- **Rationale.** A declared operator id is not proof of identity. The platform-admin API has an OIDC session, MFA where required, and refusal audit.
- **Design.** `POST /platform/audit-subjects/resolve` and `POST /platform/audit-subjects/list`, with an attempt row committed before reading and a completion row after it. The value is returned only after commit, and no row records the resolved user id (proposal, section 4.5). The permission and the eligibility requirement are set by O4, and database enforcement is covered by O11.
- **Evidence and tests.** No operator command and no Core function taking a declared id can resolve: an architecture test enumerates the callers. Every request that reaches the permission check leaves attempt and completion rows, or a refusal row. A failed attempt-row commit reads nothing. The response is sent only after commit and carries `Cache-Control: no-store`. A reference of another scope gives the same not-resolvable answer as an unknown reference.

## D4. Legal holds

**Decision (2026-11-02; restated 2026-11-03):** "legal holds take precedence; the first expiry run after release processes newly eligible records."

- **Design.** A hold matching a link's scope, subject and day keeps the link through expiry and erasure. Release deletes and unlinks nothing; the next expiry run does (proposal, section 4.9).
- **Evidence and tests.** A held link survives expiry and erasure. After release, the first expiry run deletes links whose retention passed during the hold, and unlinks the held live links of erased subjects. A released hold cannot be changed (trigger, every role). A run that starts while a hold is being placed waits on the scope's hold lock.

## D5. Existing records

**Decision (2026-11-02; restated 2026-11-03):** "existing raw-ID audit records remain a documented legacy exception; do not rewrite existing audit records or their digests in this phase."

- **Design.** Proposal, section 4.13. The release notes and the privacy notice state the exception.
- **Evidence and tests.** The ADR-0053 verifier reports no change across a full mechanism rollout on a database seeded with legacy rows: digests recorded before the rollout recompute identically after it.

## D6. Initial scope

**Decision (2026-11-02; restated 2026-11-03):** "target users in platform audit records only; operator identities are excluded from this policy."

- **Reading (OD-1 and OD-2, decided 2026-11-03, final closure).** The operator exclusion applies to a person in the role of **actor**, and an "actual operator" is a natural person performing an authenticated privileged operation (OD-1). A person who is the **target** of an action gets target-user reference treatment whether or not that person is an operator (OD-2).
- **Design.** The first phase covers platform rows whose target is a user, whoever the user is (O2 as read with OD-2), and the `user_id` metadata of operator events, which names the user behind the operator acted on (inventory, PA-3). Operators' own identities as actors (the platform `actor_user_id`, the operator id of an operator's own login row, audit-read filters naming the actors of the rows queried) stay raw under a separate, undecided operator retention policy. Operator ids as targets (`target_type = 'platform_operator'`, `previous_operator_id`) are target identifiers too, but they are not user ids: they stay as the operator record's identifier and are linkable only while `core.platform_operators.user_id` keeps the person (inventory, PA-7, PA-8 and OP-19).
- **Evidence and tests.** A pinned table enumerates every platform operation and the target type it records, so a new operation must be classified (see O2).

## D7. Expiry runner

**Decision (2026-11-02; restated 2026-11-03):** "migrations-role expiry command with dry run and explicit confirmation; scheduled jobs may only report."

- **Design.** Proposal, section 4.10. `--apply` is further gated by O9.
- **Evidence and tests.** The application role has no `DELETE` on the link, marker or hold tables (grant test). The report job runs as the application role and cannot delete. The default is a dry run. `--apply` refuses on any mismatch of `--confirm-rows`, `--confirm-digest`, `--confirm-holds` or the unlink and marker counts, deleting nothing in that scope.

## D8. Deletion evidence

**Decision (2026-11-02; restated 2026-11-03):** "deletion evidence = counts + SHA-256 over the canonicalised affected references; do not claim it proves the integrity of deleted link-table contents."

- **Design.** Canonical form v1 in proposal section 4.11. It applies to expiry runs only; erasure records counts only, because an erasure row already names the user.
- **Evidence and tests.** Fixed test vectors: the empty set, one reference, ordering by bytes, a duplicate refused, upper case refused, and the scope bound into the message. The hash in the audit row equals a recomputation from the dry-run list. No document or message claims that it proves what the deleted rows contained.

## Two-year expiry calculation (kept; owner, 2026-11-03)

**Decision (2026-11-03):** "Keep the exact two-year expiry calculation on each record's `created_at`, including leap-day handling."

**The exact rule.**

1. **Expiry instant.** For an audit record `r`, take `created_at` (as stored, `timestamptz`) and express it in UTC as a date `Y-M-D` and a time of day `τ` (microseconds). Its expiry instant `E(r)` is the UTC instant with date `(Y + 2)-M-D` and time of day `τ`. A 29 February can only fall in a leap year `Y`, and `Y + 2` is then never a leap year. If `M-D` is 02-29, the date of `E(r)` is therefore `(Y + 2)-02-28` with the same `τ`. No other date is adjusted. The session time zone and daylight saving play no part, because the date is taken in UTC first.
2. **Inclusive boundary.** `r` is past retention at instant `n` exactly when `E(r) <= n`, with `n` taken from the database clock (`now()`, the transaction start).
3. **Links.** A link may be deleted only when both of the following hold: (a) every record that carries its reference as user identification satisfies `E(r) + 1 day <= n`; and (b) the day bound `((subject_day + interval '2 years')::date + 2)::timestamp <= now() AT TIME ZONE 'UTC'` holds. A link therefore never expires early, and outlives its records by at most two days plus the delay until the next expiry run, plus any hold (proposal, section 4.8).
4. **Erasure markers** use the same rule on `erased_at` (O10).

**Worked values** (they become test vectors):

| `created_at` | `E(r)` (UTC) |
|---|---|
| `2028-02-29 12:00:00+00` | `2030-02-28 12:00:00` (730 days) |
| `2028-02-28 12:00:00+00` | `2030-02-28 12:00:00` (731 days; the same instant as the record above) |
| `2027-03-01 00:00:00+00` | `2029-03-01 00:00:00` (731 days, across 29 February 2028) |
| `2028-02-29 00:30:00+01` | `2030-02-28 23:30:00`: UTC is taken first (`2028-02-28 23:30`), so the date is not 29 February |
| `2028-12-31 23:59:59.999999+00` | `2030-12-31 23:59:59.999999` |

**Implementation.** The proposed SQL is `(created_at AT TIME ZONE 'UTC') + interval '2 years'`, on `timestamp` and never on `timestamptz + interval`. PostgreSQL adds years by calendar fields and, when the resulting day does not exist, uses the month's last day, which matches rule 1. That behaviour is the item the SQL review must confirm on PostgreSQL 16 (proposal, section 8, item 4), using the vectors above. The rule above is normative; if the SQL disagrees with it, the SQL changes, not the rule.

## O1. Reach of D2 (decided 2026-11-02)

"D2 applies to `initiated_by`. New audit records must reject user initiators that would store raw user IDs in `initiated_by`. Existing mandatory `actor_user_id` storage remains a temporary exception because current database constraints require it for user-actor records." The fields that stay raw are listed in the inventory.

## O2. Operator identities and failed or refused enrolments

**Decision (2026-11-03):** "separate actual operator identities from failed/refused enrolments; actual operator identities stay outside this target-user scope; non-operator targets of failed/refused enrolments get random references."

- **History.** On 2026-11-02 the brief offered A (all out of scope), B (all in scope) and C (split by outcome; recommended). The decision takes C.
- **Rationale.** An operator's own acts remain accountable under the separate operator policy (D6). A person who never became an operator is an ordinary target user, and so, by OD-2, is an operator on whom an action is performed.
- **OD-1, decided (owner, 2026-11-03, final closure):** "actual operator" means a natural person performing an authenticated privileged operation. It is a property of the **actor** of a row. A declared id (an operator command's `--operator`, `purge-tenant --actor`) is not an authenticated operation, so the person it names is not an actual operator under OD-1; such an actor id stays raw as the O1 actor exception, not under the operator exclusion (inventory, PA-1 and PA-5).
- **OD-2, decided (owner, 2026-11-03, final closure):** the operator exclusion applies when the person is the actor, not when that person is the target of an action; an operator who is the target of an action gets target-user reference treatment like anyone else. This replaces the 2026-11-03 recommendations of this entry (a write-time test of whether the target is an operator, with option (a) `unrevoked_operator_exists`); they are kept here as history only.
- **Design.** Every row with `target_type = 'user'` is in the first-phase scope, and the writer does **no** operator test: it writes a platform reference with `target_type = 'user_subject'`. These rows are the refusal rows of `enroll_operator` (`_run`, `saas_os/core/platform_authority/service.py:134`, called with `target_type="user"` at `:357`), the rows of `saas_os/core/identity/user_authority.py` (`:135`, `:170`, `:299`) and the rows of `resolve_user` through `run_oversight_read`. That includes rows that until OD-2 were to stay raw: the refused erasure of an enrolled operator (`:299`), a refused enrolment naming the caller (`self_authority_change`, where the actor column still names the same person raw, as the O1 exception), and every user operation whose target is an enrolled or revoked operator. The `user_id` metadata of operator events (inventory, PA-3) names the target operator's user and moves into the same scope. A successful enrolment row targets the operator id (`target_type = 'platform_operator'`), which is not a user id (D6, "Design").
- **Evidence and tests.** A pinned table of every platform operation and the target type it records. A refused enrolment of a non-operator, a refused enrolment of the caller, an enrolled-operator erasure refusal and a deactivation of an operator each record a reference, never the raw id, in the target. The actor column of each still holds the authenticated actor (O1). The same operation gives the same target type whether its target is enrolled, revoked or never enrolled. A negative control that restores an operator test in the writer makes the operator-target reference test fail.

## OD-3. Tenant API-key revocation rows naming a platform target user

**Decision (2026-11-03, final closure):** tenant API-key revocation records naming a platform target user remain subject to target-user reference treatment.

- **Rows concerned.** The tenant `api_key.revoke` rows with `"platform": true` that `record_platform_key_revocations` (`saas_os/core/api_keys/service.py:844`, row at `:860`, key `owner_user_id` at `:867`) writes for the platform operations `revoke_user_api_keys` and `deactivate_user` (inventory, TA-5). Tenant-internal revocations by a tenant administrator are not covered by OD-3 and stay with TA-5's phase P4.
- **History.** The inventory offered (a) leave it to P4, (b) omit `owner_user_id` from new platform-marked rows in P1 (recommended), and (c) a tenant reference after P3. The decision takes reference treatment, so the key is replaced by a reference, not omitted.
- **Design.** These are tenant audit rows, so the reference is a **tenant** reference (D1: a reference's scope is one tenant or the platform; tenant rows resolve only within their tenant), written under a new key `owner_user_subject_ref` by the same get-or-create as tenant initiators. It therefore ships with the tenant tables, in P3, or with P1 if O3 is decided that way. Until then these rows keep `owner_user_id` raw, and the P1 release notes must say so.
- **Evidence and tests.** A platform deactivation and a platform API-key revocation write tenant rows with `owner_user_subject_ref` and without `owner_user_id`; the reference resolves only in that tenant's scope and equals the reference of other rows of the same user, tenant and UTC day; a tenant-internal revocation is unchanged until P4. A negative control that writes `owner_user_id` again fails the test.

## O4. Permission for the lookup

**Decision (2026-11-03):** "no new permission; identity lookup requires `platform.security_retention:report` AND independent register eligibility."

- **History.** On 2026-11-02 the brief offered (i) `platform.user:read`, (ii) `platform.audit:read`, (iii) a dedicated permission (recommended at the time), and (iv) an existing permission plus register eligibility. The decision is a form of (iv). The permission vocabulary stays at 28 once PR #198 merges.
- **Rationale.** A permission that the platform owner can grant to another account of their own does not separate people. Eligibility from the independent register adds a check that the owner cannot satisfy alone.
- **Design.** The routes declare `require_platform_permission(PlatformPermission.SECURITY_RETENTION_REPORT, ...)`. This name is PR #198's member for `platform.security_retention:report` and is not on this branch. The Core functions then refuse a caller without independent register eligibility, checked at lookup time in the lookup's own transaction, with a refusal row. Holding the report permission alone, including the bootstrap owner's, never resolves anything.
- **Depends on.** PR #198 (the permission) and the register PR (eligibility). The lookup cannot ship before both are merged.
- **Evidence and tests.**
  - Refused without the permission; refused with the permission but without eligibility.
  - Refused while the enrolment is inside its 120-day delay, after it ends, and after a revocation.
  - Allowed with both the permission and eligibility.
  - Each refusal leaves a refusal row and reads no link.
  - The bootstrap owner, holding the report permission, is refused.
  - An architecture test shows that no new permission was added (28 values).
  - Negative controls: the eligibility check removed, and the route declared with another permission; each makes its refusal test fail.

## O8. Entry point for holds

**Decision (2026-11-03):** "holds placed and released through the authenticated API; a CLI may only place a hold."

- **History.** On 2026-11-02 the brief offered A (command only), B (API only) and C (API for both, plus a command that can only place holds; recommended). The decision is C.
- **Rationale.** Placing a hold errs towards retention and is safe under a declared id. Releasing is the step that can lead to removal, so it must be attributable to an authenticated person.
- **Permission (decided 2026-11-03, final closure).** The hold routes use the existing `platform.security_retention_hold:manage` (PR #198); no new permission is added, and the vocabulary stays at 28 values once PR #198 merges. The routes cannot ship before PR #198 merges.
- **Design.** Hold routes on the platform-admin router follow the conventions of PR #198's retention API: identity from the session only, no identity field in bodies, extra fields refused. An optional operator command can place a hold only and has no release subcommand. Placement and release follow the order of proposal section 4.9. The routes write as the application role, so whoever holds the application-role credential could also write or release hold rows directly, as for PR #198's retention API; the platform and tenant audit rows written with each change, and their ADR-0053 digests, are how such a change is detected.
- **Evidence and tests.** The routes for place, release and list take their identity from the session only (a body with an identity field gets `422`, and Core is never called). The command has no release path (architecture test). Releasing an already released hold is refused by the trigger. A negative control that adds a release path to the command fails the architecture test.

## O9. Separation of duties for link expiry

**Decision (2026-11-03):** "ledger expiry `--apply` stays disabled until an authenticated, register-eligible approval mechanism is implemented, independently reviewed and tested."

- **Application here.** O9 is the open item about this proposal's expiry command. The decision is recorded as applying to the expiry of audit identity links and erasure markers (D7's command). PR #198's permission-grant-ledger expiry stays disabled as well, under #198's own `_DELETION_ENABLED = False`.
- **History.** On 2026-11-02 the brief offered A (apply PR #198's rule; recommended), B (do not apply) and C (apply only where a hold was released). The decision is A.
- **Design.** The expiry module carries a literal gate, modelled on `_DELETION_ENABLED = False` in PR #198's `saas_os/core/permission_grants/expiry.py` (the proposed name here, `_APPLY_ENABLED`, is a design sketch), and `--apply` is refused before any connection is opened. Requests, approvals and execution authorisations never change the gate. Once an authenticated approval mechanism with independent register eligibility is implemented, independently reviewed and tested, a **separate, owner-approved code change** flips the literal, as PR #198's design section 8.6 prescribes for `_DELETION_ENABLED`. There is no setting, environment variable or argument that enables it. Dry runs and the report job work from phase P2 on. Until the approval mechanism exists, links and markers are kept beyond two years. This errs towards retention, and the privacy notice must say so.
- **Evidence and tests.** The literal is `False` (architecture test) and `--apply` is refused without connecting. Once an approval mechanism is approved: refusal when the approver released a hold in scope, when the approver and the execution authoriser are the same person or are not register-eligible, and when an approval is expired, consumed or invalidated. Negative controls remove each rule.

## O10. Erasure markers

**Decision (2026-11-03):** "erasure markers expire after two years."

- **History.** The options on 2026-11-02 were A (expire; recommended), B (keep while `core.users.id` exists) and C (a state on `core.users`). The decision is A.
- **Design.** A marker in a scope is deleted by the expiry command (when O9 allows `--apply`) once `erased_at`, under the rule above, plus one day is past and no live link of the subject remains in that scope (proposal, section 4.8). The consequences are stated in proposal section 4.6, "After a marker expires", and summarised here:
  - **A new audit record about the user** (for example a platform operation on the still existing `core.users` row) gets a new live link, which identifies that record for its own two years. References issued before expiry stay unresolvable.
  - **Outbox retry.** A stored initiator naming the user was rewritten to `"unavailable"` when the erasure covered that tenant, so a retry records `"unavailable"`. An event appended after the erasure that still names the user follows D2: it is refused while the gate stands. Once tenant references ship, it gets an unlinkable reference while the marker exists and a live link after it expired.
  - **Replay.** `replay_dead_lettered_events` re-reads the stored payload, so the retry case applies. An event in a tenant that the erasure did not list never had a marker there, and is not affected by marker expiry.
  - **Backup restore.** A restore to a point before the marker's deletion brings the marker back. Later records are then unlinkable again until the next expiry run deletes it once more, which errs towards protection. A restore to before the erasure brings the user's live links back. Section 4.12 then requires the erasure to be rerun from its case record, which creates a new marker whose two years start at the rerun.
  - **Re-erasure** after expiry creates a new marker and unlinks every live link created since the old marker expired, except held ones, as in a first erasure.
  - **Unchanged by marker expiry.** The erasure's own audit rows still carry `resource_id = str(user_id)` (inventory, field TA-2), and markers cover only the scopes that the erasure listed.
- **Evidence and tests.**
  - After marker expiry, a write creates a live link and the old references stay unresolvable.
  - A held live link prevents marker expiry.
  - A marker whose `erased_at` plus two years and one day has not passed is kept.
  - A re-erasure after expiry creates a new marker and unlinks.
  - A restore drill brings back a deleted marker, and the next run deletes it again.

## O11. Database enforcement of lookup

**Decision (2026-11-03):** "API/code enforcement plus architecture tests are acceptable temporarily; before the final phase an ADR evaluating database-enforced lookup restrictions must be prepared."

- **History.** On 2026-11-02 the brief offered A (API and code discipline plus an architecture test; recommended for P1 and P2), B (a `SECURITY DEFINER` get-or-create function and a separate lookup role) and C (a separate role only; not viable under ADR-0031). The decision accepts A temporarily and adds a gate.
- **Interim design.** The application role keeps `SELECT` on the link tables (proposal, section 4.3). An architecture test, in the style of `tests/architecture/test_tenant_session_boundary.py`, allows only the get-or-create, lookup, erasure and expiry modules to import the link-table models or name the tables. A negative control adds a module outside the allowlist and the test fails.
- **Gate.** "The final phase" is read as **P3, the tenant scope**, the last phase of the reference mechanism (proposal, section 9). P3 does not start until the ADR has been prepared. The reading is conservative; any later phase starts after P3 in any case.
- **What the ADR must evaluate:**
  1. Who can resolve a reference today and what that exposes, measured against the raw identifiers that remain after P1–P2 (inventory).
  2. The options: the status quo (A); a `SECURITY DEFINER` get-or-create function with the application role holding no `SELECT` on the links, plus a lookup role with its own session factory on the ADR-0056 precedent (B); a role that owns the link tables; column-level privileges or views.
  3. ADR-0031: get-or-create must stay in the audit write's own transaction and connection.
  4. The PostgreSQL 16 privilege questions, verified by tests: whether `INSERT ... ON CONFLICT DO NOTHING RETURNING` works without `SELECT`; `FORCE ROW LEVEL SECURITY` for a definer function's owner; pinning `search_path`; no `BYPASSRLS`.
  5. Erasure and expiry, which need `UPDATE` and `DELETE` and run as the application role or the migrations role.
  6. Lookup evidence across two connections (an attempt row in one, a completion row in another).
  7. Deployment cost: role setup scripts like `saas_os/infra/db/init/02-create-platform-config-role.sh`, configuration, connection pools, and backups.
  8. The amendment to the current no-`SECURITY DEFINER` stance that option B would need.
  9. The tests that would prove the chosen option: privilege tests, with negative controls.
- **Evidence and tests.** For the interim design: the architecture test and its negative control. For the gate: the ADR exists and was prepared before any P3 work started. A reviewer checks this at P3's approval.

## Items awaiting the owner (decision matrix)

Each question is quoted exactly as this record and the proposal (section 10) stated it before 2026-11-03's final closure; the options are the ones those documents state, and no new question is added. None of these is decided or implemented here. Status of every row: **awaiting owner**.

| Item | Exact question | Options (as stated) | Trade-offs | Recommendation | Consequence if deferred |
|---|---|---|---|---|---|
| O3 | "Whether the tenant scope ships with the platform scope or later (sequencing)" (proposal: "(sequencing only)") | (a) with the platform scope (P1); (b) later (P3, after P2) | (a) removes TA-3's gate and OD-3's raw `owner_user_id` sooner, but P1 then waits for the O11 ADR and the `core.audit_log` index review; (b) keeps P1 small, and the D2 gate and the raw OD-3 rows last until P3 | (b) | P3 follows P2 in the current plan, which is (b) in effect; only P3's start depends on it |
| O5 | "Product metadata keys and copies of references" (proposal: "Core cannot detect them; product obligation") | (a) a product obligation, stated in the consumer guide; no other option is stated | (a) Core cannot tell a user id from another UUID in product keys, so nothing else is enforceable; product rows may keep raw ids indefinitely | (a) | No Core phase waits on it; the privacy notice lists product keys as not covered |
| O6 | "Platform rows whose target user id does not exist (FK to `core.users`)" (proposal, section 4.4: "the implementation must decide whether such rows record no target or a dedicated `target_type`") | (a) record no target; (b) a dedicated `target_type` | (a) stores nothing about the id asked for, and loses which id was probed; (b) keeps that evidence, but a mistyped real id would be stored raw | (a) | P1 cannot ship: get-or-create fails with `23503` and turns a read of an unknown id into an error |
| O7 | "Recording probes of the lookup routes by non-operators" (proposal: "Whether probes by non-operators of the lookup routes must also be recorded (would change ADR-0045's route chain for every platform route)") | (a) not recorded: ADR-0045's existing `404` chain (the proposal's position, "not proposed here"); (b) recorded, changing the chain for every platform route | (a) no change to ADR-0045, probes stay invisible; (b) probe evidence, at the cost of an ADR-0045 amendment and audit rows for unauthenticated noise | (a) | The lookup routes ship with the existing chain; probes by non-operators are not recorded |

The retention of operators' own identities as actors (D6) remains a separate policy decision, not yet taken; it is not one of the items above.

## Dependencies at a glance

| Item | Depends on |
|---|---|
| D2 | PR #201 (compatibility unit with #196) |
| D3, O4 | PR #198 (`platform.security_retention:report`); the register PR (independent register eligibility); an amendment of ADR-0045's route table for the new routes |
| D4, O8 | Hold tables (proposal, section 4.9); PR #198's route conventions and its `platform.security_retention_hold:manage` |
| OD-3 | Tenant tables (P3, or P1 under O3 (a)) |
| D7, O9 | An authenticated, register-eligible approval mechanism, implemented, independently reviewed and tested, before `--apply` |
| O10 | D7 and O9 (markers are deleted by the same command) |
| O11 | An ADR prepared before P3 |
