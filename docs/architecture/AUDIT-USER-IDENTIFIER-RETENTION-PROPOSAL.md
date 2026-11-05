# Retention of user identifiers in completed audit records

**Status: Design proposal with the owner's decisions recorded: D1–D8 and O1 (2026-11-02), D1–D8 restated and O2, O4, O8, O9, O10 and O11 decided (2026-11-03); O3, O5, O6 and O7 decided (2026-11-03, merge preparation); section 6 and the decision record `docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md`. Not implemented on this branch. The D2 gate is in PR #201 (merged as `021e487`, after #196 as `13126f6`; the owner's rule of 2026-11-03 that #196 is never merged without #201 was kept). The reference and link-table schema and runtime stay design (owner, 2026-11-03); implementation requires separate approval.** Nothing in this document is built. It changes no schema, no runtime behaviour, no grant and no public contract. Every SQL block is a proposal that has **not been run against PostgreSQL and is not validated DDL** (section 8 lists what must be reviewed). Function names, routes and error names are design sketches, not code. Date: 2026-11-02; decisions of 2026-11-03 applied on 2026-11-03.

**Implementation status (2026-11-04).** The platform scope of phase P1 is implemented in PR #216 (merged on 2026-11-05 as `40992fe`, released in v0.8.0; migration `e2b7c4d9a1f6`): the platform link, erasure-marker and hold tables, the get-or-create in the audit transaction with the A1 existence read, references for every platform user target and for the operator events, and the platform erasure step. The SQL of this document was reviewed and run on PostgreSQL 16 (`docs/architecture/AUDIT-P1-SQL-REVIEW.md`); the reviewed DDL replaces the sketches for the three platform tables, with the four corrections that review lists. Everything else here is still design and is not built: the lookup routes, the hold routes, the expiry command, the report job, the tenant tables, the tenant expression index and the tenant get-or-create. Wherever the text below says that something is "not built" or "not implemented", read it as excluding the P1 items in the inventory's phase P1 status paragraph.

Related: ADR-0002 (tenant isolation), ADR-0031 (same-transaction audit), ADR-0045 (platform authority and platform audit), ADR-0051 (audit table immutability), ADR-0053 (audit digests in external logs), ADR 0061 (system actor attribution, PR #196), ADR 0060 (permission grant migrations, PR #198, merged as `09a69f0`) and its `docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`, `docs/MULTI-TENANCY.md` section 6 (identity erasure), `docs/BACKUP-RESTORE.md`, `docs/RUNBOOKS.md` ("Audit digests", section 4). Decision record (every D and O item decided, with the evidence and tests each needs): `docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md`. Every raw user identifier still stored, and the phased remediation of those outside this design's scope: `docs/architecture/AUDIT-RAW-IDENTITY-INVENTORY.md`.

The design in one paragraph: where this policy applies, a new audit record never stores a user id. It stores a **random, non-identifying reference** (`subject_ref`), one per user, scope and **UTC calendar day** (D1). A separate **identity-link table** maps each reference to the user id: tenant-scoped under forced row-level security for tenant audit records, and a separate untenanted table for platform audit records. The audit row never changes. The only designed path for resolving a reference to a user is an authenticated and audited platform-admin API call (D3) by a caller holding `platform.security_retention:report` **and** independent register eligibility (O4); the database does not enforce that path against other application-role code, which the owner accepts temporarily (O11, section 4.5). When every audit record that uses a link is more than two years old and no legal hold covers it (D4), a migrations-role command with dry run and explicit confirmation deletes the link (D7) and records counts and a hash of the affected references (D8; erasure records counts only, section 4.11); its `--apply` stays disabled until an authenticated, register-eligible approval mechanism is implemented, independently reviewed and tested (O9). From then on the reference still shows that several records of one day were made by the same subject, but not who that subject was. Records written before the mechanism keep their raw ids as a documented legacy exception (D5).

## 1. The approved policy (owner, 2026-11-02)

For completed audit records that contain an identifiable user initiator (the `initiated_by` user id, and analogous user ids in audit metadata):

1. Default retention is two years from the audit record's creation.
2. A legal hold can suspend expiry.
3. After expiry, a controlled privacy process removes or anonymises direct user identification where that is legally permissible.
4. The non-identifying audit history is preserved where possible.
5. Append-only audit records are never mutated silently.
6. There is no uncontrolled deletion.

The policy and decisions D1–D8, O1, O2, O4, O8, O9, O10 and O11 (section 6 and the decision record) are decided. The design that implements them is a proposal, and the owner's decisions of 2026-11-03 do not authorise implementing it.

## 2. Current behaviour (verified on `268fdfe`)

### 2.1 Audit tables are append-only for the application

- Migration `2e7cb8c64903` (`saas_os/infra/db/migrations/versions/2e7cb8c64903_create_core_audit_log_table.py`) revokes `UPDATE` and `DELETE` on `core.audit_log` from the application role; `c4a9e1f07b52` (`saas_os/infra/db/migrations/versions/c4a9e1f07b52_create_platform_authority_tables.py`, `upgrade`) does the same for `core.platform_audit_log`. There is deliberately no trigger (ADR-0051 decision 2): the table owner (the migrations role) and superusers can still change rows.
- `core.audit_log.created_at` has `server_default=now()` (`saas_os/core/audit_log/models.py`, `AuditLogEntry.created_at`): the start time of the writing transaction, on the database clock. Callers cannot set it; neither `record()` nor `record_in_transaction()` in `saas_os/core/audit_log/service.py` takes a `created_at` argument.
- The actor columns are constrained. `core.audit_log` requires `actor_user_id IS NOT NULL` when `actor_type = 'user'` (CHECK in `saas_os/infra/db/migrations/versions/a8ad8e61deb2_add_audit_log_service_account_actor.py`), and `actor_user_id` is a foreign key to `core.users`. `core.platform_audit_log` has the same pairing (`ck_platform_audit_log_actor_pairing` in `c4a9e1f07b52`).
- The `metadata` column of both audit tables is PostgreSQL `json` (SQLAlchemy `JSON`, `AuditLogEntry.entry_metadata`), not `jsonb`, bounded at 8192 bytes (`MAX_METADATA_BYTES`, `saas_os/core/audit_log/metadata.py`, and `ck_audit_log_metadata_size`).
- Indexes that matter here: `ix_audit_log_tenant_created_at (tenant_id, created_at)` on `core.audit_log`; `ix_platform_audit_log_target (target_type, target_id)` on `core.platform_audit_log` (`c4a9e1f07b52`). There is no index on any metadata expression.
- Sessions run at PostgreSQL's default isolation, READ COMMITTED (`saas_os/infra/db/session.py` sets no other level).

### 2.2 Tamper evidence (ADR-0053)

`saas_os/core/audit_digest/service.py` serializes each row from a fixed column list (`AUDIT_LOG_COLUMNS`, `PLATFORM_AUDIT_LOG_COLUMNS`; `RECORD_FORMAT = "saas-os-audit-digest/1"`). Both lists include `actor_user_id` and `metadata`. `_selected` reads `metadata` as its stored text, so any rewrite of it, even one that decodes to the same JSON value, changes the window digest. Adding a column to an audit table is a digest format change. `python -m saas_os.ops.audit_digest verify` (`saas_os/ops/audit_digest.py`) recomputes each window and reports any difference.

Consequence: **any in-place change to an audit row, including a privacy redaction, is indistinguishable from tampering to the current verifier.** This is why D5 keeps existing rows unchanged.

### 2.3 Where `initiated_by` stores a user id today (PR #196)

- `Initiator.as_metadata()` (`saas_os/core/authority/attribution.py`) writes a user initiator as `{"type": "user", "user_id": "<uuid>"}`.
- **Audit metadata.** `record_in_transaction()` (for a `SystemCaller` only) and `record_system_action_in_transaction()` in `saas_os/core/audit_log/service.py` both build `metadata["initiated_by"]` through one private function, `_attribution()`, after `_require_attribution_types()`. `record()` takes no `initiated_by`. A `UserCaller` row never carries `initiated_by`; the user is in `actor_user_id` (`_caller_actor`), and passing `initiated_by` for one fails with `InvalidActorError`.
- **Outbox payload.** `append_event(..., initiated_by=...)` (`saas_os/core/outbox/service.py`) stores the same shape in `core.outbox_events.payload` under `saas_os.initiated_by` (`INITIATED_BY_PAYLOAD_KEY`, `saas_os/core/outbox/models.py`). The dispatcher splits it off (`_split_initiator`, `saas_os/core/outbox/dispatch.py`) and passes it in memory as `TenantJobContext.initiated_by` (`_job_initiator`, `saas_os/api/outbox_dispatcher.py`). Only the event id and claim token travel through Redis.
- **Who writes a user initiator.** No Core code path does. A user initiator reaches an audit row only when a product (or a test) calls `append_event(initiated_by=Initiator.from_caller(user_caller))` and its consumer records it with `Initiator.from_job_initiator(context.initiated_by)`, as `docs/CONSUMER-GUIDE.md` instructs, or passes `Initiator.user(...)` to an audit function. PR #196 is not merged, so no released consumer depends on the shape.

### 2.4 Other user ids in audit records

The complete list, with writers, access, digest coverage and remediation, is the inventory (`docs/architecture/AUDIT-RAW-IDENTITY-INVENTORY.md`, re-verified on `1e9e215`). In short:

- Columns: `core.audit_log.actor_user_id`; `core.platform_audit_log.actor_user_id` (the operator); `core.platform_audit_log.target_id` with `target_type = 'user'` (`_TARGET_USER` in `saas_os/core/identity/user_authority.py`: user read and resolve, deactivate, reactivate, session revoke, API-key revoke, refused erasure of an enrolled operator; and the refusal rows of operator enrollment in `saas_os/core/platform_authority/service.py`); `core.audit_log.resource_id` when it names a user (erasure rows of `_erase_membership_in_tenant`, `saas_os/core/identity/erasure.py`, `resource_type = 'user'`).
- Metadata keys written by Core: `user_id` (`membership.create` in `saas_os/core/identity/service.py`; platform operator events in `saas_os/core/platform_authority/service.py`), `owner_user_id` (`_owner_metadata` and `record_platform_key_revocations`, `saas_os/core/api_keys/service.py`; the latter writes one tenant row per key revoked by a platform deactivation or API-key revocation, so the platform operation's target user is also named in tenant rows), `proposer_user_id` (only the successful `control_plane.action_approved` row, `saas_os/control_plane/approvals/service.py`), `run_by_user_id` (tenant purge's platform rows, `saas_os/core/tenancy/service.py`), and the request filter `filters.actor_user_id` that `list_platform_audit` (`saas_os/core/platform_authority/oversight.py`) records in its attempt row.
- Products write their own metadata keys. Core cannot tell a user id from any other UUID in them.
- `recipient_user_id` (`saas_os/core/notifications/service.py`) is an outbox payload field, not audit metadata.

Which of these are in the decided scope is stated in section 4.1.

### 2.5 Retention, erasure, backups, operator commands, RLS

- `saas_os/core/tenancy/retention.py` classifies `core.audit_log`, `core.platform_audit_log` and `core.audit_digests` as `SECURITY_RETAIN`. There is no time-based retention for audit rows and no legal-hold concept on this branch.
- `erase_user_identity()` (`saas_os/core/identity/erasure.py`) first removes external identities in an untenanted transaction (`remove_identity_links_unless_enrolled_operator`, `saas_os/core/identity/user_authority.py`; refuses an enrolled operator with `EnrolledOperatorErasureError`), then, tenant by tenant, `_erase_membership_in_tenant` rewrites the user's outbox initiators to `"unavailable"` (`erase_user_initiator()`, `saas_os/core/outbox/initiator_erasure.py`) and removes the membership and its dependants in one transaction per tenant. It keeps `core.users.id` and leaves every audit row unchanged.
- Backups keep `BACKUP_RETENTION_COUNT` full copies (default 7, `_DEFAULT_RETENTION_COUNT` in `saas_os/infra/db/backup/config.py`).
- Operator commands take a **declared** user id (`--operator`, `--actor`) and build `UserCaller(<that id>)` from it (`saas_os/ops/operator_cli.py`). Nothing authenticates that the person at the terminal is that user. PR #198 records the same finding and, for that reason, disables ledger deletion until an authenticated approval exists.
- RLS (`saas_os/infra/db/rls.py`): `tenant_rls_statements()` issues `ENABLE`, `FORCE` and the policy `USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)` with no separate `WITH CHECK`; `tenant_context_exclusion_statements()` makes platform tables visible and writable only while `app.tenant_id` is unset or empty. No `BYPASSRLS`, no `SECURITY DEFINER`.

### 2.6 The authenticated operator channel and the platform-to-tenant pattern

- The only authenticated operator channel is the platform-admin HTTP API (`saas_os/api/platform_admin/router.py`). Each route declares `require_platform_permission(permission, operation=..., fresh_session=...)` (`saas_os/api/dependencies.py`): deployment opt-in (`PLATFORM_ADMIN_HTTP_ENABLED`), an OIDC session (`get_current_session`, same-origin check for unsafe methods), rate limit, active operator (a non-operator gets the `404` of an unknown path and **nothing is recorded**), MFA where required (ADR-0049), then the permission. `POST /users/resolve` already resolves an identity to a user through this chain.
- `replay_outbox_events` (`saas_os/core/outbox/replay.py`) shows how a platform operation acts on tenant data in one transaction: `platform_change_session()`, `authorize_platform_caller()`, then `bind_tenant_scope(session, tenant_id)` (`saas_os/infra/db/session.py`) for the tenant read and the tenant audit row, then the platform audit row with no tenant bound. `run_oversight_read` (`saas_os/core/platform_authority/oversight.py`) shows the read pattern: an attempt row committed before reading, a completion row after.
- PR #198's `LEDGER-DELETION-APPROVAL-DESIGN.md` proposes moving retention approval and hold placement and release to this API for the same reason D3 gives here: a declared operator id is not an identity.
- PR #198's retention API was approved for further design only on 2026-11-02; on 2026-11-03 it is being implemented, with the approver eligibility register, in a separate PR stacked on #198. PR #198's decision 13 is **decided: option A** (owner, 2026-11-02, adopted on PR #198 at `a29c4cc`): eligibility to approve or authorise execution comes only from an independent approver eligibility register. This proposal relies on one property of it, **independent register eligibility**: an active approver enrolment whose 120-day delay has passed (O4, O9). It specifies nothing else about the register; PR #198 and the register PR are the authority for it.

## 3. Requirements

- **R1.** The application role stays append-only on both audit tables (ADR-0051). No audit row is rewritten to apply the policy.
- **R2.** A digest recorded before expiry still verifies after expiry. No unexplained `audit_log_changed`.
- **R3.** A link is deleted only when **every** audit record that carries the reference as its user identification (the `initiated_by` subject of a tenant row, the target of a platform row) satisfies `created_at + 2 years <= now()` on the database clock, in UTC (section 4.8). Deviation is only ever later, never earlier, and is bounded. Rows that mention a reference as the object of an operation (lookup attempt and completion rows, `audit_subject.resolved` and `audit_subject.listed` rows, hold rows and their audit rows) do not extend the link's life: a deliberate narrowing (section 4.8). A hold, not a lookup, is the way to keep a link.
- **R4.** A legal hold suspends expiry and erasure for what it covers (D4). Placing, releasing, expiring and resolving are audited without re-recording the identifier.
- **R5.** After expiry or erasure the identifier cannot be recovered from the live database, including by recomputation from `core.users.id`, which is kept forever.
- **R6.** What happened, when, and whether two records of one scope and day were made by the same subject stay readable. Records in different tenants, and tenant and platform records, are never linkable through references.
- **R7.** Within retention, only an authenticated, authorised and audited lookup resolves a reference (D3).
- **R8.** Rows written before the mechanism are handled explicitly as a legacy exception (D5).

R5 rules out any deterministic function of the user id (for example a keyed hash under one long-lived key): whoever holds the key can hash every id in `core.users` and re-link every pseudonym. Each reference comes from randomness stored only in a row that can be deleted.

## 4. The design

### 4.1 Scope, and what the decisions put in and out

| Identifier | Decided treatment | Decision |
|---|---|---|
| `initiated_by` user id in **new** tenant audit rows | Refused by the audit writers until the tenant reference mechanism ships; then written as a tenant reference | D2 as interpreted here (gate), section 7 |
| `initiated_by` user id in outbox payloads | Unchanged: stored, handed to consumers in memory, rewritten to `"unavailable"` on erasure | D2 ("existing outbox erasure behaviour preserved") |
| Target user in **new** platform audit rows (`target_type = 'user'`), whoever the user is (an operator who is the target of an action included), and the `user_id` metadata of operator events, which names the target operator's user | First scope of the reference mechanism; until it ships, written raw as today | D6, O2, OD-2 |
| Target user named in the tenant `api_key.revoke` rows (`owner_user_id`, `"platform": true`) that a platform deactivation or API-key revocation writes | Target-user reference treatment: a tenant reference under `owner_user_subject_ref`, shipped with the tenant tables (P3; O3 decided 2026-11-03); raw until then | OD-3 |
| Operators' own identity as **actors** in platform audit (`actor_user_id` of an actual operator, the operator id of an operator's own login row, `filters.actor_user_id`) | Out of scope; a separate retention policy decision | D6, OD-1, OD-2 |
| Operator ids as targets (`target_type = 'platform_operator'`, `previous_operator_id`) | Target identifiers (OD-2), but not user ids: kept as the operator record's identifier; linkable through `core.platform_operators.user_id` while that row keeps it (inventory, OP-19) | OD-2 |
| Every raw user id already stored in an audit row | Legacy exception; no rewrite of rows or digests in this phase | D5 |
| Tenant and platform `actor_user_id` | Still written raw: a **temporary exception** decided by the owner (O1), because CHECK constraints require it for user-actor records | O1 (decided) |
| Platform target user ids (`target_type = 'user'`) until P1; tenant `resource_id` naming a user; metadata `user_id` (`membership.create`), `owner_user_id` (including, until the tenant tables ship, the tenant rows written for a platform deactivation or API-key revocation), `proposer_user_id`; platform metadata `run_by_user_id` (the person who ran a tenant purge) | Still written raw. Not gated by D2 (O1 limits D2 to `initiated_by`; each field's different meaning is stated in the inventory) and not named as an exception by O1: an **outstanding privacy risk** until later phases (platform targets and operator-event `user_id` in P1; the platform-marked `owner_user_id` rows with the tenant tables, OD-3; the others in the inventory's phases P4 and P5, which need further owner decisions) | none yet for the others |
| Product metadata keys | Product obligation; Core offers the mechanism but cannot detect a raw user id | none (section 10, O5) |

**D2, verbatim (owner, 2026-11-02):** "Until the new reference/link-table mechanism is implemented, reject user initiators in audit records. Do not store raw user IDs in new audit records. Preserve the existing outbox erasure behaviour."

**O1, decided (owner, 2026-11-02):** "D2 applies to `initiated_by`. New audit records must reject user initiators that would store raw user IDs in `initiated_by`. Existing mandatory `actor_user_id` storage remains a temporary exception because current database constraints require it for user-actor records."

What this distinguishes:

- **`initiated_by`** (who originally requested an action) is gated: from the D2 gate onwards, a new audit record never stores a raw user id there. The gate is implemented in PR #201 (merged as `021e487`); #196 and #201 are both on main, so #196 no longer accepts user initiators in audit records (section 7).
- **`actor_user_id`** (who performed the action) stays raw as a temporary exception. `core.audit_log` requires `actor_user_id IS NOT NULL` when `actor_type = 'user'` (CHECK added in `a8ad8e61deb2`) and `core.platform_audit_log` has the same pairing (`ck_platform_audit_log_actor_pairing`, `c4a9e1f07b52`); removing it needs a new column, a relaxed CHECK and digest format version 2 (section 2.2), which D5 keeps out of this phase. Refusing such rows would leave user actions unaudited, against ADR-0031.

**Outstanding privacy risk (not removed by D2 or O1).** New audit records keep storing raw user ids in: the `actor_user_id` columns of both audit tables (the decided temporary exception); platform target ids with `target_type = 'user'` until the platform mechanism ships in P1 (D6); tenant `resource_id` values naming a user (erasure rows); the metadata keys `user_id`, `owner_user_id` and `proposer_user_id`; the platform metadata key `run_by_user_id`; plus whatever products write. P1 does not remove the target user's id from the tenant `api_key.revoke` rows that a platform deactivation or API-key revocation writes beside its platform row (`owner_user_id`, `"platform": true`): OD-3 (decided 2026-11-03) gives them target-user reference treatment, but as tenant rows they need tenant references, so they stay raw until the tenant tables ship (inventory, field TA-5). These raw ids do not expire, are `SECURITY_RETAIN`, and are covered by audit digests, so they cannot be removed later without the controlled redaction that D5 excludes from this phase. The O1 decision names only `actor_user_id` as an exception; the other locations are not decided exceptions but are not yet scheduled for a phase either, and should be listed in the privacy notice as identification retained beyond two years.

**O2, decided (owner, 2026-11-03):** "separate actual operator identities from failed/refused enrolments; actual operator identities stay outside this target-user scope; non-operator targets of failed/refused enrolments get random references." **OD-1 and OD-2, decided (owner, 2026-11-03, final closure):** an "actual operator" is a natural person performing an authenticated privileged operation, and the operator exclusion applies when the person is the actor, not when that person is the target of an action; an operator who is the target gets target-user reference treatment like anyone else. Every platform row with `target_type = 'user'` therefore gets a platform reference, with no write-time operator test: the refusal rows of `enroll_operator` (including a refused enrolment naming the caller), the refused erasure of an enrolled operator, and every user operation whose target is an operator. The actor column keeps the authenticated actor (O1). A successful enrolment targets the operator id (`target_type = 'platform_operator'`), which is not a user id; its `user_id` metadata names the target's user and gets a reference (inventory, PA-3).

**Phasing.** D6 fixes the first scope: platform-audit target users (platform tables, section 4.3). The tenant tables are designed in full here because lifting D2's gate depends on them; whether they ship in the same phase is a sequencing item (O3), not a policy decision. O3 was decided on 2026-11-03 (merge preparation): option (b), the tenant scope is deferred to P3.

### 4.2 Reference generation, uniqueness and collisions

- **Source.** `gen_random_uuid()` (PostgreSQL 13 and later; a version-4 UUID with 122 bits from the server's strong random source). Generated in the database so one `INSERT ... ON CONFLICT ... RETURNING` creates and returns it. Python's `uuid.uuid4()` (`os.urandom`) is equivalent if a client-side value is ever needed. References are never derived from the user id, the tenant id, the day or a key.
- **Granularity (D1).** One live reference per (scope, user, UTC calendar day), where scope is one tenant or the platform. The day is `(now() AT TIME ZONE 'UTC')::date`, computed in the audit write's own transaction, so it is the UTC date of that transaction's `now()`, which is also the audit row's `created_at`.
- **Uniqueness, two constraints.** `subject_ref` is the primary key (globally unique across every row, live or unlinked). A partial unique index allows one **live** link per (tenant, user, day) (platform: per (user, day)); unlinked rows (`user_id IS NULL`) are outside it.
- **Same-subject race.** Handled by `ON CONFLICT (tenant_id, user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING`, then a re-select (section 4.4). Both writers end with the same reference.
- **Reference collision.** `ON CONFLICT` with an explicit arbiter absorbs only conflicts on that arbiter. A collision of a fresh `gen_random_uuid()` with an existing `subject_ref` therefore raises `unique_violation` (SQLSTATE `23505`) on `pk_audit_subject_links` and is never merged into another subject. Because a failed statement aborts the enclosing transaction, which is the audited change's own, the insert runs inside a **savepoint** (`session.begin_nested()`). On `23505` naming the primary-key constraint, the function rolls back to the savepoint and retries with a new value; **at most three attempts**, then `AuditSubjectLinkUnavailableError` and the whole transaction rolls back. A `23505` on any other constraint is not retried. At 122 random bits the retry path exists for correctness, not because a collision is expected.

### 4.3 Tables, RLS and cross-tenant isolation

**Tenant link table** (proposal, not run against PostgreSQL; not validated DDL):

```sql
CREATE TABLE core.audit_subject_links (
    subject_ref    uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id      uuid        NOT NULL REFERENCES core.tenants (id),
    user_id        uuid        NULL REFERENCES core.users (id),  -- NULL once unlinked
    subject_day    date        NOT NULL,                         -- UTC calendar day (D1)
    created_at     timestamptz NOT NULL DEFAULT now(),
    unlinked_at    timestamptz NULL,
    unlink_reason  text        NULL,
    CONSTRAINT pk_audit_subject_links PRIMARY KEY (subject_ref),
    CONSTRAINT ck_audit_subject_links_unlink_pairing CHECK (
        (user_id IS NULL) = (unlinked_at IS NOT NULL)
        AND (unlinked_at IS NULL) = (unlink_reason IS NULL)
    ),
    CONSTRAINT ck_audit_subject_links_unlink_reason
        CHECK (unlink_reason IS NULL OR unlink_reason IN ('erasure', 'expiry'))
);
CREATE UNIQUE INDEX uq_audit_subject_links_live
    ON core.audit_subject_links (tenant_id, user_id, subject_day)
    WHERE user_id IS NOT NULL;
CREATE INDEX ix_audit_subject_links_day
    ON core.audit_subject_links (tenant_id, subject_day);
-- tenant_rls_statements('audit_subject_links', schema='core'):
ALTER TABLE core.audit_subject_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.audit_subject_links FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_subject_links_tenant_isolation ON core.audit_subject_links
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
```

`core.audit_subject_erasures (tenant_id, user_id, erased_at, PRIMARY KEY (tenant_id, user_id))` and `core.audit_identity_holds` (section 4.9) are tenant-owned with the same `tenant_rls_statements()`.

**Platform tables (D6 first scope).** `core.platform_audit_subject_links` has the same columns without `tenant_id`, the partial unique index on `(user_id, subject_day) WHERE user_id IS NOT NULL`, and `tenant_context_exclusion_statements()`. `core.platform_audit_subject_erasures (user_id PRIMARY KEY, erased_at)` and `core.platform_audit_identity_holds` likewise. A platform reference and a tenant reference for the same user are independent random values.

**How cross-tenant lookup is made impossible**, in layers:

1. Every tenant-scope operation (get-or-create, lookup, erasure, expiry) names exactly one `tenant_id` and runs in a session bound to it (`tenant_session_scope(tenant_id)` or `bind_tenant_scope(session, tenant_id)`), which sets `app.tenant_id` for the transaction.
2. `FORCE ROW LEVEL SECURITY` applies the policy to the table owner too (only a superuser or a `BYPASSRLS` role escapes; the deployment roles are neither). With `app.tenant_id` set to tenant A, rows of tenant B are invisible to `SELECT`, `UPDATE` and `DELETE`, and an `INSERT` or `UPDATE` producing a tenant-B row fails with `42501`. With `app.tenant_id` unset, `NULLIF(...)` is `NULL`, the comparison is `NULL`, and no tenant row is visible: an untenanted transaction (including the platform lookup before it binds a tenant) sees no tenant links.
3. Every query also carries an explicit `tenant_id = :tenant_id` predicate, so a mistake in one layer does not open the other.
4. A reference of tenant B looked up under tenant A returns zero rows and raises the same `AuditSubjectNotResolvableError` as an unknown or unlinked reference. The call does not reveal that the reference exists elsewhere.
5. There is no API that takes a reference without a scope, and none that searches across tenants. The platform link table is invisible inside a tenant-bound transaction (exclusion policy), so a tenant-scope call cannot reach platform references either.
6. Required negative controls at implementation: a test that resolves tenant B's reference under tenant A and expects the not-resolvable error; the same test with the explicit predicate removed (RLS alone must still refuse); and the same test with RLS disabled on the test table (the predicate alone must still refuse).

**Retention class.** All six tables are `SECURITY_RETAIN` (`saas_os/core/tenancy/retention.py`): tenant purge does not delete them; they leave only through the expiry procedure. The `core.tenants` foreign keys are safe because a purged tenant keeps its tombstone row; the `core.users` foreign key is safe because users are never deleted.

**Role grants.** Each migration narrows the default privileges that migration `e99c76057719` gives the application role on new tables:

| Table | Application role | Migrations role (owner) |
|---|---|---|
| `core.audit_subject_links`, `core.platform_audit_subject_links` | `SELECT`, `INSERT`, `UPDATE (user_id, unlinked_at, unlink_reason)`; no `DELETE` | all; `DELETE` used only by the expiry command |
| `core.audit_subject_erasures`, `core.platform_audit_subject_erasures` | `SELECT`, `INSERT`; no `UPDATE`, no `DELETE` | all; expiry command |
| `core.audit_identity_holds`, `core.platform_audit_identity_holds` | `SELECT`, `INSERT`, `UPDATE (released_at, released_by_platform_audit_id)` (the authenticated hold routes and the place-only command run as the application role, O8; the one-way trigger allows only the release transition); no `DELETE` | all (owner); nothing deletes a hold |

A `BEFORE UPDATE` trigger on each link table (not `SECURITY DEFINER`, fixed `search_path`; the one-way pattern of PR #198's hold trigger) allows exactly one transition, live to unlinked (`OLD.user_id IS NOT NULL AND NEW.user_id IS NULL`, every other column but `unlinked_at` and `unlink_reason` unchanged) and raises `check_violation` (`23514`) on anything else, for every role including the owner. A link can never be re-pointed at another user, and an unlinked reference can never be linked again.

### 4.4 Get-or-create in the audit write's transaction

Tenant scope, inside the audited change's `tenant_session_scope(tenant_id)` session (proposal, not run against PostgreSQL; not validated DDL):

```sql
-- 1. Subject lock, shared (section 4.7).
SELECT pg_advisory_xact_lock_shared(
    hashtextextended('audit-subject:' || CAST(:tenant_id AS text) || ':' || CAST(:user_id AS text), 0));
-- 2. Erased in this tenant?
SELECT 1 FROM core.audit_subject_erasures
 WHERE tenant_id = :tenant_id AND user_id = :user_id;
-- 3a. Not erased: create the day's live link, inside a savepoint (section 4.2).
INSERT INTO core.audit_subject_links (tenant_id, user_id, subject_day)
VALUES (:tenant_id, :user_id, (now() AT TIME ZONE 'UTC')::date)
ON CONFLICT (tenant_id, user_id, subject_day) WHERE user_id IS NOT NULL
DO NOTHING
RETURNING subject_ref;
-- 3b. No row returned: another transaction committed it first.
SELECT subject_ref FROM core.audit_subject_links
 WHERE tenant_id = :tenant_id AND user_id = :user_id
   AND subject_day = (now() AT TIME ZONE 'UTC')::date
   AND user_id IS NOT NULL;
-- 3c. Erased: a fresh reference that never holds a user id.
INSERT INTO core.audit_subject_links
       (tenant_id, user_id, subject_day, unlinked_at, unlink_reason)
VALUES (:tenant_id, NULL, (now() AT TIME ZONE 'UTC')::date, now(), 'erasure')
RETURNING subject_ref;
```

Under READ COMMITTED a conflicting insert waits for the other transaction; if it commits, `DO NOTHING` applies and 3b (a new statement, a new snapshot) sees its row; if it rolls back, 3a inserts. Section 4.7's locks make it impossible for the row to be unlinked or deleted between 3a and 3b, and expiry never touches today's links. If 3b still finds nothing, 3a and 3b are retried **once**, then `AuditSubjectLinkUnavailableError`. **Isolation requirement: READ COMMITTED.** Step 2's marker check is correct only because each statement takes a new snapshot after the `S` lock is granted. Under REPEATABLE READ or SERIALIZABLE the snapshot is taken at the transaction's first statement, possibly before the lock wait, so a marker committed by an erasure in between would be invisible and the writer would create a live link after the erasure (and 3b could miss a row committed after the snapshot). The function therefore checks `current_setting('transaction_isolation')` before step 1 and raises `AuditSubjectLinkUnavailableError` under any other level; it never works around it. After erasure (3c) every write gets its own unlinkable reference.

The platform variant is identical without `tenant_id`, with lock key `'audit-subject:platform:' || CAST(:user_id AS text)`, run in the untenanted session that writes the platform audit row (including the refusal rows of `recording_platform_refusal` and the attempt rows of `run_oversight_read`, which are written in their own transactions and therefore call it themselves). A platform writer whose target is a user calls it for every such target, operators included (OD-2), and writes the reference under `target_type = 'user_subject'`; it does not test whether the target is an operator.

**Proposed interface** (Core; names are proposals):

```text
audit_subject_ref(session, *, tenant_id: UUID, user_id: UUID) -> UUID
platform_audit_subject_ref(session, *, user_id: UUID) -> UUID
    Get-or-create as above in `session`'s transaction.
    Raises AuditSubjectLinkUnavailableError.

Recorded shapes once the mechanism is released:
    tenant:   metadata["initiated_by"] = {"type": "user", "subject_ref": "<uuid>"}
    platform: target_type = "user_subject", target_id = "<uuid>"
```

`Initiator` keeps the user id in memory (the outbox and the consumer need it); only the audit writer converts it. `Initiator.from_metadata()` would accept both the legacy `user_id` shape and the `subject_ref` shape. For platform rows, a new `target_type` value keeps readers of platform audit rows from taking a reference for a user id: `list_platform_audit` (`GET /platform/audit`) returns each row's `target_type` and `target_id` (it has no target filter; its filters are time, actor, action and target tenant). It is a change to what platform audit readers see and must be listed in the release notes.

**Unknown user ids.** The `core.users` foreign key makes get-or-create fail (`23503`) for an id that names no user. For an audit write that is fail-closed (the change rolls back). For platform read attempts on an id that does not exist (for example `GET /users/{user_id}` with a wrong id) it would turn a "not found" into an error; the implementation must decide whether such rows record no target or a dedicated `target_type`. **O6, decided (owner, 2026-11-03, merge preparation): option (a), such rows record no target.** The foreign-key implications were addressed by the owner on 2026-11-04 (option A1 of `docs/architecture/AUDIT-P1-FOREIGN-KEY-OPTIONS.md`): the `user_id` foreign key to `core.users` of `core.platform_audit_subject_links` (section 4.3) stays; the platform writers decide existence in the audit write's transaction (`SELECT ... FOR KEY SHARE` on `core.users`), and an unknown id is recorded as `target_type = 'user'` with a NULL `target_id` and no link row, so get-or-create never meets `23503`.

### 4.5 Authorised lookup (D3)

The designed lookup path is the authenticated platform-admin API, never an operator command or a declared operator id. **This is enforced by the API and by code discipline, not by the database:** the application role has `SELECT` on the link tables (section 4.3), so any application-role code in a session bound to the tenant (or, for platform links, an untenanted session) can read them. Mitigations proposed for implementation: an architecture test that only the get-or-create module, the lookup module, erasure and the expiry command import the link-table models or name the tables; and code review. **O11, decided (owner, 2026-11-03):** "API/code enforcement plus architecture tests are acceptable temporarily; before the final phase an ADR evaluating database-enforced lookup restrictions must be prepared." The ADR (what it must evaluate: decision record, O11) is a gate of P3, the tenant scope, read as the final phase of this mechanism (section 9). Proposed routes (POST, so neither the reference nor a user id appears in a URL or access log):

```text
POST /platform/audit-subjects/resolve
    body: {"scope": "platform" | {"tenant_id": "<uuid>"}, "subject_ref": "<uuid>", "reason": "<ticket ref>"}
    200: {"user_id": "<uuid>"}; 404 not_resolvable (unknown, unlinked or other scope: one answer)
POST /platform/audit-subjects/list
    body: {"scope": ..., "user_id": "<uuid>", "reason": "<ticket ref>"}
    200: {"subject_refs": [...]}   -- live references of one user, for a data subject request or a hold
```

**O4, decided (owner, 2026-11-03):** "no new permission; identity lookup requires `platform.security_retention:report` AND independent register eligibility." Each route declares `require_platform_permission(PlatformPermission.SECURITY_RETENTION_REPORT, operation=..., fresh_session=True)` (PR #198's permission, not on this branch), so the caller is the OIDC session's user (with MFA where the deployment requires it), never a declared id. Core functions `resolve_audit_subject(caller=..., ...)` and `list_audit_subject_refs(caller=..., ...)` accept only a person (`UserCaller`); no system purpose may call them. They refuse a caller without independent register eligibility (an active approver enrolment past its 120-day delay, from the register PR stacked on PR #198), checked in the lookup's own transaction and recorded as a refusal: the report permission alone, including the bootstrap owner's, never resolves a reference.

Order, combining `run_oversight_read` and `replay_outbox_events` (section 2.6):

1. **Attempt row, committed first.** A platform audit row with the operation, the scope, the `subject_ref` (resolve) or nothing about the subject (list), the reason and no outcome. If it cannot be committed, nothing is read.
2. **One transaction.** `authorize_platform_caller()`; the independent register eligibility check (O4); for a tenant scope, `bind_tenant_scope(session, tenant_id)` and `lock_open_tenant`; the link read with the explicit scope predicate; a tenant audit row (`audit_subject.resolved` or `audit_subject.listed`, `metadata: {"platform": true, ...}`); unbind; a platform completion row (`success` or `failure`). A permission refusal is recorded by `recording_platform_refusal`.
3. **Return only after commit** (ADR-0031): the identifying value leaves the server only once its evidence is durable. Response with `Cache-Control: no-store`; the value is never logged.

**No row records the resolved user id**, and the list call's input user id is not recorded either; the reason reference points to the case file that already holds the identity. Rows record the operator (as the row's actor, from the session), scope, reference or count, reason and outcome.

**What "every lookup is audited" covers.** Every request from an active operator that reaches the permission check produces platform audit rows: attempt and completion, or a refusal. A request from a caller who is not an active operator gets the `404` of an unknown path and nothing is recorded; that is ADR-0045's existing route chain (section 2.6), applied to every platform route. Recording those probes too would change the chain for all routes and is not proposed here. **O7, decided (owner, 2026-11-03, merge preparation): option (a), probes by non-operators are not recorded.**

**Holds need the list call.** A hold scoped to one person names that person's references, which only `list` can find. This makes person-scoped hold placement depend on the authenticated API, consistent with O8 (holds placed and released through the authenticated API).

### 4.6 User erasure

`erase_user_identity()` gains two steps; the hold rule is D4.

- **Platform scope**, in the untenanted transaction of `remove_identity_links_unless_enrolled_operator` (so an enrolled operator is refused before anything changes): `H(platform)` shared; `S(platform, user)` exclusive; insert the platform erasure marker (`ON CONFLICT DO NOTHING`); lock the user's live platform links `FOR UPDATE ORDER BY subject_ref`; unlink each one not covered by an active platform hold (`SET user_id = NULL, unlinked_at = now(), unlink_reason = 'erasure'`); record counts.
- **Each tenant**, in `_erase_membership_in_tenant`'s transaction, after its existing outbox and membership locks: the same steps against the tenant tables. The counts (links unlinked, links kept under hold; never reference values) go into the existing `identity.erasure_membership_removed` row or, when no membership was removed, a row of their own, as `identity.erasure_outbox_initiators_erased` does today.

The marker also covers a consumer that read the user from an outbox event before the erasure: its later audit write sees the marker and gets an unlinked reference (section 4.4, 3c). A held link stays live; the first expiry run after the hold is released unlinks it, because the marker remains (D4). The markers hold the user id, as they must to recognise the subject; the expiry command deletes a marker once `erased_at + 2 years <= now()` and no live link of that subject remains in its scope.

**Partial erasure.** Each scope is its own transaction. A crash after the platform step and some tenants leaves those committed and complete, and the remaining tenants untouched: their links are still live and resolvable, and new writes there still link the user, until a rerun. `erase_user_identity()` is rerun for recovery as today; every step is idempotent (markers by `ON CONFLICT DO NOTHING`, unlinking only rows still live), so a rerun completes the remaining scopes and changes nothing in the finished ones. No scope is ever half done.

**After a marker expires (O10, decided 2026-11-03: markers expire after two years).** Once the expiry command has deleted the marker of a scope (section 4.8; only possible when O9's gate allows `--apply`), that scope no longer treats the user as erased. Concretely:

- **A later audit record about the user** (an operator acting on the still existing `core.users` row, or a product writing about the person) gets a new live link for that day. It identifies only the new record, which has its own two years; references issued before the marker expired stay unresolvable, because their links were unlinked or deleted.
- **An outbox retry.** Erasure rewrote every stored initiator naming the user to `"unavailable"` in the tenants it was given (`erase_user_initiator`), so a retry of such an event, before or after marker expiry, records `"unavailable"`. An event appended after the erasure that still names the user (a product that kept the id) is refused by the D2 gate until tenant references ship; afterwards it gets an unlinkable reference while the marker exists and a live link once it has expired.
- **A replay** (`replay_dead_lettered_events`) re-reads the stored payload, so it behaves as a retry. An event in a tenant the erasure was not given keeps the user as initiator, and that tenant never had a marker: marker expiry changes nothing there; rerunning the erasure with that tenant does.
- **A backup restore** to a point before the marker was deleted brings the marker back: later records are unlinkable again until the next expiry run deletes it again (towards protection). A restore to a point before the erasure brings the user's live links back and lacks the marker; the erasure must be rerun from its case record before serving traffic (section 4.12), which creates a new marker whose two years start at the rerun.
- **A re-erasure** after expiry inserts a new marker (`erased_at` = the rerun) and unlinks every live link created since the old marker expired, except held ones, exactly like a first erasure.
- **Unchanged by marker expiry:** the erasure's own audit rows keep `resource_id = str(user_id)` (`identity.erasure_membership_removed`, `identity.erasure_outbox_initiators_erased`; inventory field TA-2), so the fact of the erasure stays identifiable whatever happens to the marker.

### 4.7 Locks and concurrent operations

**Same transaction (ADR-0031).** Get-or-create runs in the session of the audit write. The link insert, the audit insert and the audited change commit together or not at all; a rollback leaves no link behind.

Two advisory transaction locks per scope (no table privileges needed; released at commit or rollback):

- `H(scope)` = `hashtextextended('audit-holds:' || <tenant_id or 'platform'>, 0)`
- `S(scope, user)` = `hashtextextended('audit-subject:' || <tenant_id or 'platform'> || ':' || user_id::text, 0)`

| Operation | Lock order |
|---|---|
| Audit writer | its business row locks; `S` shared; link insert or select; audit row |
| Erasure (per scope) | existing outbox and membership locks (tenant); `H` shared; `S` exclusive; marker; links `FOR UPDATE` by `subject_ref`; audit row |
| Hold place or release (per scope) | `H` exclusive; hold row; audit rows |
| Expiry (per scope) | `H` shared; links and markers `FOR UPDATE` by key; delete or unlink; audit row |

A writer takes `S` after its business locks and nothing after it; erasure takes `S` after the membership lock, so the two cannot wait on each other in a cycle. A product writer that locks further rows after its audit write could still deadlock with an erasure; PostgreSQL aborts one (`40P01`) and both are safe to retry. A hash collision between two keys only makes unrelated operations wait.

**Races.** Two writers of one subject and day get the same reference (section 4.2). Writer and erasure are serialized by `S`: a writer that commits first has its link unlinked; one that comes after sees the marker. Writer and expiry are disjoint: a writer touches only today's link, and expiry touches only links whose day ended more than two years and one day ago (section 4.8). Hold changes wait for a running expiry or erasure of the scope and the reverse (`H`); expiry and erasure read the holds after taking `H`. Two expiry runs: the second waits on row locks, then finds the rows gone.

### 4.8 Retention calculation and boundaries

All computation uses the database clock (`now()`, the transaction start time) and UTC, never the application host's clock or the session `TimeZone`.

**Per record (the exact rule; kept by the owner on 2026-11-03).** Express `r.created_at` in UTC as date `Y-M-D` and time of day `τ`. `r` expires at `E(r)` = the UTC instant with date `(Y+2)-M-D` and time `τ`; when `M-D` is 02-29 (only possible in a leap year `Y`, so `Y+2` is never one) the date is `(Y+2)-02-28` with the same `τ`; no other date is adjusted. The boundary is **inclusive**: `r` is past retention when `E(r) <= now()` on the database clock. Examples: 2028-02-29 12:00 UTC expires 2030-02-28 12:00 UTC (730 days), the same instant as a record of 2028-02-28 12:00 UTC (731 days); 2028-02-29 00:30+01 is 2028-02-28 23:30 UTC and expires 2030-02-28 23:30 UTC. The rule is normative; the full test vectors are in the decision record. The proposed SQL is `E(r) = (r.created_at AT TIME ZONE 'UTC') + interval '2 years'` (a `timestamp`, UTC wall time): PostgreSQL adds years by calendar fields and uses the month's last day when the result date does not exist, which matches the rule; the SQL review must confirm it against the vectors (section 8, item 4), and if the SQL disagrees, the SQL changes. Computing on `timestamp` in UTC avoids the session-time-zone dependence of `timestamptz + interval` across daylight-saving changes.

**Per link.** A link may be deleted only when **every** audit record referencing it is past retention, plus one day of margin against clock steps and long transactions:

`max over referencing r of E(r) + interval '1 day' <= now() AT TIME ZONE 'UTC'`

Two bounds are used, and both must hold:

1. **Day bound (from the day, not from rotation).** Every Core-written reference is created and used in a transaction whose `now()` falls on `subject_day`, so every referencing record has `created_at` in `[subject_day 00:00, subject_day + 1 day 00:00)` UTC. For a time `t` on day `d`, `t + 2 years` is `(d + 2 years)::date` plus `t`'s time of day (the clamp moves the date, not the time), so it is strictly before `(d + interval '2 years')::date + 1`. Hence the day bound `((subject_day + interval '2 years')::date + 2)::timestamp <= now() AT TIME ZONE 'UTC'` (one day for the bucket, one day of margin). Note that `(subject_day + 1 day) + 2 years` would **not** be a valid bound: for `subject_day` 2028-02-28 it gives 2030-02-28 00:00, earlier than the expiry of a record created 2028-02-28 23:00.
2. **Record bound (from `max(created_at)` of actual referencing rows).** The command also finds the referencing audit rows through the locations Core writes and requires `max(created_at)` to be past retention. This catches a reference used outside its day (a defect, or a product that copied one) **in the identifying locations only**: `target_type = 'user_subject'` on platform rows and `initiated_by.subject_ref` on tenant rows. Rows that mention a reference as the object of a lookup or hold are not searched and do not extend the link (R3, as narrowed). References a product copies into its own metadata keys cannot be found and remain the product's obligation (O5, decided 2026-11-03: product responsibility).

Expiry query, platform scope (proposal, not run against PostgreSQL; not validated DDL):

```sql
SELECT l.subject_ref
  FROM core.platform_audit_subject_links l
 WHERE ((l.subject_day + interval '2 years')::date + 2)::timestamp
       <= (now() AT TIME ZONE 'UTC')                                  -- day bound
   AND NOT EXISTS (                                                   -- record bound
         SELECT 1 FROM core.platform_audit_log a
          WHERE a.target_type = 'user_subject'
            AND a.target_id = l.subject_ref::text
            AND (a.created_at AT TIME ZONE 'UTC') + interval '2 years' + interval '1 day'
                > (now() AT TIME ZONE 'UTC'))
   AND NOT EXISTS (                                                   -- legal hold (4.9)
         SELECT 1 FROM core.platform_audit_identity_holds h
          WHERE h.released_at IS NULL
            AND (h.subject_ref IS NULL OR h.subject_ref = l.subject_ref)
            AND (h.from_day IS NULL OR h.from_day <= l.subject_day)
            AND (h.to_day   IS NULL OR h.to_day   >= l.subject_day))
 ORDER BY l.subject_ref
   FOR UPDATE OF l;
```

The record bound uses `ix_platform_audit_log_target (target_type, target_id)`. `l.subject_ref::text` is PostgreSQL's canonical lowercase form, so `target_id` must be written with `str(uuid)`, never upper case or braces.

Tenant scope: the same query against `core.audit_subject_links` with `l.tenant_id = :tenant_id`, in a transaction bound to that tenant, and a record bound over `core.audit_log` with `a.tenant_id = :tenant_id AND (a.metadata -> 'initiated_by' ->> 'subject_ref') = l.subject_ref::text`. That needs a new expression index on `core.audit_log`, for example `(tenant_id, (metadata -> 'initiated_by' ->> 'subject_ref'))`, built `CONCURRENTLY`. Adding an index changes no row and no digest, but it is DDL on the largest audit table and is listed in section 8.

**Markers.** Eligible when `(erased_at AT TIME ZONE 'UTC') + interval '2 years' + interval '1 day' <= now() AT TIME ZONE 'UTC'` and no live link of the subject remains in the scope. **Consequence:** once a marker is deleted, the scope no longer treats the user as erased; a later audit record naming that user (for example an operator acting on the still-existing `core.users` row) gets a new live link. That link identifies only the new record, which has its own two years; the deleted references stay unresolvable. **O10, decided (owner, 2026-11-03):** "erasure markers expire after two years". Consequences for retries, replays, restores and re-erasure: section 4.6, "After a marker expires". Markers are deleted by the expiry command, so they are kept while its `--apply` is disabled (O9).

**Deviation.** A link outlives its records' two years by at most two days (bucket plus margin), plus however long the next expiry run takes to happen (D7: runs are person-run), plus any hold. It never expires early. Backups keep removed identification until they rotate out (`BACKUP_RETENTION_COUNT`, default 7 runs).

### 4.9 Legal holds (D4)

Holds take precedence over both expiry and erasure. Hold tables (tenant and platform; the tenant one shown; proposal, not run against PostgreSQL; not validated DDL):

```sql
CREATE TABLE core.audit_identity_holds (
    id                             uuid         NOT NULL,
    tenant_id                      uuid         NOT NULL REFERENCES core.tenants (id),
    reference                      varchar(100) NOT NULL,  -- legal matter id, never a name
    from_day                       date         NULL,      -- NULL: open-ended
    to_day                         date         NULL,      -- NULL: open-ended, inclusive
    subject_ref                    uuid         NULL,      -- NULL: every subject
    placed_at                      timestamptz  NOT NULL DEFAULT now(),
    placed_by_platform_audit_id    uuid         NOT NULL,
    released_at                    timestamptz  NULL,
    released_by_platform_audit_id  uuid         NULL,
    CONSTRAINT pk_audit_identity_holds PRIMARY KEY (id),
    CONSTRAINT ck_audit_identity_holds_reference
        CHECK (reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$'),
    CONSTRAINT ck_audit_identity_holds_days
        CHECK (from_day IS NULL OR to_day IS NULL OR from_day <= to_day),
    CONSTRAINT ck_audit_identity_holds_release_pairing
        CHECK ((released_at IS NULL) = (released_by_platform_audit_id IS NULL)),
    CONSTRAINT ck_audit_identity_holds_release_order
        CHECK (released_at IS NULL OR released_at >= placed_at)
);
CREATE UNIQUE INDEX uq_audit_identity_holds_active
    ON core.audit_identity_holds (tenant_id, reference, subject_ref)
    NULLS NOT DISTINCT WHERE released_at IS NULL;
```

With `tenant_rls_statements()` and a one-way release trigger as in PR #198 (`check_violation` on any change to a released hold, for every role). The platform table is the same without `tenant_id`, with `tenant_context_exclusion_statements()`.

- **Matching.** A link is held while an active hold of its scope has a NULL or equal `subject_ref` and a day range (inclusive at both ends, `NULL` open) containing `subject_day`. Day ranges use the same UTC days as links, so there is no time-zone boundary.
- **Precedence.** Expiry skips held links (section 4.8 query). Erasure unlinks every link of the subject not held and keeps held ones live (section 4.6).
- **Release.** Releasing sets `released_at`; nothing is deleted or unlinked at release time. **The first expiry run after the release** processes what becomes eligible: it deletes held links whose retention passed during the hold, and unlinks live links of erased subjects (the erasure marker is still present). Until that run the identification stays live; the D7 report job shows the backlog.
- **Person-scoped holds** name references (from the list call, section 4.5), never a user id. Covering a person's future days needs a scope-wide hold, which retains more than necessary; that is the price of never storing a user id in a hold.
- **Entry point.** Placement and release write a platform attempt row first (its id becomes `placed_by_platform_audit_id`), then the hold and a tenant audit row in one tenant transaction, then a completion row, plus one structured log line per change (hold id, scope, day range, matter reference; never a user id) so holds can be rebuilt after a restore. **O8, decided (owner, 2026-11-03):** "holds placed and released through the authenticated API; a CLI may only place a hold." Placement and release run as platform-admin routes with the session's identity (no identity field in bodies, extra fields refused, following PR #198's retention API conventions); an operator command, if provided, can only place a hold (its declared id errs towards retention) and has no release path. The hold routes use PR #198's existing `platform.security_retention_hold:manage` (decided 2026-11-03, final closure; no new permission). The routes write as the application role, so whoever holds the application-role credential could also write or release hold rows directly, as for PR #198's retention API; the platform and tenant audit rows written with each change, and their ADR-0053 digests, are how such a change is detected.

### 4.10 Expiry procedure (D7)

- **Runner.** A migrations-role command (proposal: `python -m saas_os.ops.audit_identity_expiry`), the only role with `DELETE` on the link and marker tables. A scheduled worker job, under the application role with `SELECT` only, may **report** eligible and overdue counts per scope; it never deletes and has no privilege to.
- **Dry run by default.** The report lists, per scope, the eligible link count, the marker count, the canonical hash of the eligible references (section 4.11) and the canonical hash of the active hold ids.
- **Apply.** `--apply` requires `--confirm-rows`, `--confirm-digest` and `--confirm-holds` copied from a dry-run report; in each scope transaction the command recomputes the eligible set and the hold set after taking `H` and refuses (`AuditIdentityExpiryRefusedError`, nothing deleted in that scope) unless all three match. This is PR #198's confirmation pattern (`saas_os/ops/permission_grant_ledger_expiry.py`, on that branch only). What each confirmation covers: `--confirm-rows` and `--confirm-digest` cover the set of links to be **deleted** (eligible under section 4.8, live or unlinked); `--confirm-holds` covers the active hold ids. Two further sets are not covered by any digest: live links of erased subjects to be **unlinked** after their hold was released, and erasure markers to be deleted. The dry-run report gives their counts, the apply recomputes them, and a changed count also refuses the apply.
- **Order.** A platform start row (planned scopes and counts) is committed first. The platform scope runs in one untenanted transaction; each tenant in one transaction bound to that tenant. Each scope transaction deletes eligible links (live or unlinked), unlinks released-hold links of erased subjects, deletes eligible markers, and writes its audit row with the three counts and the hash of the deleted-link set. A platform finish row closes the run.
- **Declared operator.** The command's `--operator` is declared, not authenticated (section 2.5). Its records show who the person at the terminal said they were; the control is possession of the migrations credential. **O9, decided (owner, 2026-11-03):** "ledger expiry `--apply` stays disabled until an authenticated, register-eligible approval mechanism is implemented, independently reviewed and tested." Applied here to the expiry of links and markers (O9 is this command's open item). The module carries a literal gate (design name `_APPLY_ENABLED = False`, modelled on `_DELETION_ENABLED` in PR #198's `saas_os/core/permission_grants/expiry.py`); `--apply` is refused before connecting; no setting, environment variable or argument enables it, and only a separate, owner-approved code change flips the literal after the approval mechanism is implemented, independently reviewed and tested (PR #198's design, section 8.6). Dry runs and the report job are unaffected. Until the approval mechanism exists, links and markers are kept beyond two years (towards retention; the privacy notice must say so).

### 4.11 Deletion evidence and the canonical reference-set hash (D8)

Each **expiry** scope transaction writes an audit row with counts and a SHA-256 over the deleted references. Those audit rows are covered by the ADR-0053 digests, which anchors the evidence externally. Expiry rows name no subject: their actor is the declared operator, and the set mixes every subject of the scope.

**Erasure evidence is counts only, never a hash.** The tenant erasure row `identity.erasure_membership_removed` already carries `resource_id = str(user_id)` (`_erase_membership_in_tenant`, `saas_os/core/identity/erasure.py`), and audit rows are `SECURITY_RETAIN`. A hash of that user's references in the same row would let anyone who holds references (for example from an audit export) hash candidate subsets and test which references belong to the named user: re-identification through the evidence itself. A hash under a per-run secret salt that is then discarded would avoid that, but could never be verified afterwards and so would prove nothing; it is not proposed. D8 therefore applies to expiry; erasure records the numbers of links unlinked and kept under hold.

**Canonical form, version 1.** The hash is computed in Python, never in SQL (no dependence on collation, `string_agg` order or client encoding):

```text
message = PREFIX || SCOPE || LF || COUNT || LF || REF_1 || LF || ... || REF_n || LF
PREFIX  = "saas-os/audit-subject-ref-set/v1" || LF        (domain separation and version)
SCOPE   = "platform"  or  "tenant:" || <tenant uuid, canonical lowercase>
COUNT   = n in ASCII decimal, no sign, no leading zeros ("0" when empty)
REF_i   = str(uuid.UUID(...)): 36 characters, lowercase hex, hyphens at 8-4-4-4-12,
          no braces, no "urn:uuid:" prefix
order   = strictly ascending by the bytes of REF_i (equal to the uuid's 128-bit
          big-endian order and to PostgreSQL's uuid ordering); a duplicate is an
          error, never silently removed
LF      = the single byte 0x0A; no CR, no BOM, no other whitespace
encoding = ASCII (every byte < 0x80; identical in UTF-8)
digest  = lowercase hexadecimal of SHA-256(message), 64 characters
empty set: n = 0 and no REF lines; the message is PREFIX || SCOPE || LF || "0" || LF,
           and its hash is still recorded, so a run with nothing to do is evidenced too
```

The hold-set hash used by `--confirm-holds` has the same form with the prefix `saas-os/audit-identity-hold-set/v1` and hold ids as items. Any change to the format takes a new version string.

**What this proves, and what it does not.** It lets anyone holding a candidate list of references check whether it is exactly the set a run reported, and it binds the set to its scope and count. It is **not** a proof of the integrity of the deleted link-table contents: it says nothing about which user ids the deleted rows held, whether the link table was altered before the run (the link table is not digested, by design, because its rows change lawfully), or whether a migrations-role user removed rows by plain SQL outside the command. Deletion and its evidence row commit in one transaction, which is the only guarantee that a recorded run deleted what it reports.

### 4.12 Failure and recovery

- **Link insert fails** (constraint, RLS, connection, retries exhausted): the audit write raises and the audited change rolls back with it. There is no fallback to writing the raw id.
- **Expiry run crashes.** Each scope is one transaction: the scope in progress rolls back; committed scopes are done, each with its audit row. A start row without a finish row identifies the interrupted run. A rerun needs a new dry run (the confirmed counts are per run) and continues; already-processed scopes report zero.
- **Erasure crashes.** Section 4.6.
- **Restore from backup.** A restored database contains links unlinked or deleted after the backup and lacks markers, holds and erasures made after it. Before serving traffic: (1) re-place holds made since the backup from the platform audit evidence and the hold log lines; (2) rerun erasures made since the backup from their case records (already necessary for `erase_user_identity()`); (3) run the expiry procedure. Until then, identification removed since the backup is live again.
- **A hold lost by a restore** is the dangerous case; `--confirm-holds` forces the operator to compare the active hold set with the externally logged hold history before anything is deleted.

### 4.13 Existing rows (D5)

Rows written before the mechanism keep their raw user ids: a documented legacy exception. No audit row and no digest is rewritten in this phase; the ADR-0051 and ADR-0053 guarantees stay as they are. Identification in these rows does not expire. The release notes and privacy notice must say so. An optional read-only backlog report (counts per scope and calendar year of `created_at`, no ids) can show the size of the exception; it changes nothing. In-place redaction (alternative (d), section 5) would need an ADR amending ADR-0051 and ADR-0053 and digest format version 2, and is not part of this phase.

With D2 limited to `initiated_by` (O1, decided), no new tenant `initiated_by` user id is written once the gate ships, so that part of the legacy set closes then. The `actor_user_id` columns (the decided temporary exception), Core metadata keys and tenant `resource_id` values keep adding raw ids (section 4.1, outstanding privacy risk). Platform target users keep being written raw until the platform mechanism ships (D6 does not gate them), so the platform legacy set grows until then.

### 4.14 Audit digest integrity (ADR-0053)

References are written at insert time and never change, so every window digest recorded before an expiry recomputes identically after it. No digest format change is needed. The link, marker and hold tables are not digested and do not join the ADR-0053 windows, because their rows change by design; their changes are evidenced by audit rows that are digested (section 4.11).

## 5. Alternatives compared

- **(a) Random references and a deletable link table**: this design.
- **(b) Keyed HMAC pseudonyms** `HMAC(K_day, scope || user_id)`. No link table; lookup recomputes for every user id. One key serves every subject of the day: erasing one person means deleting the key for everyone or failing the erasure; while a key exists, whoever obtains it re-identifies the whole day by hashing all user ids.
- **(c) Per-subject encryption keys (crypto-shredding).** Once the row carries a key id (which is (a)'s reference) the guarantees equal (a), at the cost of encryption in every audit write, key management and a key-loss failure mode.
- **(d) In-place redaction of audit rows with a redaction ledger.** The only option that covers rows already written, but it mutates the evidence ADR-0051 keeps immutable, needs digest format version 2, verifier changes and an updating role. Excluded for this phase by D5.
- **(e) Keep raw ids** and rely on erasing `core.users` identity data. `core.users.id` is kept forever, so nothing expires. Does not implement the policy.

| | (a) | (b) | (c) | (d) | (e) |
|---|---|---|---|---|---|
| R1 append-only | yes | yes | yes | **no** | yes |
| R2 digests verify | yes | yes | yes | only with digest v2 | yes |
| R3 per-record expiry | at most two days late | at most two days late | at most two days late | exact | **no** |
| R4 holds | per subject or scope | whole day key | yes | per record | n/a |
| R5 unrecoverable | after unlinking (backups until rotation) | only when the shared key goes | after key deletion | yes | **no** |
| R6 bounded linkage | within one day and scope | same | same | none | unbounded |
| R7 authenticated lookup | yes (D3) | by enumeration | yes | before redaction only | no control |
| R8 legacy rows | declared exception (D5) | same | same | yes | n/a |

(a) is the only option meeting R1 to R7 while allowing one person to be erased alone, with no change to the audit tables, their grants or the digest format.

## 6. Decision record (owner, 2026-11-02; restated 2026-11-03)

Decided by the owner on 2026-11-02 and restated by the owner on 2026-11-03 in these words: D1 "random user reference per user per UTC calendar day"; D2 "reject new user initiators in `initiated_by`; the `actor_user_id` database requirement remains a temporary documented exception"; D3 "identity lookup only through the authenticated platform-admin API; every lookup audited"; D4 "legal holds take precedence; the first expiry run after release processes newly eligible records"; D5 "existing raw-ID audit records remain a documented legacy exception; do not rewrite existing audit records or their digests in this phase"; D6 "target users in platform audit records only; operator identities are excluded from this policy"; D7 "migrations-role expiry command with dry run and explicit confirmation; scheduled jobs may only report"; D8 "deletion evidence = counts + SHA-256 over the canonicalised affected references; do not claim it proves the integrity of deleted link-table contents". The open items O2, O4, O8, O9, O10 and O11 were decided on 2026-11-03; each decision, its short rationale and the evidence and tests it needs when implemented are in the decision record (`docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md`). The previous version of this section listed options and recommendations; where a decision differs from the earlier recommendation, that is noted.

**D1. Reference granularity: a new random reference per UTC calendar day.** Decided 2026-11-02. One live reference per (scope, user, UTC day), the day being `(now() AT TIME ZONE 'UTC')::date` of the audit write's transaction (section 4.2). Replaces the earlier recommendation of a calendar month. Consequences: linkage after expiry is limited to one day; a link outlives its records' two years by at most two days (section 4.8); the link tables hold one row per active (scope, user, day).

**D2. Verbatim: "Until the new reference/link-table mechanism is implemented, reject user initiators in audit records. Do not store raw user IDs in new audit records. Preserve the existing outbox erasure behaviour."** Decided 2026-11-02. Its reach was settled by **O1 (decided 2026-11-02):** "D2 applies to `initiated_by`. New audit records must reject user initiators that would store raw user IDs in `initiated_by`. Existing mandatory `actor_user_id` storage remains a temporary exception because current database constraints require it for user-actor records." The outbox storage of initiators and its rewrite on erasure are unchanged. The gate changes PR #196's audit path; it is **not implemented in this document's commits** and is implemented in PR #201 (merged as `021e487`) (section 7); #196 no longer accepts user initiators in audit records. The raw ids that remain are listed in section 4.1 as an outstanding privacy risk.

**D3. Lookup only through an authenticated and authorised operator function; every lookup is audited; a declared operator id is not proof of identity.** Decided 2026-11-02. Implemented by design as platform-admin API routes behind `require_platform_permission` with an OIDC session (section 4.5), following the pattern PR #198's approval design proposes for retention. Replaces the earlier recommendation of an operator command with a declared operator id. The permission is decided by O4 (2026-11-03): `platform.security_retention:report` and independent register eligibility, no new permission.

**D4. Legal holds take precedence.** Decided 2026-11-02. Over expiry and over erasure. Eligible records under a released hold are processed by the first expiry run after the release (section 4.9).

**D5. Existing raw-user-id records are a documented legacy exception.** Decided 2026-11-02. No rewriting of existing audit records or digests in this phase (section 4.13).

**D6. Initial scope: target-user identification in platform audit records.** Decided 2026-11-02. The retention of operators' own identities is a separate policy decision and is not included (section 4.1). O2 (2026-11-03) gives references to the non-operator targets of failed or refused enrolments; OD-1 and OD-2 (2026-11-03, final closure) limit the operator exclusion to actors, so every target user, operators included, gets a reference.

**D7. Expiry is a migrations-role command with dry run and explicit confirmation; a scheduled job may only report, never delete.** Decided 2026-11-02. Section 4.10. O9 (2026-11-03): `--apply` stays disabled until an authenticated, register-eligible approval mechanism is implemented, independently reviewed and tested.

**D8. Deletion evidence is audit records with counts and a cryptographic hash over the affected references.** Decided 2026-11-02. It is explicitly **not** a proof of the integrity of the deleted link-table contents. Canonical form in section 4.11. The two-year calculation on each record's `created_at`, with its leap-day rule, is kept (owner, 2026-11-03; exact rule in section 4.8). Applied to expiry runs; erasure evidence records counts only, because erasure rows name the user and a reference-set hash beside the user id would allow re-identification (section 4.11).

## 7. The D2 code change (PR #201, merged as `021e487`; not on PR #196)

D2 changes the runtime behaviour of PR #196, so no commit on #196 implements it. It is implemented in PR #201 (merged as `021e487`). **Compatibility unit (owner, 2026-11-03): #196 is never merged without #201.** On 2026-11-03 #201 is being extended to `record_platform_event_in_transaction`, so that `metadata["initiated_by"]` cannot carry a user initiator into a platform row, and to an audit of every audit-writer call site and of the consumers; #201 is the authority for what it implements and for its evidence, and this document does not restate its results. **Historical (before #201 merged), #196 itself accepted user initiators in audit records:** `record_in_transaction` and `record_system_action_in_transaction` on the #196 branch stored `{"type": "user", "user_id": ...}` under `initiated_by`. Merging #196 without #201 would have released the raw-id shape that D2 forbids. The table below is the change as designed here; #201 is authoritative for what was actually changed. What changes:

| File | Symbol | Change |
|---|---|---|
| `saas_os/core/audit_log/service.py` | `_require_attribution_types` (called by `_attribution`, `record_in_transaction` and, through `_attribution`, `record_system_action_in_transaction`) | Raise `InvalidActorError` when `initiated_by` is an `Initiator` with `type is InitiatorType.USER`, before any insert. Both public writers are covered because both go through this check; `record()` takes no `initiated_by`. No new error type and no public API change |
| `saas_os/core/audit_log/service.py` | docstrings of `record_in_transaction`, `record_system_action_in_transaction` | State the refusal and that a user-initiated asynchronous action is recorded with `initiated_by=None` (`"unavailable"`) until references ship |
| `saas_os/core/authority/attribution.py` | `Initiator` docstrings | Unchanged behaviour: `Initiator.user`, `from_caller`, `as_metadata`, `from_metadata`, `from_job_initiator` still produce and parse the user shape, because the outbox still stores it |
| `docs/CONSUMER-GUIDE.md` | system-actor attribution section | A consumer must pass `initiated_by=None` when `context.initiated_by` is a user; passing the converted user initiator now fails |
| `tests/core/audit_log/test_system_actor_unit.py` | `test_a_user_initiated_system_row_names_the_user_only_as_initiator`, `test_record_in_transaction_writes_a_system_callers_attribution_beside_its_purpose` (user-initiator cases) | Assert the refusal instead of the stored user shape |
| `tests/core/audit_log/test_system_actor_integration.py` | `test_the_actor_is_committed_with_the_callers_transaction` | Use a non-user initiator, plus a refusal case that writes nothing |
| `tests/api/test_outbox_attribution_integration.py` | `test_a_user_initiator_is_preserved_from_producer_to_the_consumers_audit_row` | Keep asserting the stored outbox payload and the in-memory `context.initiated_by`; assert the audit writer refuses the user initiator and that `None` records `"unavailable"` |

Unchanged by D2: `append_event` (`saas_os/core/outbox/service.py`), `_split_initiator` (`saas_os/core/outbox/dispatch.py`), `_job_initiator` (`saas_os/api/outbox_dispatcher.py`), `erase_user_initiator` (`saas_os/core/outbox/initiator_erasure.py`), and the service-account and system initiator shapes.

Consumer consequence (found by #201): a consumer that converts `context.initiated_by` for a user and passes it to an audit writer is refused (`InvalidActorError`); its outbox event's job fails, retries and finally dead-letters. #201's consumer-guide change tells consumers to pass `initiated_by=None`, which records `"unavailable"`. PR #196 is unreleased, so no released consumer is affected; the guide change and release notes are the mitigation. Whether Core should offer a helper that maps a user initiator to `None` is a public API addition and is not proposed here.

## 8. PostgreSQL-specific SQL and migration review required before implementation

None of the SQL in this document has been run. Before implementation, a reviewer must verify on PostgreSQL 16 (the supported version) at least:

1. **Partial unique index as `ON CONFLICT` arbiter.** `ON CONFLICT (tenant_id, user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING` infers `uq_audit_subject_links_live`; the predicate must imply the index predicate. Confirm that a primary-key conflict is not absorbed and raises `23505`, and the savepoint retry works through SQLAlchemy `begin_nested()`.
2. **`NULLS NOT DISTINCT`** (PostgreSQL 15 and later) on `uq_audit_identity_holds_active`, combined with a partial `WHERE released_at IS NULL`; confirm two active tenant-wide holds (`subject_ref` NULL) with the same reference conflict, and alembic `op.create_index` can emit the clause (likely raw `op.execute`).
3. **UTC day computation.** `(now() AT TIME ZONE 'UTC')::date` versus the three-argument `date_trunc('day', now(), 'UTC')` (PostgreSQL 12 and later); confirm both are independent of the session `TimeZone`; this design uses the former.
4. **Interval arithmetic.** `date + interval '2 years'`, `timestamp + interval '2 years'` (leap-day clamp: 2028-02-29 to 2030-02-28; every test vector of the exact rule, section 4.8 and the decision record), `(...)::date + 2`, and that no expression uses `timestamptz + interval` (session-zone dependent).
5. **RLS.** `ENABLE` plus `FORCE` on the six tables; the owner (migrations role) is bound by `FORCE`; the commands set `app.tenant_id` per transaction; `42501` on a cross-tenant insert; the exclusion policy on the platform tables; that `ON CONFLICT DO NOTHING` under RLS behaves as expected (the conflicting row must be visible to the policy).
6. **Trigger semantics.** The one-way `BEFORE UPDATE` triggers (no `SECURITY DEFINER`, `SET search_path`), raising `23514`; interaction with `ON CONFLICT` (no `DO UPDATE` is used).
7. **Lock levels of each DDL.** `CREATE TABLE` (none on existing tables); `REFERENCES core.tenants`, `REFERENCES core.users` (`SHARE ROW EXCLUSIVE` on the referenced tables while the constraint is added); `CREATE INDEX` on the new empty tables (`SHARE`, harmless); the expression index on `core.audit_log` (plain `CREATE INDEX` takes `SHARE` and blocks every audit insert for the build, so it must be `CREATE INDEX CONCURRENTLY` (`SHARE UPDATE EXCLUSIVE`), outside a transaction block, in an alembic `autocommit_block()`, with a check for an `INVALID` index after a failed build); `GRANT`/`REVOKE`; `CREATE POLICY` and `ALTER TABLE ... ROW LEVEL SECURITY` (locks on the new tables only; exact level to confirm).
8. **Expression index on `json`.** `metadata` is `json`, not `jsonb`; confirm `->` and `->>` on `json` are immutable and indexable, and that the planner uses the index for `(metadata -> 'initiated_by' ->> 'subject_ref') = $1`.
9. **Advisory locks.** `pg_advisory_xact_lock_shared` and `pg_advisory_xact_lock` with `hashtextextended(text, 0)` (64-bit); confirm no conflict with other advisory-lock users in the codebase.
10. **Text equality of references.** `uuid::text` output is lowercase canonical; `target_id` (varchar) written with `str(uuid)`; no collation dependence for equality.
11. **`gen_random_uuid()`** available without `pgcrypto` on the supported versions.
12. **Bind parameters and casts.** In SQLAlchemy `text()`, `:name::text` is mis-parsed (the `::` cast collides with the `:name` bind syntax); every cast of a bind parameter must be written `CAST(:name AS text)`. Check every statement here and in the implementation.
13. **Isolation check.** `current_setting('transaction_isolation')` returns `read committed` by default; confirm the get-or-create refusal under the other levels (section 4.4).
14. **Downgrade.** Refuses while any row exists in the new tables (the PR #198 pattern): dropping a link table destroys the only way to resolve references already written. The expression index downgrade uses `DROP INDEX CONCURRENTLY`.
15. **Default privileges** from `e99c76057719` are narrowed exactly as in section 4.3, checked by a grant test, including column-level `UPDATE`.
16. **Query plans** for the expiry query on realistic volumes (anti-joins over `core.platform_audit_log` and `core.audit_log`), and `FOR UPDATE OF l` with `NOT EXISTS` subqueries.

## 9. Implementation-readiness assessment

| Area | Status | Prerequisites | Main risks |
|---|---|---|---|
| D2 gate in the audit writers (section 7) | **Implemented in PR #201** (merged as `021e487`) | O1 decided (D2 is `initiated_by` only); #201 merged | Consumers passing a user `context.initiated_by` to an audit writer are refused and their events retry, then dead-letter; #201's guide says pass `None` (none released) |
| Reference generation and get-or-create, platform scope | Not ready | SQL review (section 8, items 1, 3, 5, 9, 11, 12, 13); O6 decided (a), record no target, with its foreign-key implications addressed (2026-11-04, option A1: the foreign key stays, existence decided in the audit transaction); release-note plan for `target_type = 'user_subject'` | Platform audit readers see a new target type; FK failures on unknown ids |
| Lookup API (D3) | Not ready; decided (O4, 2026-11-03) | PR #198 (`platform.security_retention:report`) and the register PR stacked on it (independent register eligibility), both merged; amendment of ADR-0045's HTTP route table for the new routes; the O11 architecture test | Register eligibility is procedural; separate accounts are not proof of separate people |
| Platform tables, RLS, grants, triggers | Not ready | SQL review (items 2, 5, 6, 7, 14, 15) | Downgrade policy; trigger correctness |
| Erasure integration | Not ready | Platform and tenant tables; lock-order review against `erase_user_identity()` | Deadlock with product writers (retryable) |
| Legal holds | Not ready; decided (O8, 2026-11-03: API for placing and releasing; a CLI may only place) | Hold tables; PR #198's `platform.security_retention_hold:manage` (decided 2026-11-03; no new permission) | A hold lost by restore; person-scoped holds need the lookup API |
| Expiry command and report job (D7) | Not ready; `--apply` disabled by decision (O9, 2026-11-03) | SQL review (items 4, 16); for `--apply`: an authenticated, register-eligible approval mechanism, implemented, independently reviewed and tested | Links and markers kept beyond two years until then; people not running it on time |
| Deletion evidence (D8) | Specified | Implementation with test vectors (empty set, ordering, scope binding) | Format drift without a version change |
| Tenant scope (lifting D2's gate) | Not ready; gated (O11) | The O11 ADR on database-enforced lookup restrictions, prepared before P3 starts; O3 decided (b): P3, after P2; expression index on `core.audit_log` (item 7, 8); tenant tables | Index build on the largest audit table |
| Legacy rows (D5) | Nothing to build | Release-note and privacy-notice text | Exception does not expire |
| Audit digests | No change needed | none | none |

**Estimated phases** (each its own PR with migration review and owner approval):

1. **P0**: D2 gate (section 7): code, tests, consumer guide; PR #201 (merged as `021e487`).
2. **P1**: platform scope (D6, O2): platform link, marker and hold tables; get-or-create in every platform target write, with no operator test (OD-2), and for the `user_id` metadata of operator events; `target_type = 'user_subject'`; lookup API (O4; after PR #198 and the register PR); the O11 architecture test; erasure step.
3. **P2**: platform holds through the API (O8) and the expiry command with the report job; `--apply` disabled (O9); markers expire under the same command (O10).
4. **P3** (the final phase of this mechanism; starts only after the O11 ADR is prepared): tenant scope: tenant tables, expression index, writers produce `initiated_by` references (lifting D2's gate), tenant lookup, per-tenant erasure and expiry.
5. **Later, separate decisions**: the identifiers that stay raw after O1 (section 4.1), operator identity retention (D6), any legacy redaction (would need an ADR amending ADR-0051 and ADR-0053).

The inventory (`docs/architecture/AUDIT-RAW-IDENTITY-INVENTORY.md`, section 9) maps these phases onto every raw identifier still stored and adds the later phases that need further owner decisions.

Honest summary: the design is complete enough to review, the canonical hash and retention rules are fully specified, every owner decision it needed is taken (decision record), and only the D2 gate is implemented (PR #201, merged as `021e487`). Everything with SQL is unverified until section 8 is done. The lookup waits on PR #198 and the register PR; `--apply` waits on an approval mechanism that does not exist yet; P3 waits on the O11 ADR.

## 10. Open items and things not decided here

O1 (2026-11-02) and O2, O4, O8, O9, O10, O11, OD-1, OD-2, OD-3 and the hold route permission (2026-11-03) are decided; the decision record (`docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md`) holds each decision, its rationale and the evidence it needs. O3, O5, O6 and O7 were decided on 2026-11-03 (merge preparation); the decision record holds each decision with its matrix. O6's foreign-key implications were addressed on 2026-11-04 (option A1); P1 is no longer blocked by O6.

- **O1. Interpretation of D2: DECIDED (owner, 2026-11-02).** "D2 applies to `initiated_by`. New audit records must reject user initiators that would store raw user IDs in `initiated_by`. Existing mandatory `actor_user_id` storage remains a temporary exception because current database constraints require it for user-actor records." Distinction and remaining raw ids: section 4.1.
- **O2: DECIDED (owner, 2026-11-03).** Non-operator targets of failed or refused enrolments get references (section 4.1).
- **OD-1, OD-2: DECIDED (owner, 2026-11-03, final closure).** An actual operator is a natural person performing an authenticated privileged operation; the operator exclusion applies to actors only, and an operator who is a target gets a reference like anyone else (section 4.1).
- **O3: DECIDED (owner, 2026-11-03, merge preparation).** Whether the tenant scope ships with the platform scope or later (sequencing only): option (b), later, in P3.
- **O4: DECIDED (owner, 2026-11-03).** No new permission; lookup requires `platform.security_retention:report` and independent register eligibility (section 4.5).
- **O5: DECIDED (owner, 2026-11-03, merge preparation).** Product metadata keys and copies of references: Core cannot detect them; product responsibility (the only stated option).
- **O6: DECIDED (owner, 2026-11-03, merge preparation).** Platform audit rows targeting a user id that does not exist (FK to `core.users`): option (a), record no target. The foreign-key implications were addressed on 2026-11-04 (option A1, section 4.4): P1 is no longer blocked by O6.
- **O7: DECIDED (owner, 2026-11-03, merge preparation).** Whether probes by non-operators of the lookup routes must also be recorded (would change ADR-0045's route chain for every platform route): option (a), not recorded.
- **O8: DECIDED (owner, 2026-11-03).** Holds placed and released through the authenticated API; a CLI may only place a hold (section 4.9).
- **O9: DECIDED (owner, 2026-11-03).** `--apply` stays disabled until an authenticated, register-eligible approval mechanism is implemented, independently reviewed and tested (section 4.10).
- **O10: DECIDED (owner, 2026-11-03).** Erasure markers expire after two years; consequences in section 4.6, "After a marker expires".
- **O11: DECIDED (owner, 2026-11-03).** API and code enforcement plus architecture tests are accepted temporarily; an ADR evaluating database-enforced lookup restrictions must be prepared before the final phase (P3); what it must evaluate: decision record.
- **OD-3: DECIDED (owner, 2026-11-03, final closure).** Tenant API-key revocation records naming a platform target user remain subject to target-user reference treatment: a tenant reference, with the tenant tables (section 4.1; inventory, field TA-5).
- **Hold route permission: DECIDED (owner, 2026-11-03, final closure).** The existing `platform.security_retention_hold:manage` (PR #198); no new permission (section 4.9).
- Whether published outbox events (kept until tenant purge, carrying `saas_os.initiated_by`) and application logs follow the same two-year rule. The policy names audit records only; outbox initiators are already rewritten on erasure.
- Who attests that removal is legally permissible, and whether a product may extend retention for its tenants. Both can be expressed as holds once decided.
