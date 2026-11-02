# Retention of user identifiers in completed audit records

**Status: Proposal; not implemented; requires separate approval.** Nothing in this document is built. It changes no schema, no runtime behaviour, no grant and no public contract. The DDL, function signatures and error names below are a design sketch for review, not code. Date: 2026-11-02.

Related: ADR-0002 (tenant isolation), ADR-0019 (field encryption), ADR-0031 (same-transaction audit), ADR-0045 (platform authority and platform audit), ADR-0051 (audit table immutability), ADR-0053 (audit digests in external logs), ADR 0061 (system actor attribution, PR #196), ADR 0060 (permission grant migrations, PR #198, not merged), `docs/MULTI-TENANCY.md` section 6 (identity erasure), `docs/BACKUP-RESTORE.md`, `docs/RUNBOOKS.md` ("Audit digests", section 4).

The design in one paragraph: where this policy applies, an audit record never stores a user id. It stores a **random, non-identifying reference** (`subject_ref`). A separate, tenant-scoped **identity-link table** maps each reference to the user id. The audit row never changes. When the retention period ends, or when the user is erased and no legal hold applies, the link row loses its user id or is deleted. From then on the reference still shows that several records in one tenant and period were made by the same subject, but not who that subject was.

## 1. The approved policy (owner, 2026-11-02)

For completed audit records that contain an identifiable user initiator (the `initiated_by` user id, and analogous user ids in audit metadata):

1. Default retention is two years from the audit record's creation.
2. A legal hold can suspend expiry.
3. After expiry, a controlled privacy process removes or anonymises direct user identification where that is legally permissible.
4. The non-identifying audit history is preserved where possible.
5. Append-only audit records are never mutated silently.
6. There is no uncontrolled deletion.

The policy is approved. Everything below is a proposal.

## 2. Current behaviour (verified on `471339d`)

### 2.1 Audit tables are append-only for the application

- Migration `2e7cb8c64903` (`saas_os/infra/db/migrations/versions/2e7cb8c64903_create_core_audit_log_table.py`) revokes `UPDATE` and `DELETE` on `core.audit_log` from the application role; `c4a9e1f07b52` (`saas_os/infra/db/migrations/versions/c4a9e1f07b52_create_platform_authority_tables.py`, `upgrade`) does the same for `core.platform_audit_log`. There is deliberately no trigger (ADR-0051 decision 2): the table owner (the migrations role) and superusers can still change rows.
- `core.audit_log.created_at` has `server_default=now()` (`saas_os/core/audit_log/models.py`, `AuditLogEntry.created_at`): the start time of the writing transaction. Callers cannot set it; neither `record()` nor `record_in_transaction()` in `saas_os/core/audit_log/service.py` takes a `created_at` argument.
- The actor columns are constrained. `core.audit_log` requires `actor_user_id IS NOT NULL` when `actor_type = 'user'` (CHECK in `saas_os/infra/db/migrations/versions/a8ad8e61deb2_add_audit_log_service_account_actor.py`), and `actor_user_id` is a foreign key to `core.users` (`AuditLogEntry.actor_user_id`). `core.platform_audit_log` has the same pairing (`ck_platform_audit_log_actor_pairing` in `c4a9e1f07b52`).
- Audit metadata is bounded at 8192 bytes (`MAX_METADATA_BYTES`, `saas_os/core/audit_log/metadata.py`).
- Sessions run at PostgreSQL's default isolation, READ COMMITTED (`saas_os/infra/db/session.py` sets no other level).

### 2.2 Tamper evidence (ADR-0053)

`saas_os/core/audit_digest/service.py` serializes each row from a fixed column list (`AUDIT_LOG_COLUMNS`, `PLATFORM_AUDIT_LOG_COLUMNS`; `RECORD_FORMAT = "saas-os-audit-digest/1"`). Both lists include `actor_user_id` and `metadata`. `_selected` reads `metadata` as its stored text, so any rewrite of it, even one that decodes to the same JSON value, changes the window digest (`canonical_row`). The comment above `AUDIT_LOG_COLUMNS` records that a test fails when an audit table gains a column the lists do not name: adding a column is a digest format change. Digests and the chained record go to the worker's log before they are stored in `core.audit_digests`; `python -m saas_os.ops.audit_digest verify` (`saas_os/ops/audit_digest.py`) recomputes each window and reports any difference.

Consequence: **any in-place change to an audit row, including a privacy redaction, is indistinguishable from tampering to the current verifier.**

### 2.3 Where `initiated_by` stores a user id today (PR #196)

- `Initiator.as_metadata()` (`saas_os/core/authority/attribution.py`) writes a user initiator as `{"type": "user", "user_id": "<uuid>"}`.
- **Audit metadata.** `record_in_transaction()` (for a `SystemCaller` only) and `record_system_action_in_transaction()` in `saas_os/core/audit_log/service.py` write that shape under `metadata["initiated_by"]` (`_attribution`). `record()` takes no `initiated_by`. A `UserCaller` row never carries `initiated_by`; the user is in `actor_user_id` (`_caller_actor`), and passing `initiated_by` for one fails with `InvalidActorError`.
- **Outbox payload.** `append_event(..., initiated_by=...)` (`saas_os/core/outbox/service.py`) stores the same shape in `core.outbox_events.payload` under the reserved key `saas_os.initiated_by` (`INITIATED_BY_PAYLOAD_KEY`, `saas_os/core/outbox/models.py`). The dispatcher splits it off before the consumer sees the payload (`_split_initiator`, `saas_os/core/outbox/dispatch.py`) and passes it in memory as `TenantJobContext.initiated_by` (`_job_initiator`, `saas_os/api/outbox_dispatcher.py`). The arq job carries only the event id and claim token (`_run_outbox_event`), so the user id does not travel through Redis.
- **Who writes a user initiator.** No Core code path does today. The only Core caller that passes `initiated_by=` is the dispatcher, forwarding what a producer stored. A user initiator reaches an audit row only when a product (or a test) calls `append_event(initiated_by=Initiator.from_caller(user_caller))` and its consumer records it, or passes `Initiator.user(...)` to an audit function. PR #196 is not merged, so no released consumer depends on the shape yet.

### 2.4 Other user ids in audit records (not exhaustive)

- Columns: `core.audit_log.actor_user_id`; `core.platform_audit_log.actor_user_id`; `core.platform_audit_log.target_id` when the target is a user (`saas_os/core/identity/user_authority.py`; operator enrollment in `saas_os/core/platform_authority/service.py`); `core.audit_log.resource_id` when it names a user (the erasure rows written by `_erase_membership_in_tenant` in `saas_os/core/identity/erasure.py`).
- Metadata keys written by Core: `user_id` (`membership.create` in `saas_os/core/identity/service.py`; platform operator events in `saas_os/core/platform_authority/service.py`), `owner_user_id` (`_owner_metadata`, `saas_os/core/api_keys/service.py`), `proposer_user_id` (`saas_os/control_plane/approvals/service.py`), and the request filters that `list_platform_audit` (`saas_os/core/platform_authority/oversight.py`) records in its own attempt row (`filters.actor_user_id`).
- Products write their own metadata keys. Core cannot tell a user id from any other UUID in them.
- Correction to the previous version of this document: `recipient_user_id` (`saas_os/core/notifications/service.py`) is an outbox payload field and aggregate id, not audit metadata. Notifications write no audit rows.

### 2.5 Retention, erasure, backups, operator commands, RLS

- `saas_os/core/tenancy/retention.py` classifies `core.audit_log`, `core.platform_audit_log` and `core.audit_digests` as `SECURITY_RETAIN` (never deleted by tenant purge). There is no time-based retention for audit rows and no legal-hold concept on this branch.
- `erase_user_identity()` (`saas_os/core/identity/erasure.py`) deletes external identities, memberships and their dependants, and sessions; keeps `core.users.id`; leaves every audit row unchanged; refuses an enrolled platform operator (`EnrolledOperatorErasureError`). Per tenant, in the transaction that then locks the membership row `FOR UPDATE`, it calls `erase_user_initiator()` (`saas_os/core/outbox/initiator_erasure.py`), which locks the matching outbox rows `FOR UPDATE` in id order and rewrites their stored initiator to `"unavailable"`.
- Backups keep `BACKUP_RETENTION_COUNT` full copies (default 7; `saas_os/infra/db/backup/config.py`, `docs/BACKUP-RESTORE.md`).
- Operator commands take a **declared** user id (`--operator`, `--actor`) and build `UserCaller(<that id>)` from it (`saas_os/ops/operator_cli.py`). Nothing authenticates that the person at the terminal is that user; the control is possession of the database credentials. PR #198 records the same finding for its expiry command.
- RLS (`saas_os/infra/db/rls.py`): tenant tables use `tenant_rls_statements()` (`ENABLE`, `FORCE`, policy `tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid`, no separate `WITH CHECK`); platform tables use `tenant_context_exclusion_statements()` (rows visible and writable only while `app.tenant_id` is unset). A tenant-scoped transaction therefore cannot write a platform audit row, and an untenanted one cannot write a tenant row. No `BYPASSRLS` and no `SECURITY DEFINER` (`c4a9e1f07b52` docstring).
- Platform authority does not read tenant data: `platform.audit:read` (`PlatformPermission.AUDIT_READ`, `saas_os/core/platform_authority/permissions.py`) covers the platform audit table. Tenant audit reads (`saas_os.core.audit_log.list` and `get`) perform no Core authorization; the product decides who may call them. Platform reads commit an attempt row before reading and a completion row afterwards (`run_oversight_read`, `saas_os/core/platform_authority/oversight.py`).

## 3. Requirements

- **R1.** The application role stays append-only on both audit tables (ADR-0051). No audit row is rewritten to apply the policy.
- **R2.** A digest recorded before expiry still verifies after expiry, or any difference is explained by a record that is itself tamper-evident. No unexplained `audit_log_changed`.
- **R3.** Expiry follows the record: two years from its `created_at`, with any deviation bounded and stated.
- **R4.** A legal hold suspends expiry (and erasure, per D4) for what it covers. Placing, releasing, expiring and resolving are audited without re-recording the identifier.
- **R5.** After expiry or erasure the identifier cannot be recovered from the live database, including by recomputation from `core.users.id`, which is kept forever.
- **R6.** What happened, when, in which tenant, and whether two records in the same tenant and period were made by the same subject stay readable. Records in different tenants are never linkable through the reference.
- **R7.** Within retention, an authorised and audited lookup can resolve a record to the user.
- **R8.** Rows written before the mechanism are handled explicitly, not ignored.

R5 rules out any deterministic function of the user id (for example a keyed hash under one long-lived key): whoever holds the key can hash every id in `core.users` and re-link every pseudonym. Each reference must come from randomness that is stored only in a row that can be deleted.

## 4. The design

### 4.1 Reference generation and uniqueness

**Source.** `gen_random_uuid()` (built into PostgreSQL 16; a version-4 UUID from the server's cryptographically strong random source). Generating it in the database lets one `INSERT ... ON CONFLICT ... RETURNING` create and return it. Python's `uuid.uuid4()` (`os.urandom`) is equivalent if the insert is built in Python. With 122 random bits a collision is not a practical concern; if one happened, the primary key on `subject_ref` refuses the insert (`unique_violation`, SQLSTATE `23505`), the statement fails and the audit write's transaction rolls back. Two subjects are never merged silently.

**Granularity.** One reference per (tenant, user, period). Options:

| Granularity | Linkage after expiry | Expiry precision (R3) | Link rows |
|---|---|---|---|
| Per record | none: every record unlinkable | exact | one per audit row that names a user |
| Per period (day, week or month) | records of one subject in one tenant and period | the link outlives the earliest record of its period by up to one period | one per active (tenant, user, period) |
| Per tenant lifetime | everything the subject ever did in the tenant | fails: the link must live until two years after the subject's **last** record, so early records stay identified for years | one per (tenant, user) |

Per tenant lifetime fails R3 and is rejected. Per record meets R3 exactly but loses all linkage (R6) and grows the link table with the audit log. Per period is the middle ground; its length is decision D1. Periods are UTC calendar periods computed from the same `now()` that sets the audit row's `created_at`, so a record and its link always agree on the period.

**Expiry of a link.** A link for the period `[period_start, period_end)` expires at `period_end + 2 years`. Every record using it was created before `period_end`, so no record loses its identification before its own two years; the earliest record of the period keeps it up to one period longer (the stated deviation under R3).

**Table** (tenant-owned):

```sql
CREATE TABLE core.audit_subject_links (
    subject_ref   uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES core.tenants (id),
    user_id       uuid        NULL REFERENCES core.users (id),  -- NULL once unlinked
    period_start  timestamptz NOT NULL,
    period_end    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    unlinked_at   timestamptz NULL,
    unlink_reason text        NULL,  -- 'erasure' | 'expiry'
    CONSTRAINT pk_audit_subject_links PRIMARY KEY (subject_ref),
    CONSTRAINT ck_audit_subject_links_period CHECK (period_end > period_start),
    CONSTRAINT ck_audit_subject_links_unlink_pairing CHECK (
        (user_id IS NULL) = (unlinked_at IS NOT NULL)
        AND (unlinked_at IS NULL) = (unlink_reason IS NULL)
    ),
    CONSTRAINT ck_audit_subject_links_unlink_reason CHECK (
        unlink_reason IS NULL OR unlink_reason IN ('erasure', 'expiry')
    )
);
-- One live link per (tenant, user, period); unlinked rows do not count.
CREATE UNIQUE INDEX uq_audit_subject_links_live
    ON core.audit_subject_links (tenant_id, user_id, period_start)
    WHERE user_id IS NOT NULL;
CREATE INDEX ix_audit_subject_links_expiry
    ON core.audit_subject_links (tenant_id, period_end);
```

The `user_id` foreign key is safe because `core.users` rows are never deleted (`docs/MULTI-TENANCY.md` section 6).

**Get-or-create**, inside the audit write's own transaction:

```sql
-- 1. Subject lock, shared (section 4.5).
SELECT pg_advisory_xact_lock_shared(hashtextextended(
    'audit-subject:' || :tenant_id::text || ':' || :user_id::text, 0));
-- 2. Is the subject erased in this tenant? (section 4.4)
SELECT 1 FROM core.audit_subject_erasures
 WHERE tenant_id = :tenant_id AND user_id = :user_id;
-- 3a. Not erased: create or find the live link for the current period.
INSERT INTO core.audit_subject_links (tenant_id, user_id, period_start, period_end)
VALUES (:tenant_id, :user_id,
        date_trunc(:unit, now(), 'UTC'),
        date_trunc(:unit, now(), 'UTC') + :one_unit)
ON CONFLICT (tenant_id, user_id, period_start) WHERE user_id IS NOT NULL
DO NOTHING
RETURNING subject_ref;
-- 3b. Nothing returned: another transaction committed it first; read it.
SELECT subject_ref FROM core.audit_subject_links
 WHERE tenant_id = :tenant_id AND user_id = :user_id
   AND period_start = date_trunc(:unit, now(), 'UTC');
-- 3c. Erased: a fresh row that never holds a user id.
INSERT INTO core.audit_subject_links
       (tenant_id, user_id, period_start, period_end, unlinked_at, unlink_reason)
VALUES (:tenant_id, NULL, date_trunc(:unit, now(), 'UTC'),
        date_trunc(:unit, now(), 'UTC') + :one_unit, now(), 'erasure')
RETURNING subject_ref;
```

Under READ COMMITTED a conflicting insert waits for the other transaction. If that one commits, `DO NOTHING` applies and 3b (a new statement with a new snapshot) sees its row; if it rolls back, this insert proceeds. Section 4.5's locks and the period rule make it impossible for the row to be unlinked or deleted between 3a and 3b; if 3b still finds nothing, the function retries 3a once and then raises `AuditSubjectLinkUnavailableError`, and the transaction rolls back. Under REPEATABLE READ or SERIALIZABLE, 3b cannot see a row committed after the snapshot; the function raises rather than return a wrong value, and the caller retries as for any serialization failure (`40001`). After erasure (3c) every write gets its own unlinkable reference, so an erased subject's later records are not linkable even within a period; such writes are rare (section 4.4).

**Proposed interface** (Core, `saas_os.core.audit_log`; names are proposals):

```text
audit_subject_ref(session, *, tenant_id: UUID, user_id: UUID) -> UUID
    Get-or-create as above, in `session`'s transaction (the
    tenant_session_scope(tenant_id) session of the audited change).
    Raises AuditSubjectLinkUnavailableError.

Recorded shape of a user initiator once the mechanism is released:
    metadata["initiated_by"] = {"type": "user", "subject_ref": "<uuid>"}
```

`Initiator` keeps the user id in memory (the outbox and the consumer need it). Only the audit writer converts it, by calling `audit_subject_ref()` in the same transaction. Core's other metadata keys follow the same rule: `user_id` becomes `user_ref`, `owner_user_id` becomes `owner_user_ref`, `proposer_user_id` becomes `proposer_user_ref`. `Initiator.from_metadata()` accepts both the legacy `user_id` shape and the `subject_ref` shape, so readers work across the cutover. The metadata size bound is unaffected: a reference has the length of the id it replaces.

### 4.2 Tenant scoping and RLS

- `core.audit_subject_links`, `core.audit_subject_erasures` and `core.audit_identity_holds` (section 4.9) are tenant-owned: `tenant_id NOT NULL` and `tenant_rls_statements()`. The policy has no separate `WITH CHECK`, so the `USING` expression also governs inserts and updates: a writer can create or read links only of the tenant its session is scoped to, and the database refuses anything else (`42501`, row-level security violation).
- **Cross-tenant non-linkability.** The same user in two tenants gets two unrelated random references; nothing in either is derived from the user id or from the other tenant. Two tenants' audit exports cannot be joined through references.
- **Platform audit rows** have no tenant (`core.platform_audit_log` has no `tenant_id`; `target_tenant_id` is a reference, not ownership). If they are in scope (D6), their references live in a separate global table, `core.platform_audit_subject_links` (the same columns without `tenant_id`, unique on `(user_id, period_start) WHERE user_id IS NOT NULL`), under `tenant_context_exclusion_statements()`: readable and writable only in an untenanted transaction. A platform reference and a tenant reference for the same user are independent random values and are not linkable to each other.
- **Retention class.** All four new tables are `SECURITY_RETAIN` (`saas_os/core/tenancy/retention.py`). Tenant purge does not delete them; like the audit rows they serve, they leave only through the expiry procedure. Their foreign keys to `core.tenants` are safe because a purged tenant keeps its tombstone row.
- **Owner and RLS.** `FORCE ROW LEVEL SECURITY` binds the table owner too (only a superuser or a `BYPASSRLS` role escapes it, and the deployment roles must be neither). The migrations-role commands of sections 4.3 and 4.9 therefore work tenant by tenant, setting `app.tenant_id` for each tenant's transaction exactly as `tenant_session_scope()` does.

**Role grants.** Each migration narrows the default `SELECT, INSERT, UPDATE, DELETE` that migration `e99c76057719`'s default privileges give the application role on every new table:

| Table | Application role | Migrations role (owner) |
|---|---|---|
| `core.audit_subject_links` | `SELECT`, `INSERT`, `UPDATE (user_id, unlinked_at, unlink_reason)`; no `DELETE` | all; used by the expiry procedure |
| `core.audit_subject_erasures` | `SELECT`, `INSERT`; no `UPDATE`, no `DELETE` | all; used by the expiry procedure |
| `core.audit_identity_holds` | `SELECT` only | all; used by the hold command |
| `core.platform_audit_subject_links` (if D6) | as `core.audit_subject_links` | as above |

A `BEFORE UPDATE` trigger on each link table (not `SECURITY DEFINER`, fixed `search_path`; the pattern of PR #198's `permission_grant_ledger_holds_release_once`) allows exactly one transition, live to unlinked: `OLD.user_id IS NOT NULL AND NEW.user_id IS NULL`, with `subject_ref`, `tenant_id`, `period_start`, `period_end` and `created_at` unchanged. Anything else, for every role including the owner, raises `check_violation` (`23514`). A link can never be re-pointed at another user, and an unlinked reference can never be linked again.

### 4.3 Authorised lookup

Within retention a reference resolves to a user id only through two audited functions:

```text
resolve_audit_subject(*, tenant_id: UUID, subject_ref: UUID,
                      operator: UUID, reason: str) -> UUID
    The user id, or AuditSubjectNotResolvableError when the reference is
    unknown, unlinked (erased or expired) or belongs to another tenant: one
    error for all three, so the call reveals nothing about which.

list_audit_subject_refs(*, tenant_id: UUID, user_id: UUID,
                        operator: UUID, reason: str) -> tuple[UUID, ...]
    The live references of one user in one tenant: for a data subject access
    request, and to scope a legal hold to one subject.
```

Order, mirroring `run_oversight_read`: (1) an attempt row is committed to `core.platform_audit_log` in an untenanted transaction; (2) in one transaction scoped to `tenant_id`, the link is read and a tenant audit row `audit_subject.resolved` (or `audit_subject.listed`) is written with `record_system_action_in_transaction()`; (3) a completion row is written to the platform audit log. If (1) fails, nothing is read. The rows record the declared operator id, the tenant, the `subject_ref` (for the reverse lookup only the number of references returned), the reason reference and the outcome. **No row records the resolved user id**, and the reverse lookup's input user id is not recorded either: the reason reference must point to the case file that already holds the identity. The result goes to the command's standard output only, never to a log.

Who may call these functions is decision D3. On this branch there is no tenant permission for audit reads, and `platform.audit:read` covers platform evidence, not tenant data.

### 4.4 User erasure

Today `erase_user_identity()` leaves audit rows alone, and in each tenant `_erase_membership_in_tenant` rewrites the user's outbox initiators in the transaction that locks the membership. The proposal adds, in that same transaction, after the existing outbox and membership locks:

1. `pg_advisory_xact_lock_shared(H(tenant))`: holds cannot change while erasure decides.
2. `pg_advisory_xact_lock(S(tenant, user))`, exclusive: waits for in-flight writers of this subject, then blocks new ones until commit.
3. `INSERT INTO core.audit_subject_erasures (tenant_id, user_id, erased_at) ... ON CONFLICT DO NOTHING`. From then on, get-or-create issues references with no identity behind them (section 4.1, step 3c). This also covers a consumer attempt that read the user from an outbox event before the erasure, the case `erase_user_initiator`'s docstring says it cannot reach.
4. Lock the subject's live links `FOR UPDATE ORDER BY subject_ref` and unlink each one not covered by an active hold: `SET user_id = NULL, unlinked_at = now(), unlink_reason = 'erasure'`.
5. Record the counts (links unlinked, links kept under hold) in the existing `identity.erasure_membership_removed` row or, when no membership was removed, in a row of its own, as `identity.erasure_outbox_initiators_erased` does today. Never the reference values.

A link kept under a hold stays live. When the hold is released, the next expiry run unlinks it, because the erasure marker is still there (section 4.9). Whether a hold overrides erasure at all is decision D4.

`core.audit_subject_erasures` holds the user id; it must, to recognise the subject. It is itself identifying, like the erasure audit rows that already carry `resource_id = str(user_id)`. The expiry procedure deletes a marker two years after `erased_at`, but only once no live link of that subject remains in the tenant (a hold may have kept one).

### 4.5 Atomicity and concurrent operations

**Same transaction (ADR-0031).** `audit_subject_ref()` runs in the session of the audit write, which is the session of the audited change. The link insert, the audit insert and the change commit together or not at all. A transaction that obtains a reference and then rolls back for any reason leaves nothing behind, because its link insert rolls back too.

**Locks, in a fixed order.** Two advisory transaction locks; they need no table privileges and are released at commit or rollback:

- `H(tenant)` = `hashtextextended('audit-holds:' || tenant_id::text, 0)`
- `S(tenant, user)` = `hashtextextended('audit-subject:' || tenant_id::text || ':' || user_id::text, 0)`

| Operation | Lock order |
|---|---|
| Audit writer | its own business row locks; `S` shared; link insert or select; audit row |
| Erasure (per tenant) | outbox rows `FOR UPDATE` (existing); membership `FOR UPDATE` (existing); `H` shared; `S` exclusive; marker; link rows `FOR UPDATE` by `subject_ref`; audit row |
| Hold place or release (per tenant) | `H` exclusive; hold row; tenant audit row |
| Expiry (per tenant) | `H` shared; link and marker rows `FOR UPDATE` by key; delete or unlink; tenant audit row |

A writer takes `S` after its business locks and takes nothing after it; erasure takes `S` after the membership lock. Through these locks the two cannot wait on each other in a cycle. A product writer that locks further business rows after its audit write could still deadlock with an erasure; PostgreSQL detects it (`40P01`) and aborts one transaction, and both operations are safe to retry (erasure is idempotent). A hash collision between two subjects only makes unrelated operations wait for each other.

**Races.**

- *Two writers, same subject and period:* the unique index with `ON CONFLICT DO NOTHING` and the re-select gives both the same reference.
- *Writer and erasure:* `S` serializes them. A writer that commits first has its link unlinked by the erasure; a writer that comes after sees the marker and gets a reference with no identity.
- *Writer and expiry:* disjoint by construction. A writer touches only the period containing its own `now()`; expiry touches only links with `period_end + 2 years + 1 day <= now()` (one day of margin against clock and transaction-duration effects).
- *Hold and expiry, hold and erasure:* `H` makes a hold placement or release wait for a running expiry or erasure of the tenant, and the reverse. Expiry and erasure read the active holds after taking `H`.
- *Two expiry runs:* the second waits on the row locks and then finds the rows gone. Counts differ; the outcome does not.

**Idempotency.** Get-or-create returns the existing reference. A repeated erasure finds the marker and no live links. A repeated expiry run finds nothing eligible. A hold is unique per (tenant, matter reference, subject) while active.

**Errors (proposed).**

| Error | When | Effect |
|---|---|---|
| `AuditSubjectLinkUnavailableError` | get-or-create cannot return a reference after one retry | audit write fails; the audited change rolls back |
| `AuditSubjectNotResolvableError` | lookup of an unknown, unlinked or other-tenant reference | nothing returned; the platform completion row records `failure` |
| `AuditIdentityHoldError` | a hold with an invalid scope, or release of a released hold | nothing written |
| `AuditIdentityExpiryRefusedError` | apply whose confirmed count or digest (rows or active holds) no longer matches | nothing deleted |
| SQLSTATE `23505`, `23514`, `42501`, `40P01`, `40001` | duplicate reference; illegal link or hold update (trigger); RLS refusal; deadlock; serialization failure | the statement fails and the transaction rolls back |

### 4.6 Existing audit rows and rollout

**Rows already written** hold raw ids in four places: the `actor_user_id` columns; `resource_id` and `target_id` values naming a user; Core metadata keys (`initiated_by.user_id`, `user_id`, `owner_user_id`, `proposer_user_id`); and product metadata keys. Options:

1. **Leave and declare.** Rows stay unchanged and are a documented exception, with a report (counts per tenant and month, no ids) so the backlog and each row's would-be expiry date are known. Digests untouched. R8 is met only in the sense of "handled explicitly": identification in these rows does not expire.
2. **Rewrite under a tamper-evident redaction record.** A tier-0 command with the migrations role replaces each raw id with a reference (creating link rows dated to the record's period) or with a marker, writes a redaction ledger, and sends a digest-chain continuation record to the external log listing, per window and tenant, the old and new digests and the changed row ids. The verifier learns to accept a window change only when such a record explains it. Two constraints make this hard. The verifier cannot prove that only identifiers changed unless digests commit to identifier fields separately (digest format version 2). And publishing an old per-row hash is unsafe: with `core.users.id` kept, anyone can recompute the old row for every user id and recover the identifier (R5). It is a controlled mutation of evidence and needs an ADR amending ADR-0051 and ADR-0053.
3. **Dual-write cutover.** Write both the raw id and the reference for a while. This does nothing for old rows and creates more raw rows. Rejected.

**The `actor_user_id` columns.** The CHECK constraints require `actor_user_id IS NOT NULL` for `actor_type = 'user'` on both tables, and the column is digested. Moving a user actor to a reference needs a new column (for example `actor_subject_ref`), a relaxed CHECK, digest format version 2 (the column lists are fixed per format) and changes to every reader, including `saas_os.core.audit_log.list(actor_user_id=...)` and `list_platform_audit(actor_user_id=...)`. The owner's policy text names `initiated_by` and user ids in metadata; whether the columns follow is part of D5.

**Rollout order** (metadata references):

1. Migration: create the link, erasure-marker and hold tables (additive, empty, no backfill). Downgrade refuses while any row exists in them (the PR #198 pattern): dropping the link table would silently destroy the only way to resolve references already written.
2. Release N: readers accept both shapes (`Initiator.from_metadata()`, the lookup command); writers unchanged.
3. Release N+1: writers produce references. During a rolling deploy, old instances keep writing raw ids until they are replaced; the boundary per tenant is the `created_at` of its first link row, which the backlog report uses.
4. Products: Core offers `audit_subject_ref()` and documents that product audit metadata must carry references, not user ids. Core cannot detect a product's raw user id reliably (any UUID could be anything), so it does not refuse one; this stays the product's obligation under the same policy.

### 4.7 Failure and recovery

- **Link insert fails** (constraint, RLS, connection): the audit write raises and the audited change rolls back with it. No change commits without its evidence (ADR-0031). There is no fallback to writing the raw id.
- **Expiry run crashes mid-run.** Each tenant is one transaction: a crash rolls back the tenant in progress; tenants already committed are done, each with its tenant audit row. The platform start row (committed before the first tenant) lists the planned tenants and counts; a start row without a finish row identifies the interrupted run. A rerun computes the eligible set again and continues. No tenant is ever half done.
- **Restore from backup.** A restored database contains link rows that were unlinked or deleted after the backup, and lacks markers, holds and erasures made after it. Before the application serves traffic, in order: (1) re-place the holds made since the backup, from the platform audit evidence and the hold command's log lines (section 4.9); (2) re-run the erasures made since the backup from their case records (already necessary for `erase_user_identity()` itself); (3) run the expiry procedure, which is date-based and idempotent and so unlinks everything that had expired. Until these steps finish, identification removed since the backup is live again.
- **Backups.** Every backup keeps the deleted identification until it rotates out (`BACKUP_RETENTION_COUNT` runs, default 7). Removal is immediate in the live database and complete in backups only after rotation; the privacy notice should say so.
- **A hold lost by a restore** is the dangerous case: expiry could remove what a court needs. The expiry command therefore refuses `--apply` unless the operator confirms the set of active holds by count and digest, which the runbook compares with the externally logged hold history.

### 4.8 Audit digest integrity (ADR-0053)

- **References keep digests valid.** The reference is written into `metadata` at insert time and never changes. Unlinking or deleting a link row changes no audit row, so every window digest recorded before expiry recomputes identically after it. No digest format change is needed for metadata references.
- **The link table is not digested, and should not join the ADR-0053 windows.** Its rows change by design (unlinking, deletion); digesting them would turn every lawful expiry into a verifier finding.
- **Its own evidence (D8).** Deleting identification is security-relevant: a premature deletion destroys forensic value irreversibly. Proposed: each expiry run and each erasure writes audit rows with counts and a SHA-256 over the sorted affected `subject_ref` values. Those audit rows are themselves digested, so the evidence of each deletion is anchored externally. Unlinked references identify no one, so the dry-run report may list them.
- **Legacy rows.** Section 4.6 option 1 changes no row and keeps digests valid. Option 2 changes rows and is acceptable only with the re-anchoring record and digest format version 2 described there.

### 4.9 Retention, legal holds and the expiry procedure

**Retention.** A link expires at `period_end + 2 years`. An erasure marker expires at `erased_at + 2 years`, once no live link of its subject remains. Audit rows themselves are never deleted (`SECURITY_RETAIN` unchanged).

**Holds** reuse the shape of PR #198's `core.permission_grant_ledger_holds` without depending on it (a separate table and trigger function), but are tenant-scoped, because erasure and expiry must read them inside a tenant transaction:

```sql
CREATE TABLE core.audit_identity_holds (
    id                             uuid         NOT NULL,
    tenant_id                      uuid         NOT NULL REFERENCES core.tenants (id),
    reference                      varchar(100) NOT NULL,  -- legal matter id, never a name
    from_period_start              timestamptz  NULL,      -- NULL: open-ended
    to_period_end                  timestamptz  NULL,      -- NULL: open-ended
    subject_ref                    uuid         NULL,      -- NULL: every subject
    placed_at                      timestamptz  NOT NULL DEFAULT now(),
    placed_by_platform_audit_id    uuid         NOT NULL,
    released_at                    timestamptz  NULL,
    released_by_platform_audit_id  uuid         NULL,
    CONSTRAINT pk_audit_identity_holds PRIMARY KEY (id),
    CONSTRAINT ck_audit_identity_holds_reference
        CHECK (reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$'),
    CONSTRAINT ck_audit_identity_holds_release_pairing
        CHECK ((released_at IS NULL) = (released_by_platform_audit_id IS NULL)),
    CONSTRAINT ck_audit_identity_holds_release_order
        CHECK (released_at IS NULL OR released_at >= placed_at)
);
CREATE UNIQUE INDEX uq_audit_identity_holds_active
    ON core.audit_identity_holds (tenant_id, reference, subject_ref)
    NULLS NOT DISTINCT WHERE released_at IS NULL;
```

With tenant RLS, and a one-way release trigger as in PR #198 (`check_violation` on any change to a released hold, for every role). Because a tenant transaction cannot write a platform audit row (section 2.5), placing a hold follows the lookup's order: the platform attempt row is committed first and its id becomes `placed_by_platform_audit_id`; the hold and a tenant audit row are written in one tenant transaction; a platform completion row follows. Release is the same. The command also writes one structured log line per hold change (hold id, tenant, period range, matter reference, never a user id) so holds can be reconstructed after a restore.

A hold scoped to one person names that person's references (found with `list_audit_subject_refs`), never the user id. A hold that must also cover a person's future periods has to be tenant-wide, which retains more than strictly needed; that is the price of never storing a user id in a hold. A link is held when an active hold of its tenant has a matching or NULL `subject_ref` and a period range that overlaps the link's period.

**Expiry procedure.** A platform start row is committed first. Then, per tenant, in one transaction scoped to that tenant: take `H` shared; read the active holds; lock the eligible rows in key order (links with `period_end + interval '2 years' + interval '1 day' <= now()`, live or unlinked, not held; live links of an erased subject that are no longer held; markers past their expiry with no live link left); delete expired links, unlink held-then-released links of erased subjects, delete expired markers; write the tenant audit row with counts and the digest of the affected references. A platform finish row closes the run. Dry run by default; `--apply` needs `--confirm-rows`, `--confirm-digest` and the active-hold confirmation from a prior report, as PR #198's `saas_os/ops/permission_grant_ledger_expiry.py` does (not on this branch). Runner and control are decision D7.

Whatever runner is chosen, the operator id it records is **declared, not authenticated** (section 2.5). The record shows who the person at the terminal said they were; the real control is possession of the database credentials the command needs. Neither the expiry procedure, the hold command nor the lookup can claim authenticated approval or enforced separation of duties until operator commands authenticate their operator.

**"Where legally permissible."** Core cannot judge legality. The default is that expiry proceeds; a hold encodes "not permissible yet"; the reason reference on each run and hold points to the decision record outside the database.

## 5. Alternatives compared

- **(a) Random references and a deletable link table**: this design (section 4).
- **(b) Keyed HMAC pseudonyms.** The row stores `HMAC(K_period, tenant_id || user_id)`. Deterministic, so there is no link table: lookup recomputes the HMAC for every user id of the tenant. Expiry deletes the period key. Cheap, but one period key serves every subject of the period: erasing one person means deleting the key for everyone (losing forensics for all) or keeping it (the erasure fails). A hold on one person keeps the whole period's key. While a key exists, whoever obtains it re-identifies every pseudonym of the period by hashing all user ids, a small and known set.
- **(c) Per-subject encryption keys (crypto-shredding).** The row stores the user id encrypted under a key per (tenant, user, period), kept in a key table and wrapped by a deployment key (ADR-0019's `EncryptionService`). Expiry deletes the key. Once the row also carries a key id (which is (a)'s reference), the guarantees equal (a), at the cost of authenticated encryption in every audit write, per-subject key management, rotation of the wrapping key, and a new failure mode: a lost wrapping key makes every unexpired identifier unreadable. Its one advantage, that a stolen audit row reveals nothing, is already true of a random reference.
- **(d) In-place redaction of audit rows with a redaction ledger.** At expiry a controlled command rewrites identifiers in the rows, records a redaction ledger and re-anchors the digest chain (section 4.6, option 2). It is the only option that also covers rows already written. It needs a role that can update audit rows, digest format version 2, verifier changes and an ADR amending ADR-0051 and ADR-0053; a partial run leaves verifier findings until it completes; a mistaken rewrite is irreversible; and after redaction records are not linkable unless the marker carries a pseudonym, which reintroduces (a).
- **(e) Keep raw ids and rely on erasing `core.users` identity data.** Today's behaviour plus `erase_user_identity()`. `core.users.id` is kept forever and is the key under which products and logs know the user, so the id remains a stable, re-identifiable handle across audit rows, logs, backups and product databases, and nothing expires. This contradicts the owner's classification of a user id in an audit record as identifying.

| | (a) refs + link table | (b) HMAC per period | (c) crypto-shredding | (d) in-place redaction | (e) keep raw ids |
|---|---|---|---|---|---|
| R1 append-only | yes | yes | yes | **no**: needs an updating role | yes |
| R2 digests verify | yes | yes | yes | only with digest v2 and re-anchoring | yes |
| R3 per-record expiry | within one period | within one period | within one period | exact | **no** |
| R4 holds, audited | yes, per subject or tenant | coarse: whole period key | yes | yes, per record | n/a |
| R5 unrecoverable | yes after unlinking (backups until rotation) | only after the shared key is deleted; one person cannot be erased alone | yes after key deletion (same backup caveat) | yes (same backup caveat) | **no** |
| R6 history, bounded linkage | yes | yes | yes, with a key id | identifier gone, no linkage | unbounded linkage |
| R7 authorised lookup | yes | yes, by enumeration | yes | before redaction only | no control: anyone who reads the row |
| R8 legacy rows | needs (d) or a declared exception | same | same | **yes** | n/a |
| Cost | three tables (four with D6), lock protocol, lookup | key table | key table, encryption, key rotation | updating role, digest v2, verifier, ledger | none |

**Why (a).** It is the only option that meets R1 to R7 together while allowing one person to be erased without affecting anyone else, and it needs no change to the audit tables, their grants or the digest format. The audit row is fixed at write time; everything that changes later lives in a separate table whose changes are themselves audited. (b) fails per-person erasure and leaves re-identification open to anyone holding a key. (c) gives the guarantees of (a) with strictly more machinery and a new key-loss failure. (d) mutates the evidence the system was built to keep immutable, and is worth its cost only for rows already written. (e) does not implement the policy.

## 6. Decisions D1–D8

Each decision lists options, trade-offs and a recommendation. The recommendations are proposals for the owner, not decisions.

**D1. Reference granularity and period.**
Options: per record; per UTC day; per UTC week; per UTC calendar month; per tenant lifetime.
Trade-offs: shorter periods track the two-year rule more exactly (identification outlives a record by at most one period) but keep less linkage after expiry and create more link rows; per record is exact with no linkage; per tenant lifetime fails R3.
*Recommendation:* UTC calendar month, expiry at month end plus two years. Identification outlives a record by at most one month; say so in the privacy notice. Choose UTC day instead if "two years" must hold within a day.

**D2. How `initiated_by` is stored before this design is released.**
Today (section 2.3) a user initiator is stored as `{"type": "user", "user_id": ...}` in `core.outbox_events.payload["saas_os.initiated_by"]` and, when an audit function receives it, in `metadata["initiated_by"]`. No Core path creates one; products can, through the public API, once PR #196 is released.
Options: (i) keep raw ids until the mechanism ships: no delay, but every such audit row becomes a legacy row (D5) and products start depending on the `user_id` shape; (ii) store a reference from day one: correct shape immediately, but pulls the link table and its migration into or ahead of PR #196, beyond step 1's scope; (iii) gate: until the mechanism ships, the audit writers refuse a user `Initiator` (`InvalidActorError`), while the outbox keeps storing it (operational data, already rewritten on erasure) and consumers still receive it in memory; a consumer records such an action with `initiated_by` unavailable, and its `correlation.outbox_event_id` leads an investigator to the event's stored initiator.
*Recommendation:* (iii). No audit row with a raw `initiated_by` user id is ever written, so there are no legacy rows and no public shape to retract. The cost is a temporary attribution gap in audit rows for user-initiated asynchronous actions, which no Core path produces today. (i) is acceptable only if D5 accepts declared legacy rows.

**D3. Lookup authority.**
Options: (i) a tenant capability through `saas_os.core.rbac.can()` (for example resource `audit_subject`, action `resolve`, registered like `api_key`/`create` in `saas_os/core/api_keys/service.py`): fits tenant ownership of the data, but is a new tenant permission; (ii) reuse `platform.audit:read`: no new permission, but extends platform authority from platform evidence into tenant data, which ADR-0045 keeps apart; (iii) a dedicated platform permission (for example `platform.audit_identity:resolve`): explicit and least-privilege, but a new permission, which needs the owner's approval; (iv) an operator command only, with no permission, gated by database credentials and recording a declared operator id.
*Recommendation:* (iv) for the first release. Forensic resolution is rare, no permission is added, and every call is audited without the identifier. The limitation is explicit: the operator id is declared, not authenticated. Add (i) later as its own decision if tenants need self-service resolution. Do not choose (ii).

**D4. Erasure versus legal hold.**
Options: (i) the hold wins: erasure unlinks everything not held, keeps held links, and the first expiry run after release unlinks them; (ii) erasure wins: erasure unlinks everything, holds notwithstanding; (iii) erasure is refused while any hold covers the subject.
Trade-offs: (i) honours an obligation to preserve evidence and still completes the erasure automatically later; (ii) can destroy evidence a court ordered preserved; (iii) blocks the whole erasure (sessions, memberships, identity links) because of an audit hold, which is out of proportion.
*Recommendation:* (i). Report the number of held links (never the references) in the erasure result and audit row.

**D5. Rows written before the mechanism, and the `actor_user_id` columns.**
Widened from "legacy rows" because the code shows that the columns cannot move to references without a schema and digest change (section 4.6): the CHECK constraints require `actor_user_id` for user actors, and `AUDIT_LOG_COLUMNS` fixes the digested columns.
Options: (i) leave legacy rows and the columns unchanged, declared as an exception with a backlog report; (ii) a one-time controlled redaction with re-anchoring and digest format version 2 (alternative (d)); (iii) (i) now, and a later phase that adds reference columns for user actors and redacts legacy rows under (ii), designed together.
*Recommendation:* (iii). Metadata references need no audit-table change and can ship first; the column phase and the legacy redaction share digest version 2 and one ADR amendment, so they should be one decision.

**D6. Platform audit (untenanted) scope.**
Options: (i) out of scope: operators' identification is kept for accountability under a separate retention; (ii) in scope with `core.platform_audit_subject_links` (section 4.2) for every user id, columns per D5; (iii) in scope only for user ids naming someone other than the acting operator (users who are the target of an operator action).
Trade-offs: an operator cannot be erased while enrolled (`EnrolledOperatorErasureError`), and holding operators accountable is the purpose of the platform audit log; the targets of operator actions are ordinary users the policy protects.
*Recommendation:* (iii), with the retention of the operator as actor stated as a separate policy for the owner to confirm. Most target ids are in the `target_id` column, so most of (iii) falls under D5's column phase.

**D7. Expiry procedure runner and its control.**
Options: (i) a scheduled worker job under the application role, which then needs `DELETE` on the link tables and runs without a person; (ii) an operator command with the migrations role, dry run and confirmed apply (PR #198's pattern), run on a schedule from the runbook; (iii) (ii) plus a scheduled worker job that only reports what is eligible or overdue.
Trade-offs: (i) is automatic but gives the application's credentials the power to remove identification wholesale, and a defect deletes evidence unattended; (ii) keeps deletion out of the application's reach but depends on people running it on time. Neither enforces separation of duties: operator ids are declared, not authenticated, so one person can place a hold, release it and run expiry.
*Recommendation:* (iii). The report job makes overdue expiry visible; deletion stays a person-run, credential-gated, audited command. Record the separation-of-duties limitation in the runbook and revisit it when operator commands authenticate.

**D8. Evidence for link deletion; a digest of the link table.**
Options: (i) audit rows with counts only; (ii) audit rows with counts and a SHA-256 over the sorted affected references, anchored through ADR-0053 because audit rows are digested; (iii) (ii) plus a separate digest chain over the link table itself.
Trade-offs: (i) cannot show which links a run removed; (iii) conflicts with the link table's purpose (its rows change by design) and needs a second verifier.
*Recommendation:* (ii). No digest of the link table itself.

## 7. Not decided here

- Whether published outbox events (kept until tenant purge, carrying `saas_os.initiated_by`) and application logs follow the same two-year rule. The policy names audit records only; outbox initiators are already rewritten on erasure.
- Who attests that removal is legally permissible for a tenant, and whether a product may extend retention for its tenants. Both can be expressed as holds once decided.
- Whether Core should refuse product audit metadata that looks like a raw user id (section 4.6: not reliably detectable).
