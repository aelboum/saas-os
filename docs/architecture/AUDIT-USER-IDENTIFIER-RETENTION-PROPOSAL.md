# Retention of user identifiers in completed audit records

**Status: Proposal; not implemented; requires separate approval.** Nothing in this document is built. It changes no schema, no runtime behaviour, no grant and no public contract. Date: 2026-11-02.

Related: ADR-0031 (same-transaction audit), ADR-0045 (platform audit), ADR-0051 (audit table immutability), ADR-0053 (audit digests in external logs), ADR-0019 (field encryption), ADR 0061 (system actor attribution, PR #196), `docs/MULTI-TENANCY.md` section 6 (identity erasure), `docs/BACKUP-RESTORE.md`.

## 1. The approved policy (owner, 2026-11-02)

For completed audit records that contain an identifiable user initiator (the `initiated_by` user id, and analogous user ids in audit metadata):

1. Default retention is two years from the audit record's creation.
2. A legal hold can suspend expiry.
3. After expiry, a controlled privacy process removes or anonymises direct user identification where that is legally permissible.
4. The non-identifying audit history is preserved where possible.
5. Append-only audit records are never mutated silently.
6. There is no uncontrolled deletion.

The policy is approved. The mechanism below is a proposal.

## 2. How audit integrity works today (verified on `e148526`)

**Append-only for the application.** Migration `2e7cb8c64903` revokes `UPDATE` and `DELETE` on `core.audit_log` from the application role; `c4a9e1f07b52` does the same for `core.platform_audit_log`. `TRUNCATE` was never granted. `tests/infra/db/test_audit_tables_append_only_integration.py` asserts the role holds exactly `SELECT` and `INSERT` and that `UPDATE`, `DELETE` and `TRUNCATE` are refused. There is deliberately no trigger (ADR-0051 decision 2): the table owner (the migrations role) and superusers can still change rows, and a trigger would not bind them.

**Tamper evidence (ADR-0053).** The worker job `_audit_digest_cycle` digests settled UTC windows. Each row is serialized canonically from a fixed column list (`AUDIT_LOG_COLUMNS`, `PLATFORM_AUDIT_LOG_COLUMNS` in `saas_os/core/audit_digest/service.py`, format `saas-os-audit-digest/1`). The list includes `actor_user_id` and `metadata`, and `metadata` is hashed as the column's **stored text** (the `json` type keeps its input text), so any rewrite of `initiated_by`, even one that decodes to the same value, changes the window digest. Per-tenant SHA-256 values and the chained record are written to the worker's log before they are stored in `core.audit_digests`. The log line is the evidence; it carries window times, row counts, digests and tenant ids, never audit content or user ids. `python -m saas_os.ops.audit_digest verify` recomputes each window from the database and reports `audit_log_changed` (naming the tenant) or `platform_audit_log_changed` for any change.

Consequence: **any in-place change to an audit row, including a privacy redaction, is indistinguishable from tampering to the current verifier.** The digest cannot be "updated" either: the evidence is in an external store the database holders cannot change, by design.

**Retention registry.** `saas_os/core/tenancy/retention.py` classifies `core.audit_log`, `core.platform_audit_log` and `core.audit_digests` as `SECURITY_RETAIN`: never deleted by tenant purge. There is no time-based retention for audit rows and no legal-hold concept anywhere in SaaS OS.

**Existing erasure and redaction paths.**
- `erase_user_identity()` (`saas_os/core/identity/erasure.py`) deletes external identities, memberships and their dependants, and sessions. It keeps `core.users.id` (many `NOT NULL` foreign keys) and leaves every audit row unchanged. `docs/MULTI-TENANCY.md` section 6 recorded that a retained `actor_user_id` is an opaque id; the 2026-11-02 policy now treats a user id in a completed audit record as identifying for retention purposes.
- `erase_user_initiator()` (`saas_os/core/outbox/initiator_erasure.py`, PR #196) rewrites an erased user's stored outbox initiator to `"unavailable"`. Outbox rows are operational, not audit evidence, and are not digested.
- `saas-os-operator redact-webhook-errors` redacts stored webhook error text (operational data, not audit).
- Backups (`docs/BACKUP-RESTORE.md`) keep full copies for `BACKUP_RETENTION_COUNT` runs (default 7).

**Where user ids sit in audit records today** (not exhaustive; products add their own metadata):
- columns: `core.audit_log.actor_user_id` (foreign key to `core.users`), `core.platform_audit_log.actor_user_id`;
- `resource_id` strings naming a user (for example the erasure rows in `saas_os/core/identity/erasure.py`);
- metadata: `initiated_by.user_id` (PR #196), `owner_user_id` (API keys), `recipient_user_id` (notifications), `proposer_user_id` (approvals), `user_id` (identity and platform-authority events), and whatever products write under their own keys.

## 3. Requirements a mechanism must meet

R1. The application role stays append-only on both audit tables (ADR-0051).
R2. A digest recorded before expiry still verifies after expiry, or any difference is explained by a record that is itself tamper-evident; no unexplained `audit_log_changed`.
R3. Expiry is per record: two years from that record's `created_at`.
R4. A legal hold suspends expiry for the records it covers, and holding, releasing and expiring are themselves audited without re-recording the identifier.
R5. After expiry the identifier cannot be recovered from the database, including by recomputation from `core.users.id`, which is kept forever.
R6. What happened, when, in which tenant, and whether two records were initiated by the same subject within a bounded period stay readable.
R7. Within retention, forensics can still resolve a record to the user.
R8. Rows written before the mechanism are handled explicitly, not ignored.

R5 rules out a deterministic keyed hash (HMAC) under one installation-wide key as the only protection: whoever holds the key can hash every id in `core.users` and re-link every pseudonym. Every option below that pseudonymises therefore needs per-subject randomness that is deleted at expiry.

## 4. Alternatives

### (a) Pseudonymous identifiers at write time, with a deletable mapping

The audit row stores an opaque subject reference instead of the user id, for example `initiated_by: {"type": "user", "subject_ref": "<random uuid>"}`. A separate tenant-scoped table maps `subject_ref -> user_id`. To meet R3 with bounded linkage, the reference is minted per (tenant, user, period), for example per calendar month of `created_at`; the mapping row expires two years after its period ends.

- **Digests.** Unaffected. The audit row never changes; only the mapping row is deleted, and the mapping table is not digested.
- **Legal hold.** A hold marks the mapping rows in its scope (tenant, user, period range) as not deletable. Simple and exact at period granularity.
- **Forensics.** Within retention, a join resolves the user. After expiry, rows in one period stay linkable to each other ("the same subject did these things in March") but not to a person (R6). Products reading `initiated_by.user_id` must resolve through an API instead; that is a public contract change.
- **Existing rows.** Not covered. Rows already holding plain user ids need option (c) once, or an accepted exception.
- **Complexity.** Medium: one table with RLS, a minting step inside the audit write (same transaction, fail closed), a scheduled expiry job, a resolve function with its own authorization.
- **Failure modes.** A mapping row deleted early (bug, wrong hold scope) loses identification irreversibly; a restore from backup brings deleted mapping rows back until the expiry job runs again (idempotent by date; early erasures need a tombstone list of deleted refs to re-apply). Expiry granularity is the period, not the exact record (a record created on the 1st of a month keeps its link up to a month longer than two years unless periods are shorter).
- **Legal permissibility.** Expiry is the default; a hold encodes "not permissible yet". Core cannot judge legality; the process records who decided.
- **Schema and runtime.** One additive table; a change to how `Initiator.as_metadata()` and other writers store user ids; `actor_user_id` columns stay as they are unless the scope decision (section 6, D1) extends to them, in which case a new column and digest format version 2 are needed.

### (b) Crypto-shredding

The audit row stores the user id encrypted under a per-subject data key (per tenant, user and period), held in a key table and wrapped by a deployment key (ADR-0019's `EncryptionService`/`KeyProvider`). Expiry deletes the data key.

- **Digests.** Unaffected: the ciphertext in the row never changes.
- **Legal hold.** As (a): held keys are not deleted.
- **Forensics.** Within retention, decrypt; after, the ciphertext is opaque. Linkage within a period survives only if the row also carries a key id, which is in effect (a)'s reference.
- **Existing rows.** Not covered; as (a).
- **Complexity.** Higher than (a): per-subject key management, AEAD in the audit write, key rotation of the wrapping key, and decryption needs a key on every read path. ADR-0019's keys are deployment-level today; per-subject keys are new.
- **Failure modes.** As (a), plus a lost wrapping key makes every unexpired identifier unreadable; ciphertext in backups is only shredded once every backup holding the key has rotated out (the same is true of (a)'s mapping).
- **Verdict.** Same guarantees as (a) for more machinery. Its one advantage, that a stolen audit row reveals nothing, is small here because a user id is already random and the key table sits in the same database.

### (c) Controlled redaction with a redaction record and digest re-anchoring

An audited operator process rewrites identifiers in place (for example `initiated_by.user_id` replaced by a marker) once a record expires. It writes a redaction audit entry and a digest-chain continuation that lists, per window and tenant, the old and new digests and the ids of the rows changed. The verifier is extended to accept a window change only when a redaction record explains it.

- **Digests.** The hardest part. The re-anchoring record must itself go to the external store. The verifier can then accept a new window digest, but it cannot prove that only identifiers changed unless digests commit to the non-identifying fields separately (a digest format version 2 that hashes identifier fields as separate salted commitments). Publishing an old per-row hash is not safe: with `core.users.id` kept, the old row can be recomputed for every user id to recover the identifier (breaks R5).
- **Legal hold.** The process skips held rows.
- **Forensics.** Before redaction, unchanged. After, the identifier is gone and rows are no longer linkable unless the marker carries a pseudonym, which reintroduces (a).
- **Existing rows.** Covers them: this is the only option that handles rows already written with plain ids.
- **Complexity.** High: a role or function with `UPDATE` on audit tables (weakens R1 unless it is the migrations role, run as a tier-0 operator command), a new digest format, verifier changes, and a redaction ledger.
- **Failure modes.** A partial run leaves windows changed without their explanation (verifier findings until it completes); a mistaken rewrite is irreversible; a restore from backup reintroduces redacted identifiers and the process must run again.
- **Policy fit.** Allowed as a non-silent, controlled mutation, but it is a mutation of evidence, which ADR-0051 and ADR-0053 were built to make visible. It needs an ADR amending both.

### (d) Identity side table referenced by id

The audit row stores a per-record reference (`identity_ref`), and a side table holds `identity_ref -> user_id` with the record's creation time, expiry and hold status. Expiry deletes the side-table row (or nulls its `user_id`).

- **Digests.** Unaffected, as (a).
- **Legal hold.** Exact per record.
- **Forensics.** Within retention, a join. After expiry, records are no longer linkable to each other at all (one reference per record), which loses more history than (a) (R6).
- **Existing rows.** Not covered.
- **Complexity.** As (a), with one side-table row per audit row (the side table grows with the audit log).
- **Failure modes.** As (a).
- **Verdict.** Exact per-record expiry (R3) at the cost of all linkage. (a) with a short period (a month) is a middle ground; a per-record reference that also carries the period pseudonym gives both, at the cost of two tables.

### (e) Aggregate, then delete

After two years, summarise records (counts per tenant, action and month) and delete the raw rows.

- **Digests.** Every deleted row is an `audit_log_changed` finding unless covered by a re-anchoring record as in (c).
- **Legal hold.** Held rows are not deleted.
- **Forensics.** Lost: aggregates answer volume questions, not "who changed this resource on that day".
- **Policy fit.** Conflicts with "preserve the non-identifying audit history where possible" and needs `DELETE` on evidence tables; it would change their `SECURITY_RETAIN` class.
- **Verdict.** Not recommended. It may become a later archival tier for very old records under a separate decision.

### Comparison

| | Digest intact | Hold | History kept | Existing rows | Schema change | Effort |
|---|---|---|---|---|---|---|
| (a) pseudonym + mapping | yes | per period | linkable per period | no | one table; metadata shape | medium |
| (b) crypto-shredding | yes | per period | as (a) with a key id | no | key table; ciphertext | high |
| (c) redaction + re-anchoring | only with digest v2 | per record | identifier gone | **yes** | grant/role, digest v2, verifier | high |
| (d) side table per record | yes | per record | not linkable | no | one table | medium |
| (e) aggregate then delete | no (needs (c)) | per record | aggregates only | yes | delete grant | medium |

## 5. Recommendation (separate from the facts above)

1. **For new records: option (a)**, a random pseudonymous subject reference minted in the audit write's own transaction per (tenant, user, month), with a tenant-scoped mapping table under RLS, a scheduled expiry job that deletes mapping rows two years after their month ends unless a hold covers them, and a resolve function for forensics behind an explicit authority. Audit rows and digests never change. A month bounds the extra retention at one month and keeps a month of linkage after expiry.
2. **Decide before PR #196's `initiated_by` shape reaches a release.** Today it stores `{"type": "user", "user_id"}` in metadata. Switching new rows to a `subject_ref` is cheapest before consumers depend on it; afterwards it is a public contract change plus a migration of rows already written.
3. **For rows written before the mechanism: option (c), once, as a tier-0 operator command** with a redaction ledger and a digest-chain continuation record sent to the external store, designed together with digest format version 2. Until then, existing rows are an accepted, documented exception, and the expiry date of each is still computed so the backlog is known.
4. **Legal holds** as a small table (scope: tenant, optionally subject and time range; reason reference; placed and released by; timestamps), managed by an operator command first, with every place, release and expiry run recorded in the platform audit log without the identifier.
5. **Backups:** document that a deleted mapping row survives in backups until they rotate (default 7 runs) and that the expiry job must run after any restore; keep a list of early-deleted references so a restore re-applies them.
6. **Not (b) or (e)**, for the reasons in section 4.

## 6. Decisions needed

- **D1 Scope.** Only `initiated_by` user ids and other user ids in metadata (the owner's text), or also the `actor_user_id` columns, `resource_id` values naming a user, and `core.platform_audit_log` (operator actions)? Including columns means a new column, a digest format version 2 and changes to every audit reader.
- **D2 Mechanism.** Approve (a) for new records, or another option.
- **D3 Legacy rows.** Approve a one-time (c) process with digest re-anchoring, or accept existing rows as an exception until a later decision.
- **D4 Granularity.** Pseudonym period (month proposed), and whether expiry is exact per record (needs (d) as well) or per period.
- **D5 Legal holds.** Who may place and release a hold (an operator command first, or a new platform permission), and what reference a hold must carry.
- **D6 Permissibility.** Who attests that removal is legally permissible for a tenant or installation, and whether a product can extend retention for its tenants.
- **D7 Products' own metadata.** Whether Core refuses raw user ids in product-supplied audit metadata (requiring products to pass a subject through Core) or leaves products responsible under the same policy.
- **D8 Adjacent stores.** Whether published outbox events (kept until tenant purge, carrying `saas_os.initiated_by`) and application logs follow the same two-year rule; this policy names audit records only.
