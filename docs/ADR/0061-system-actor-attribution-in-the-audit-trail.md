# ADR-0061: System actor attribution in the audit trail

Status: Proposed
Date: 2026-11-01
Supersedes / Superseded by: none

## Context

Products and SaaS OS itself perform actions no member performs: a worker job, a scheduled task, a webhook or provider-event processor, inbound mail handling, a public link carrying a token (an unsubscribe link), a maintenance command, an automated billing step. Verified at `main` `6fd2dfd`:

- `core.audit_log` already allows `actor_type = 'system'` with both actor ids `NULL` (a database CHECK enforces the pairing). `tenant_id` is mandatory; there are no tenant-less rows. `correlation_id` exists.
- `record_in_transaction(session, caller=...)` (same transaction, fail closed) derives the actor from a typed caller; a `SystemCaller` becomes `system` with `metadata.system_authority`. The only purposes are `PROVISIONING`, `TENANT_PURGE`, `BILLING_OPERATIONS` and `PLATFORM_BOOTSTRAP`. None describes a worker, a webhook processor or a public link.
- `record()` (separate transaction, documented for denials) takes a free `actor_type` and is also used for successful system actions (tenant bootstrap, parts of billing, tenancy and the control plane) with no purpose and no structure.
- Jobs carry no caller: `TenantJobContext` holds a tenant id and a correlation id only.
- The first consumer records such actions only in its own rows, without audit entries, because borrowing a purpose would misstate authority.

Two things are tangled today: **authority** (what an operation lets a system caller do) and **attribution** (who or what did it, on what trigger). Adding a `SystemAuthority` per actor kind would grant authority to fix an attribution problem, and each new purpose is in-process ambient authority (ADR-0031: "a purpose is a label, not a credential").

## Options Considered

### Option A: new `SystemAuthority` values per actor kind (`WORKER`, `WEBHOOK`, ...)
- Advantages: reuses `record_in_transaction` as is.
- Disadvantages: every value is accepted somewhere and becomes authority; attribution would require authority; the matrix of ADR-0031/0045 grows for a non-authorization need.

### Option B: an attribution-only `SystemActor`, recorded in validated metadata
A frozen value type `SystemActor(kind, name, initiator)`: `kind` from a closed enum (`worker_job`, `scheduled_job`, `webhook_processor`, `provider_event_processor`, `inbound_processor`, `public_link`, `maintenance`, `billing_process`); `name` a product-chosen identifier (`[a-z0-9_.:-]{1,100}`); `initiator` an optional `(type, id)` reference to the triggering record (outbox event, provider event, job id, link token id, never the token). A new `record_system_action_in_transaction(session, *, tenant_id, actor, action, resource_type, resource_id, outcome, correlation_id, metadata)` writes a `system` row whose metadata carries `system_actor` under a fixed schema validated before the insert, in the caller's transaction, failing closed. `SystemActor` is **not** a `Caller`: no Core mutation accepts it, so it confers no authority. When a system action also needs Core authority, the call uses an existing, unchanged `SystemCaller` purpose, and the actor is attached to that caller for attribution (`SystemCaller(authority, actor=...)`), never in place of it.
- Advantages: no migration; no new authority; the audit digest format (ADR-0053) is unchanged because metadata is already digested; products get a sanctioned path today's `record()` misuse does not offer.
- Disadvantages: actor fields are queryable only through JSON; the metadata size limit (8 KB) applies.

### Option C: Option B with dedicated nullable columns
Same model, stored in new nullable columns (`system_actor_kind`, `system_actor_name`, `initiator_type`, `initiator_id`) with CHECK constraints.
- Advantages: indexable, constrained by the database.
- Disadvantages: a migration on an append-only table; the audit digest must include the new columns, which versions the digest format and its verifier.

## Recommendation

**Option B now; Option C only if querying by actor becomes a real need.** Rules:

1. Attribution never implies authority: `SystemActor` is accepted only by audit functions and as an annotation on a `SystemCaller`.
2. Tenant context is mandatory, as today: a system action is recorded in the audit of the tenant it affected. Installation-level system actions use the platform audit (ADR-0045).
3. Tenant id comes from the verified context (`TenantJobContext`, the event's own tenant, a verified link token), never from untrusted input, as `docs/CONSUMER-GUIDE.md` section 7 already requires for sessions.
4. The correlation id is the job's, the request's or the event's, so a chain (inbound event, outbox event, job, audit row) is traceable.
5. `record()` keeps its documented use for denials; its use for successful system actions is migrated to the new function, and a later release refuses `actor_type = 'system'` through `record()` for a non-denial outcome.
6. `TenantJobContext` and `SystemJobContext` gain an optional `system_actor` derived by the job wrapper (`worker_job` or `scheduled_job`, name = the registered job name, initiator = the job id), so handlers attribute consistently without building it themselves.
7. Public links: the actor is `public_link`; the initiator names the link record, never the bearer token.

## Decision

Pending. Questions for the owner:

- Q1. Option B (recommended) or C?
- Q2. Is the closed `kind` list right, and may products extend it (recommendation: no; products choose `name`, Core owns `kind`)?
- Q3. Timetable for refusing purpose-less successful system rows through `record()` (rule 5).

## What Would Be Difficult to Change Later

- The `kind` vocabulary appears in every product's audit history; renaming a kind later breaks queries over old rows.
- Moving from metadata (B) to columns (C) later needs a backfill on an append-only table and a digest-format version; deciding C first avoids that but costs it now.

## Related

ADR-0020 (redaction), ADR-0031 (typed callers, same-transaction audit), ADR-0045 (platform audit), ADR-0051 (append-only audit), ADR-0053 (audit digests), ADR-0060 (uses this for permission-upgrade attribution); `docs/architecture/UNIVERSAL_PLATFORM_ASSESSMENT.md` section 8.
