# ADR-0061: System actor attribution in the audit trail

Status: Accepted (2026-11-02, owner). Proposed 2026-11-01; the history below is kept as written. Accepted with Option B and the decisions recorded in "Decision", including the completed-audit retention policy, which is policy only. Step 1 is implemented in pull request #196 (open, not merged).
Date: 2026-11-01 (accepted 2026-11-02; amended 2026-11-02 for the attribution decision (C) of the 2026-11-01 owner review, clarified 2026-11-02, and for the erasure decision of 2026-11-02: see "Amendment 2026-11-02"; review correction 2026-11-02)
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
An audit row for a system action records three distinct roles, each under its own metadata key (amended 2026-11-02 for the attribution decision (C) of the 2026-11-01 owner review, which is not Option C below):

- **Executing actor** (`system_actor`): the system component or job that performed the action. A frozen value type `SystemActor(kind, name)`, recorded as `{"kind", "name"}`: `kind` from a closed, Core-owned enum (`worker_job`, `scheduled_job`, `webhook_processor`, `provider_event_processor`, `inbound_processor`, `public_link`, `maintenance`, `billing_process`); `name` a product-chosen identifier (`[a-z0-9_.:-]{1,100}`).
- **Initiating actor** (`initiated_by`): the original user, service account or system actor that requested the action, as one of `{"type": "user", "user_id"}`, `{"type": "service_account", "service_account_id"}`, `{"type": "system", "kind", "name"[, "record_type", "record_id"]}` (the optional record names the triggering record, such as a provider event or a public-link record, never a token or other credential), or the exact string `"unavailable"` when it cannot be established. The executing actor is never substituted for it, and a user id is never invented.
- **Correlation** (`correlation`): `arq_job_id`, `outbox_event_id` and `request_id`, each optional, each under its own key. Correlation data links an execution to its request, event and job; it is never actor identity.

A new `record_system_action_in_transaction(session, *, tenant_id, actor, action, resource_type, resource_id, outcome, correlation_id, metadata, initiated_by, correlation)` writes a `system` row whose metadata carries `system_actor`, `initiated_by` and `correlation` under a fixed schema validated before the insert, in the caller's transaction, failing closed; an omitted `initiated_by` is recorded as `"unavailable"`. `SystemActor` is **not** a `Caller`: no Core mutation accepts it, so it confers no authority. When a system action also needs Core authority, the call uses an existing, unchanged `SystemCaller` purpose, and the actor is attached to that caller for attribution (`SystemCaller(authority, actor=...)`), never in place of it.
- Advantages: no migration; no new authority; the audit digest format (ADR-0053) is unchanged because metadata is already digested; products get a sanctioned path today's `record()` misuse does not offer.
- Disadvantages: actor fields are queryable only through JSON; the metadata size limit (8 KB) applies.

### Option C: Option B with dedicated nullable columns
Same model, stored in new nullable columns (`system_actor_kind`, `system_actor_name`, `initiated_by_type`, `initiated_by_id`; correlation stays in metadata) with CHECK constraints.
- Advantages: indexable, constrained by the database.
- Disadvantages: a migration on an append-only table; the audit digest must include the new columns, which versions the digest format and its verifier.

## Recommendation

**Option B now; Option C only if querying by actor becomes a real need.** Rules:

1. Attribution never implies authority: `SystemActor`, the initiating actor and the correlation are accepted only by audit functions and (the actor) as an annotation on a `SystemCaller`; none is a `Caller` or is read by any authorization check.
2. Tenant context is mandatory, as today: a system action is recorded in the audit of the tenant it affected. Installation-level system actions use the platform audit (ADR-0045).
3. Tenant id comes from the verified context (`TenantJobContext`, the event's own tenant, a verified link token), never from untrusted input, as `docs/CONSUMER-GUIDE.md` section 7 already requires for sessions.
4. The `correlation_id` column and the `correlation` metadata (`request_id`, `arq_job_id`, `outbox_event_id`) carry the request's, the job's and the event's ids, so a chain (inbound event, outbox event, job, audit row) is traceable. These are correlation data, never actor identity: none of them is recorded as, or in place of, the executing or the initiating actor.
5. `record()` keeps its documented use for denials; its use for successful system actions is migrated to the new function, and a later release refuses `actor_type = 'system'` through `record()` for a non-denial outcome.
6. (Amended 2026-11-02.) Job attribution distinguishes three roles. `TenantJobContext` and `SystemJobContext` gain an optional `system_actor`, the **executing actor**, derived by the job wrapper as `{kind, name}` (`worker_job` or `scheduled_job`, name = the registered job name). `TenantJobContext` also carries `initiated_by`, the **initiating actor**: the original user, service account or system actor that requested the work, propagated from the producer (for an outbox consumer, the initiator recorded with the event). In the job context it is `None` when the initiator cannot be established (pull request #196: plain data, `JobInitiator | None`); the audit row records that case as exactly `"unavailable"` (corrected 2026-11-02); the executing job is never substituted for it and no user id is invented. The arq job id, the outbox event id and the request id are **correlation** (`correlation`), never actor identity: the job id identifies an execution, not who initiated it. Handlers attribute consistently without building any of the three themselves.
7. Public links: the executing actor is `public_link`; where the link is the initiator, `initiated_by` is a `system` initiator whose optional record names the link record, never the bearer token.

## Decision

**Accepted by the owner on 2026-11-02: Option B**, with the rules of the recommendation as amended ("Amendment 2026-11-02"), and the following.

1. **Three distinct roles.** An audit row for a system action records the **executing actor** (`system_actor`: the system component or job that performed the action), the **initiating actor** (`initiated_by`: the original user, service account or system actor that requested it, or exactly `"unavailable"` when it cannot be established) and **correlation** (`correlation`: request id, arq job id, outbox event id) under separate keys. None is substituted for another: the executing actor is never recorded as the initiator, correlation ids are never actor identity, and a user id is never invented.
2. **`SystemActor` never expands authorisation.** It is not a `Caller`; no Core mutation accepts it and no authorization check reads it. When a system action needs Core authority it uses an existing, unchanged `SystemCaller` purpose, and the actor is attached to that caller as an annotation for attribution only. No `SystemAuthority` is added for attribution.
3. **`kind` (Q2, 2026-11-01)** is a closed, Core-owned list; products choose `name` only.
4. **Refusing purpose-less successful `system` rows through `record()` (Q3, 2026-11-01)** is deferred until every call site is classified and a migration plan is approved (`docs/architecture/SYSTEM-ACTOR-CALLSITE-INVENTORY.md`, pull request #188).
5. **Erasure of a stored outbox initiator (2026-11-02).** When a user is erased, every outbox event in each tenant the erasure covers whose stored initiating actor is that user has it replaced by `"unavailable"`, whatever the event's status, in the erasure's per-tenant transaction under that tenant's RLS; nothing else in the event changes.
6. **Retention of completed audit rows that identify a user initiator (owner policy of 2026-11-02).** A completed audit record whose attribution contains an identifiable user initiator is retained for **two years from the audit record's creation**. A legal hold can suspend that expiry. After expiry, a controlled privacy process removes or anonymises the direct user identification where legally permissible, preserving the non-identifying history of the record (what was done, its outcome and time, the executing actor and the correlation). Append-only audit records are never mutated silently, and there is no uncontrolled deletion: any such change is made only by that controlled process and is itself recorded. This is **policy only**: no mechanism exists. The mechanism is a separate technical proposal for pull request #196, not implemented; until it is approved and implemented, completed audit rows are not changed (item 5 does not touch them).

**Implementation status (2026-11-02).** Step 1 (the `SystemActor` value type, the attribution audit function, the job-context fields and the outbox initiator erasure of item 5) is implemented in pull request #196 (open, not merged). Item 6 is not implemented anywhere. Acceptance does not mean any of it is deployed.

The questions as first asked (2026-11-01), kept as history:

- Q1. Option B (recommended) or C?
- Q2. Is the closed `kind` list right, and may products extend it (recommendation: no; products choose `name`, Core owns `kind`)?
- Q3. Timetable for refusing purpose-less successful system rows through `record()` (rule 5).

## Amendment 2026-11-02 (attribution decision (C) of the 2026-11-01 owner review, clarified 2026-11-02)

*Naming (review correction 2026-11-02):* the owner's review of 2026-11-01 labelled its decisions with letters; its decision C is the separation of the three attribution roles below. It is **not** this ADR's Option C (dedicated nullable columns), which was not chosen: the owner chose Option B.

The proposal of 2026-11-01 modelled `SystemActor(kind, name, initiator)`, with `initiator` an optional `(type, id)` reference to the triggering record, and its rule 6 read: "`TenantJobContext` and `SystemJobContext` gain an optional `system_actor` derived by the job wrapper (`worker_job` or `scheduled_job`, name = the registered job name, initiator = the job id), so handlers attribute consistently without building it themselves."

That conflated three different things. The arq job id identifies one execution of the job that already appears as the executing actor; recording it as the initiator says nothing about who asked for the work, and it hid the cases where the original requester (a user, a service account, a schedule, a provider event) is known and should be recorded, as well as the cases where it is not known and should say so. The owner decided (attribution decision (C) of the 2026-11-01 review, clarified on 2026-11-02) to separate the roles: executing actor (`system_actor`, `{kind, name}`), initiating actor (`initiated_by`, a user, service account or system actor, or exactly `"unavailable"`; never the executor, never an invented user id) and correlation (`correlation`: request id, arq job id, outbox event id; never actor identity). Option B, rules 1, 4, 6 and 7 and Option C's column list were amended accordingly; the shapes are those implemented in PR #196.

**User erasure (owner decision of 2026-11-02).** When a user is erased, every outbox event of each tenant whose stored initiating actor is that user has it replaced by `"unavailable"`, whatever the event's status, in the erasure's per-tenant transaction under that tenant's RLS; the event's other payload keys, its id, status and schedule are unchanged. Completed audit rows are not changed by this: whether an audit row's recorded `initiated_by` is retained or erased is a separate policy decision, not taken here (*decided 2026-11-02 as a policy, not implemented: "Decision", item 6*). Implemented in pull request #196 (`erase_user_initiator()` in `saas_os.core.outbox.initiator_erasure`, deliberately not exported from `saas_os.core.outbox` and fenced by the identity-erasure import-linter contract; called only by `erase_user_identity()`; open, not merged).

Unchanged by the amendment: attribution only (`SystemActor` is never a `Caller` and confers no authority); `kind` stays a closed, Core-owned list; a write whose initiator cannot be established is recorded with `"unavailable"`, not refused; `PROVISIONING` is not narrowed here (that remains ADR-0045's deferred item and capability C03).

## Owner decisions recorded (2026-11-02 review correction)

*Superseded 2026-11-02 by the owner's acceptance (Status and "Decision" above); the note is kept as written.* The Status and Decision fields above are unchanged; accepting this ADR is the owner's step. For readers, the owner's decisions so far and where they are recorded:

- Option **B**; Q2 a closed, Core-owned `kind` list, products choose `name` only; Q3 deferred until every call site is classified and a migration plan is approved (all 2026-11-01). Recorded in `docs/architecture/SYSTEM-ACTOR-CALLSITE-INVENTORY.md` section 1 (pull request #188).
- The attribution decision (C) of the 2026-11-01 owner review, clarified 2026-11-02, and the erasure decision of 2026-11-02: section "Amendment 2026-11-02" above.
- Implementation of step 1: pull request #196 (open, not merged; head `b6a7f07` when this note was written).

## What Would Be Difficult to Change Later

- The `kind` vocabulary appears in every product's audit history; renaming a kind later breaks queries over old rows.
- The `initiated_by` shapes and the `"unavailable"` value likewise appear in audit history; adding an initiator type is additive, renaming one is not.
- Moving from metadata (B) to columns (C) later needs a backfill on an append-only table and a digest-format version; deciding C first avoids that but costs it now.

## Related

ADR-0020 (redaction), ADR-0031 (typed callers, same-transaction audit), ADR-0045 (platform audit), ADR-0051 (append-only audit), ADR-0053 (audit digests), ADR-0060 (its implementation in pull request #198 does not use a `SystemActor`: the operator is recorded as `operator_user_id`, with `system_authority=permission_upgrade`; aligning it with `initiated_by` is a possible future change, not done); `docs/architecture/UNIVERSAL_PLATFORM_ASSESSMENT.md` section 8.
