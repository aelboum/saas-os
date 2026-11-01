# System actor: decision record and inventory of actorless system audit rows

**Status: inventory, 2026-11-01. Changes no code.** Prepared on `main` `6fd2dfd`. It records the owner's decisions on the system-actor ADR (proposed as ADR 0061 in pull request #187) and inventories every place that can write a `core.audit_log` row with `actor_type = 'system'`, as decision Q3 requires before any such row may be refused.

## 1. Decisions (owner, 2026-11-01)

| Question | Decision |
|---|---|
| Option | **B**: an attribution-only `SystemActor` recorded in validated audit metadata (no migration, no digest-format change) |
| Kind list (Q2) | **Closed, owned by Core**; products choose only `name` |
| Refusing actorless system rows (Q3) | **Deferred** until every call site below is classified and a migration plan is approved |

What the decisions fix:

- **Attribution only.** `SystemActor(kind, name, initiator)` says who or what acted. It is not a `Caller`: no Core mutation accepts it, so it can never satisfy an authorization check. When a system action needs Core authority, it uses an existing, unchanged `SystemCaller` purpose, and the actor is attached to that caller for attribution only.
- **Validated metadata.** The actor is written under a fixed key with a validated schema (kind from the closed list; `name` matching `[a-z0-9_.:-]{1,100}`; `initiator` a record type and id, never a token or secret), before the insert, in the caller's transaction, failing closed.
- **Closed kind list:** `worker_job`, `scheduled_job`, `webhook_processor`, `provider_event_processor`, `inbound_processor`, `public_link`, `maintenance`, `billing_process`. A product cannot add a kind; it names its actor with `name`.
- **Product restrictions:** a product may attribute its own non-member actions with a `SystemActor`; it may not use one to call a Core mutation, may not set `actor_type` directly, and must take the tenant from a verified context (job context, the event's own tenant, a verified link token).
- **Nothing is refused yet.** Existing rows keep their meaning; existing calls keep working.

## 2. Inventory

Read from the code on 2026-11-01; "F" marks what was read, "I" an inference.

### 2.1 Successful system rows with no purpose (through `record()`, a separate transaction)

| # | Site | Function | Outcomes | Who acts | Reachable by a product with no actor? | Purpose today | Proposed classification | Impact if refused |
|---|---|---|---|---|---|---|---|---|
| 1 | `saas_os/api/tenant_bootstrap.py` (`_audit`) | first-tenant bootstrap | success | the bootstrap operator command | No (command only) | `{"bootstrap": "first_tenant"}`, no purpose (F) | `maintenance` actor, or write through the command's own `PROVISIONING` caller with `record_in_transaction` (I) | The command only |
| 2 | `saas_os/core/billing/service.py` (`subscribe`, also `subscribe_idempotent`) | legacy subscription API | success | legacy trusted path; `actor_user_id` is attribution only (F) | **Yes**: exported, `actor_user_id: uuid.UUID \| None = None` (F) | `plan_key` only | `billing_process` | **High**: a product calling the legacy API without a user breaks. The v1 routes use the commercial path instead (F) |
| 3 | `saas_os/core/billing/service.py` (`upgrade_subscription`) | legacy | success | as 2 | **Yes** (F) | plans only | `billing_process` | as 2 |
| 4 | `saas_os/core/billing/service.py` (`cancel_subscription`) | legacy | success | as 2 | **Yes** (F) | none | `billing_process` | as 2 |
| 5 | `saas_os/core/tenancy/service.py` (`_record_lifecycle_event`, from `purge_tenant`: started, failed, completed) | tenant purge | success, **failure** | purge; the caller must be `SystemCaller(TENANT_PURGE)`, `actor_user_id` optional (F) | **Yes**: `purge_tenant(..., actor_user_id=None)`; the operator CLI's `--actor` may be omitted (F) | **none**: the caller's `TENANT_PURGE` purpose is held but not written to these rows (F) | write the existing purpose (then "already attributed"), or `maintenance` | Low: purge is an operator operation, but a run without an actor would break |
| 6 | `saas_os/control_plane/self_learning/continuous_loop/service.py` (`_audit`, from `run_continuous_learning_cycle`) | learning cycle | success, **denied** | the scheduled tenant job passes no actor (F) | **Yes**: exported, `actor_user_id=None` default (F) | `trigger` only | denied rows keep `record()`; success → `scheduled_job` | SaaS OS's own scheduled job, and products calling it without a user |
| 7 | `saas_os/control_plane/self_learning/system_learning/service.py` (`propose_system_learning_proposal`) | proposal | success | product or system code; no caller in the repository (F) | **Yes** (F) | domain metadata, no purpose | `worker_job` (I: may fit no kind well) | Products calling it without a user |
| 8 | `saas_os/control_plane/self_learning/system_learning/service.py` (`withdraw_system_learning_proposal`) | withdrawal | success | as 7 | **Yes** (F) | status fields | `worker_job` (I) | as 7 |

**Seven of the eight are reachable by a product through a public parameter that defaults to no actor.** Refusing purpose-less successful system rows before these move would break the legacy billing API, purge without `--actor`, the scheduled learning cycle and the system-learning proposals.

### 2.2 System rows written through a variable `actor_type`

| Site | Can be `system`? | Note |
|---|---|---|
| `saas_os/core/billing/commercial.py`: payer-side creation row, payment page issued (success), payment page refused (denied) | **Yes** | `audit_actor()` (`saas_os/core/billing/authorization.py`) returns `system` for `SystemCaller(BILLING_OPERATIONS)` and merges `system_authority` into the metadata (F): **already attributed**, though written through `record()` |
| `saas_os/core/api_keys/service.py` (`validate_api_key`, five denial sites) | No | user or service account only (F) |
| `saas_os/api/dependencies.py` audit helpers | No | user or service account only (F) |
| `saas_os/control_plane/inference/service.py` attempt rows | Not `core.audit_log` | an attempt-ledger column (F) |
| `saas_os/core/rbac/authorization.py`, `saas_os/core/rbac/service.py` | Not audit | `PrincipalType` arguments to `can()` (F) |
| `saas_os/core/platform_authority/audit.py` | Not `core.audit_log` | the platform audit table (F) |

### 2.3 Already attributed: `record_in_transaction()` with a `SystemCaller`

About thirty sites, each writing `metadata.system_authority` (F):

- `PROVISIONING`: `add_tenant_membership`, `create_service_account` (`saas_os/core/identity/service.py`); `create_role`, `grant_permission`, `_insert_membership_role` (`saas_os/core/rbac/service.py`); webhook `subscribe`, `unsubscribe`; `record_tenant` in `saas_os/core/tenancy/authority.py` (tenant creation, activation; move only where the operation lists the purpose, I).
- `TENANT_PURGE`: `revoke_tenant_support_access` during purge.
- `BILLING_OPERATIONS`: `record_billing_audit` (catalog, commercial, inheritance and parties functions), the refused-creation row. Stripe provider-event processing acts as `SystemCaller(BILLING_OPERATIONS)`, so reconciliation rows read `billing_operations`, not a provider-event processor (F); a `provider_event_processor` actor could be attached for attribution (I).
- `PLATFORM_BOOTSTRAP`: writes only the platform audit table (I).

## 3. Migration plan to approve before any refusal (not started)

The owner approved this four-step direction on 2026-11-01; the detailed plan is `docs/architecture/SYSTEM-ACTOR-MIGRATION-PLAN.md`. Actorless writes are still not refused.

1. Add `SystemActor` and the same-transaction function (option B), and attach a derived actor to job contexts. Additive; no refusal.
2. Move sites 1 and 5 to an attributed write (the existing caller's purpose, plus an actor) and sites 6 to 8 to `SystemActor` for their success rows; keep denials on `record()`.
3. Sites 2 to 4 (legacy billing API): deprecate calls without `actor_user_id` and a `SystemActor` for one release, with a warning naming the calling module; the v1 commercial path is unaffected.
4. Only then, in a later release and with its own approval: refuse successful `system` rows through `record()` that carry neither a purpose nor an actor.
