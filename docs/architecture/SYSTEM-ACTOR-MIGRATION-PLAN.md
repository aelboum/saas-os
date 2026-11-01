# System actor: migration plan for the eight actorless call sites

**Status: plan, 2026-11-01. Approved in direction by the owner (four steps); nothing is implemented, and actorless writes are not refused.** Prepared on `main` `6fd2dfd`. Built from the call-site inventory in `docs/architecture/SYSTEM-ACTOR-CALLSITE-INVENTORY.md` (its section 3 holds the four steps this plan details; nothing in them is replaced). Option B of the system-actor ADR (proposed as ADR 0061 in pull request #187): `SystemActor` records attribution only, never authorization; Core owns a closed list of kinds.

## Invariants every step keeps

1. **Attribution is not authority.** `SystemActor` is not a `Caller`; `require_caller()` refuses it; no Core mutation takes it as its authority. Where an action needs authority, it keeps its existing `SystemCaller` purpose or user caller, unchanged.
2. **Closed, Core-owned kinds:** `worker_job`, `scheduled_job`, `webhook_processor`, `provider_event_processor`, `inbound_processor`, `public_link`, `maintenance`, `billing_process`. Products choose `name` only.
3. **Tenant from verified context only** (job context, the event's own tenant, the caller's tenant), never from an actor field.
4. **No refusal** of actorless writes until step 4 is separately approved. **`PROVISIONING` is not narrowed.**

## Step 1: the attribution primitive (additive; minor release)

| Change | Where | Public surface |
|---|---|---|
| `SystemActorKind` (the eight kinds) and `SystemActor(kind, name, initiator_type=None, initiator_id=None)`, frozen, validated at construction (`name` and `initiator_type` match `[a-z0-9_.:-]{1,100}`; `initiator_id` a UUID or `[A-Za-z0-9_.:-]{1,100}`, never a token) | `saas_os/core/authority/` | Additive |
| `record_system_action_in_transaction(session, *, tenant_id, actor, action, resource_type, resource_id=None, outcome=SUCCESS, correlation_id=None, metadata=None)`: `actor_type = 'system'`, the actor under the reserved metadata key `system_actor`, the same validation and fail-closed behaviour as `record_in_transaction` | `saas_os/core/audit_log/` | Additive |
| `system_actor` refused as a key in caller-supplied metadata (it cannot be forged through `metadata=`) | `saas_os/core/audit_log/` | A product passing that key today gets an error; none is known |
| `SystemCaller(authority, actor=None)`: an optional attribution field; `record_in_transaction` writes it under `system_actor` next to `system_authority` | `saas_os/core/authority/caller.py` | Additive keyword with a default |
| `TenantJobContext.system_actor` and `SystemJobContext.system_actor`, derived by the job wrapper (`worker_job` or `scheduled_job`, `name` the registered function, `initiator` the arq job id) | `saas_os/infra/jobs/` (passed as data: Infra does not import Core, import contract) | Additive field with a default |
| A `DeprecationWarning` and a log line `audit_system_row_unattributed` (calling module only) when `record()` writes a successful `system` row with neither a purpose nor an actor | `saas_os/core/audit_log/service.py` | Warning only; nothing refused |

The audit digest (ADR-0053) hashes each row including its metadata, so its format is unchanged.

## Step 2: SaaS OS's own sites (same or next minor release)

| # | Site | Change | Kind / name | Transaction |
|---|---|---|---|---|
| 1 | `saas_os/api/tenant_bootstrap.py` `_audit` | Write through `record_system_action_in_transaction` in the bootstrap's own transaction, with its existing `PROVISIONING` caller's purpose | `maintenance` / `first_tenant_bootstrap` | Moves from a separate transaction into the change's own |
| 5 | `saas_os/core/tenancy/service.py` `_record_lifecycle_event` (purge started, failed, completed) | When `actor_user_id` is `None`, record the caller's purpose (`tenant_purge`) and a `maintenance` actor; with a user, unchanged | `maintenance` / `tenant_purge` | Unchanged: the "failed" row is written after the failed step, outside its rolled-back transaction, so it keeps a separate write |
| 6 | `saas_os/control_plane/self_learning/continuous_loop/service.py` `_audit` | Success rows: the job context's actor when scheduled; denied rows keep `record()` | `scheduled_job` / `continuous_learning_cycle` | Unchanged |
| 7 | `saas_os/control_plane/self_learning/system_learning/service.py` `propose_system_learning_proposal` | New optional keyword `system_actor`; with neither a user nor an actor, the step-1 warning | chosen by the caller; `worker_job` from a job | Unchanged |
| 8 | same, `withdraw_system_learning_proposal` | As 7 | as 7 | Unchanged |

## Step 3: the legacy billing API (sites 2 to 4; deprecation release)

`subscribe` (and `subscribe_idempotent`), `upgrade_subscription` and `cancel_subscription` in `saas_os/core/billing/service.py` gain an optional `system_actor` keyword. A call with neither `actor_user_id` nor `system_actor` writes as today, plus the step-1 warning, for at least one minor release. The v1 commercial path (`create_subscription` and the opt-in routers) is unaffected: it already audits through `SystemCaller(BILLING_OPERATIONS)` with its purpose.

## Step 4: refusal (separate approval, later release)

`record()` refuses a successful `system` row with neither a purpose nor an actor. Preconditions: steps 1 to 3 released; one release with the warning; the consumer inventory below re-run with no unattributed call left.

## Product compatibility and consumer migration

| Consumer path | Affected by | Consumer action |
|---|---|---|
| Legacy billing calls without a user | Steps 3 and 4 | Pass `system_actor=SystemActor(BILLING_PROCESS, "<name>")` or move to the commercial API, before step 4 |
| `purge_tenant(..., caller=SystemCaller(TENANT_PURGE))` without `actor_user_id` | Step 2 attributes it automatically | None. The first consumer does this in two integration probes in its own repository (read 2026-11-01); they keep working |
| Learning cycle or system-learning calls without a user | Steps 2 and 4 | Pass `system_actor`, before step 4 |
| A product's own audit writes for non-member actions | Step 1 offers the path | Optional: use `record_system_action_in_transaction` |

No consumer pin moves as part of this plan; each consumer adopts by its own approved pin change. The first consumer's code calls none of the other inventoried paths (read-only search of its repository, 2026-11-01).

## Tests

- **Attribution:** each migrated site writes `system_actor` with the expected kind and name, in the expected transaction; where the write joins the change's transaction (site 1, and sites 6 to 8 when attributed), an injected audit failure leaves no change.
- **Separation from authority:** `require_caller()` refuses a `SystemActor`; every exported mutating Core function refuses one in place of its caller; a `SystemCaller` with an actor is authorized exactly as without one (the actor never changes `can()`, the platform matrix or anti-amplification); negative control: making `SystemActor` acceptable as a `Caller` fails these tests.
- **Validation:** unknown kinds, bad names, a token-like initiator and a caller-supplied `system_actor` metadata key are refused before any write.
- **No refusal yet:** an actorless successful `system` row through `record()` is still written, with the warning.
- **Isolation:** attribution never changes a row's tenant; the tenant comes from the context.
- **Digest:** `python -m saas_os.ops.audit_digest verify` passes over rows written before and after step 1.

## Differences from the request, and why

The request asks for a plan that migrates all eight sites. The inventory's four steps already cover them (site 1 and sites 5 to 8 in step 2, sites 2 to 4 in step 3); this plan details them without changing their order or content. One refinement is recorded rather than invented: site 5's "failed" row cannot join the purge step's transaction, because it must survive that step's rollback, so it keeps a separate write and gains attribution only.
