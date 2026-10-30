# Control-plane audit atomicity: decision brief (Phase 9 finding S3)

**Status: decided 2026-10-30; the owner chose option A, implemented and recorded in the ADR-0031 amendment of 2026-10-30.** The text below is the brief as presented. Prepared 2026-10-30 against `main` `df87808`. It records how the AI Control Plane writes its audit evidence today, why no existing ADR settles whether that must change, and the options, with a recommendation. Nothing in this brief has been implemented. Source: finding S3 in `docs/architecture/PHASE-9-RECERTIFICATION.md` and its row in the deferred-issue ledger (`docs/P-ROADMAP.md`, "Phase 9 S3").

## 1. Current behaviour (verified by reading the code)

**Core.** ADR-0031 ("Foundation Authority & Evidence") made `core.audit_log.record_in_transaction(session, *, caller, ...)` the rule for every function in its inventory. The audit row is added to the mutation's own `tenant_session_scope()` session and flushed, never committed separately. The actor columns are derived from a typed `Caller` (`UserCaller`, `ServiceAccountCaller` or `SystemCaller`). A committed change therefore always has its record, and a rolled-back one never has.

**Control plane, one module already follows the Core rule.** `control_plane/inference/config/tenant_policy.py` (ADR-0054, ADR-0055 section 7) writes tenant AI policy changes with `record_in_transaction` and a `UserCaller` or `ServiceAccountCaller`, inside the same transaction as the change. A refusal writes a `denied` row after the rollback.

**Control plane, everything else.** The services below commit their change in one `tenant_session_scope()` and then call `core.audit_log.record()`, which opens a second, independent transaction. The actor is passed as a bare `actor_user_id` with `ActorType.USER`, not as a `Caller`.

| Group | Modules | What the audit row records |
|---|---|---|
| A. Production-effect self-learning transitions | `self_learning/adaptive` (`learning.adaptation_activated`, `.rolled_back`), `self_learning/autonomous_improvement` (`learning.canary_started`, `.rolled_back`, `.rollback_failed`) | A state change that alters what a tenant's AI behaviour uses, or records that such a change failed |
| B. Other persisted self-learning changes | `adaptive` (`.adaptation_created`), `autonomous_improvement` (`.canary_created`, `.canary_observation_recorded`, `.succeeded`, `.promoted`, `.cancelled`; the code calls promotion and cancellation bookkeeping, since the adaptation is already active or was never started), `experiments` (`.experiment_created`, `.executed`, `.result_recorded`, `.cancelled`), `continuous_loop`, `system_learning` | A row change with no production effect by itself |
| C. Approval workflow | `approvals` (`control_plane.action_proposed`, `.approved`, `.rejected`), `orchestration` (`control_plane.tool_invocation`) | The request lifecycle and each tool execution |
| D. Decision evidence | `data_authorization`, `self_learning/evaluation`, `self_learning/policy_gate`, `self_learning/service.py` (learning authorization) | A decision whose only persistent trace is the audit row. Later steps verify provenance by reading that row back (`verify_evaluation_provenance` and similar) |

`inference/service.py` is outside these groups: its only `record()` call writes a `denied` row after a refusal, best effort by design (a failed write is logged and the refusal stands), and an attempt that reaches a destination is recorded in its attempt row, not the audit log (ADR-0055).

For groups A to C, a failure of the audit write leaves the change committed with no audit row. The failure is raised to the caller, never swallowed (`record()` lets it propagate), so the caller sees an error for an operation that did take effect. Group D has no gap: the audit row is the only write, so it either exists or the call failed.

**`start_canary`** (`autonomous_improvement/service.py`) runs four transactions in sequence:

1. `activate_adaptation()` commits the adaptation as `ACTIVE` (and any previous version as `SUPERSEDED`);
2. `record()` writes `learning.adaptation_activated`;
3. a new transaction sets the canary to `RUNNING`;
4. `record()` writes `learning.canary_started`.

A failure after step 1 leaves the adaptation `ACTIVE` while the canary is still `CONFIGURED`. A failure after step 3 leaves a running canary with no `canary_started` row. From the code (not exercised by a test): retrying `start_canary` after a failure in step 2 or 3 is refused by `activate_adaptation()` with `AdaptationNotCandidateError`, because the adaptation is no longer a candidate, so the canary cannot be started and the adaptation stays active outside canary monitoring until an operator rolls it back. The canary's own status is read before step 1 and not re-checked under lock in step 3.

## 2. Why the existing ADRs do not decide this

- ADR-0031's rule and inventory are written for Core. Its own text describes the old pattern ("committed its change in one `tenant_session_scope()` transaction and wrote its audit entry afterwards with `core.audit_log.record()`, in a second, independent transaction") as the thing it replaced, but only for the functions it lists. No control-plane function is in the inventory.
- ADR-0054 and ADR-0055 require same-transaction audit for the AI inference configuration they introduce, not for the Phase 7 approval workflow or the Phase 9 self-learning services, which predate them.
- `CLAUDE.md` section 11.7 says to follow the applicable ADR for event ordering and failure behaviour. For groups A to C there is none that requires in-transaction audit, so changing them is a change of control-plane audit semantics. Finding S3 recorded it as an owner decision for that reason.

Changing the actor from a bare user id to a `Caller` is in scope of any option that uses `record_in_transaction`, because that function only accepts a `Caller`. Building `UserCaller(user_id)` from an already-authenticated id is what the API layer and the operator CLIs do today (`saas_os/api/v1/_common.py`, `saas_os/ops/ai_commands.py`). It names the actor and grants nothing: authorization stays with the approval workflow and the Policy Gate. No import-linter contract changes: the control plane already imports `saas_os.core.authority` and `saas_os.core.audit_log`.

## 3. Options

**A. Same-transaction audit for the production-effect transitions only (group A), plus one transaction for `start_canary`.**
- `activate_adaptation`, `rollback_adaptation` and the group-A canary transitions write their audit row with `record_in_transaction` in the transaction that changes the row, with `UserCaller(<the user id they already receive>)`.
- `start_canary` activates the adaptation and sets the canary to `RUNNING` in one transaction, with both audit rows, re-reading the canary under lock. This needs an internal variant of the activation that takes the caller's session; the public `activate_adaptation()` keeps its signature for the tier-1 tool.
- For: closes the part of S3 that matters (a production-effect change without evidence, and the half-started canary). Small, contained change; follows the pattern `tenant_policy.py` already uses.
- Against: groups B and C keep the gap. Two audit styles remain in the control plane, and the boundary between them needs to be written down.

**B. Same-transaction audit for every persisted control-plane change (groups A, B and C).**
- Everything in option A, plus the remaining self-learning services, the approval workflow and the orchestration invocation record.
- For: one rule for Core and the control plane; ADR-0031 can be extended by name.
- Against: the largest change. The approval workflow's claim (`approved` to `executing` to `executed`) deliberately spans transactions around the tool handler, so its audit placement needs its own design: the `tool_invocation` row cannot be in the same transaction as a handler that opens its own sessions. Ten test files name these groups' audit actions and would need review, not only the code.

**C. Keep the current behaviour and record it as accepted.**
- Amend ADR-0031, or write a short control-plane ADR, stating that control-plane audit is written after commit and is not atomic with the change. Fix only the `start_canary` ordering, so that a failure cannot leave an active adaptation behind an unstarted canary.
- For: no change of audit semantics; least work.
- Against: the platform's audit-completeness standard stays lower for the control plane than for Core, including for changes with production effect. S3 stays open as an accepted risk.

**D. Write the audit through the transactional outbox (ADR-0032).**
- For: atomic with the change without passing a session into the audit API.
- Against: a second audit path beside `record_in_transaction`, which `CLAUDE.md` section 5 ("do not introduce a parallel mechanism") and ADR-0031 both argue against. The audit row would also appear later than the change, so provenance reads in group D could miss it. Not recommended.

Group D is unaffected by every option: its audit row is its only write.

## 4. Recommendation

Option A now, with option B's remaining groups left as recorded LOW-severity work.

- It removes the two outcomes S3 is actually about: a production-effect change committed without evidence, and an adaptation active outside its canary.
- It reuses the mechanism and caller shape already accepted for the control plane (`tenant_policy.py`) and for Core, so no new pattern or dependency is introduced.
- It does not touch the approval workflow's claim design, which is where option B needs its own decision.

Proposed acceptance for option A:

- each group-A transition writes its row with `record_in_transaction`;
- an injected audit failure rolls the transition back, for each transition;
- `start_canary` is one transaction, and a failure at any point leaves both the adaptation and the canary unchanged;
- a negative control shows the rollback test fails if the audit is moved back after the commit;
- the full unit and integration suites pass.

The ADR-0031 extension would be written as an amendment naming the group-A functions, so its Core inventory stays accurate.

## 5. Decision needed

One choice: **A**, **B**, **C** or **D**. If B, also whether the approval workflow's `tool_invocation` row should be written in the claim's transaction (before the handler runs) or in the `executed` transaction (after it). Implementation, tests and the ADR amendment follow from the choice without further questions.

## 6. Not affected

- No migration is needed for options A, B or C: `core.audit_log` and the control-plane tables keep their schema.
- No authorization, RLS or tenancy rule changes. The approval workflow, the Policy Gate and the fresh canary authorization (CP-03) stay as they are.
- The public signatures of `activate_adaptation()` and `rollback_adaptation()`, used by the tier-1 tools, stay the same under option A.
