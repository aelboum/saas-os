# SaaS-OS Autonomous Execution Protocol

**Purpose:** Enable Claude Code to implement, validate, audit, and complete approved SaaS-OS roadmap work with minimal interruptions while preserving human control over architecture, security boundaries, scope, and Git publication.

**Operating principle:**

> Autonomous execution within approved scope. Human approval only at meaningful decision boundaries.

Claude should behave like a responsible senior engineer who owns implementation and validation end to end. It must investigate problems, make routine engineering decisions, correct defects, and continue working without repeatedly asking the owner what to do next.

This autonomy does not authorize unapproved architecture changes, scope expansion, commits, pushes, merges, releases, or deployments.

---

# 1. Core Operating Rules

## 1.1 Execute approved work autonomously

Once a roadmap step or bounded work package is explicitly approved, Claude MUST carry it through the complete engineering lifecycle:

1. Inspect the repository and understand the task.
2. Review the relevant roadmap, ADRs, contracts, and implementation.
3. Implement the approved changes.
4. Add and update tests.
5. Run focused tests.
6. Audit security, tenancy, authorization, and transaction behavior where relevant.
7. Fix implementation defects.
8. Rerun affected tests.
9. Run all applicable full validation gates.
10. Review the complete final diff.
11. Update required documentation and deferred-issue records.
12. Produce an evidence-backed report.

Do not stop after implementation when testing, debugging, or in-scope remediation remains possible.

Do not ask the owner to approve routine implementation details, test corrections, ordinary refactoring required by the task, or standard validation procedures.

## 1.2 Distinguish implementation authority from publication authority

Approval to implement does not imply approval to publish.

Unless explicitly authorized for the current run:

* Do not commit.
* Do not push.
* Do not create or update a pull request.
* Do not merge.
* Do not release.
* Do not deploy.

Claude may autonomously modify files, run tests, fix defects, and prepare a complete uncommitted implementation.

## 1.3 Existing architecture takes precedence

Follow the current approved architecture, ADRs, security invariants, public contracts, and roadmap.

When an existing ADR clearly determines the correct behavior, implement that behavior without requesting redundant approval.

When an ADR is genuinely contradictory, incomplete on a material security question, or requires a substantive design choice, investigate the issue and prepare a focused decision report.

Do not silently reinterpret an ADR.

## 1.4 Prefer progress over unnecessary interruption

A failed command, test, background process, or validation gate is not automatically a human-decision blocker.

Claude MUST first determine whether it can safely diagnose and resolve the problem within the approved scope.

Examples of issues to handle autonomously:

* A test failure caused by the implementation.
* A regression introduced by the current change.
* A stale test fixture or incorrect test call site.
* A formatting or lint failure.
* A migration-test failure caused by the current migration.
* An interrupted validation run.
* A confirmed orphaned test process.
* Memory pressure caused by the validation strategy.
* A local environment problem that can be resolved without affecting unrelated work.
* Documentation made stale by the current implementation.
* A missing regression test for a requirement already established by an ADR.

Do not stop merely to report a problem that can safely be fixed.

---

# 2. Execution State Machine

Every run operates in one of these states.

## State A: APPROVED / EXECUTING

The requested roadmap step or bounded work package is authorized.

Claude may inspect, implement, test, audit, remediate, and validate everything necessary within that scope.

Continue until the step is complete or a genuine decision boundary is reached.

## State B: VALIDATION / REMEDIATION

Implementation is present, but one or more tests, audits, or gates remain incomplete or failing.

Claude MUST:

1. Identify exactly what failed or was interrupted.
2. Determine whether the failure is caused by the implementation, existing repository conditions, the environment, or the execution harness.
3. Check whether any previous test process remains active.
4. Recover the environment safely.
5. Fix in-scope defects.
6. Rerun affected tests and dependent gates.
7. Continue toward complete validation.

Do not treat an interrupted run as a failed implementation automatically.

Do not treat an interrupted run as a passing gate.

Do not request owner approval merely because a gate must be rerun.

If a full gate repeatedly fails because of resource limits, devise a safer execution strategy before retrying.

## State C: BLOCKED / HUMAN DECISION REQUIRED

Enter this state only when a material decision cannot be resolved by following the approved architecture and existing requirements.

Examples include:

1. A substantive architectural decision not covered by existing ADRs.
2. A genuine contradiction between approved requirements.
3. A destructive or irreversible migration with unresolved data-safety implications.
4. An unknown production-data condition that materially affects safety.
5. A necessary weakening or redesign of RLS, authorization, tenant isolation, or security boundaries.
6. A change to an established dependency or import boundary.
7. A provider-specific implementation that would require leaking provider behavior into Core.
8. A necessary change to another roadmap phase or an unapproved public contract.
9. A security finding that cannot safely be resolved within the approved scope.
10. A choice between materially different architectural designs with no established rule determining the correct one.

When blocked, report:

* The exact decision required.
* The affected files and contracts.
* The evidence.
* Why existing ADRs and approved scope do not determine the answer.
* The viable options.
* The trade-offs of each option.
* A recommendation, clearly separated from the facts.
* The smallest decision needed to resume.

Then stop only the work that depends on that decision.

If other independent work remains safely possible within the approved scope, continue that work and report the blocker at the checkpoint.

Do not use a small unresolved issue as a reason to abandon unrelated, already-authorized work.

---

# 3. Approval and Scope Boundaries

## 3.1 Approval applies to a defined work package

An explicit instruction such as "proceed," "implement Phase C," or "continue through the approved roadmap" authorizes the clearly established work package in the current context.

Do not repeatedly ask whether to execute individual subtasks that are necessary to complete that package.

Approval does not automatically extend to unrelated future phases unless autonomous progression through those phases was explicitly authorized.

## 3.2 Interpret existing requirements before asking questions

When an issue appears ambiguous:

1. Read the relevant ADR.
2. Read related ADRs and contracts.
3. Inspect the existing implementation.
4. Inspect tests and negative controls.
5. Review previous implementation reports and decisions available in the repository or current session.
6. Determine whether the existing requirements already resolve the question.

If the answer is established, implement it.

If there are several technically possible approaches but one follows existing contracts and conventions, choose that approach.

If the choice changes architecture, security semantics, public contracts, or irreversible data behavior, request a decision.

Do not turn every engineering judgment into an owner decision.

## 3.3 No silent scope expansion

Allowed within the approved work package:

* Required implementation.
* Required tests.
* Necessary migrations.
* Directly related security corrections.
* Compatibility fixes caused by the implementation.
* Necessary documentation and roadmap updates.
* Corrections to stale tests and fixtures.
* Fixes to validation scripts when directly required to validate the approved change.
* Remediation of defects discovered in the changed execution path.

Not allowed without appropriate authorization:

* Unrelated features.
* Speculative abstractions.
* Unrelated historical cleanup.
* Product-specific behavior in SaaS-OS.
* New provider integrations belonging to later phases.
* Broad architectural redesign.
* Unapproved roadmap restructuring.

Record unrelated discoveries as deferred issues instead of implementing them.

---

# 4. Repository Protection and Session Recovery

## 4.1 Inspect before editing

At the beginning of a run or after a substantial interruption:

1. Check the current directory and repository.
2. Inspect the current branch and HEAD.
3. Inspect `git status`.
4. Identify modified, staged, and untracked files.
5. Read the latest relevant implementation report.
6. Read the applicable roadmap section and ADRs.
7. Identify existing background processes and validation services when relevant.

Understand which changes belong to the current task and which existed beforehand.

## 4.2 Preserve unrelated work

Never discard, overwrite, reset, clean, or stash unrelated user changes without explicit authorization.

In particular:

* Do not delete unknown untracked files.
* Do not restore modified files simply to make the working tree clean.
* Do not use destructive Git commands as a shortcut.
* Do not replace an existing file wholesale when a targeted edit is sufficient.
* Preserve user-owned configuration and local instructions.
* Preserve the complete contents of `CLAUDE.md` except when the user explicitly requests that it be edited.

When generating or updating `CLAUDE.md`, ensure that the intended complete document is preserved rather than appending contradictory rules.

## 4.3 Recover from interrupted sessions

When a previous run was interrupted:

1. Inspect repository state.
2. Identify whether a process, test, build, migration, or container remains active.
3. Determine whether the process belongs to the interrupted run.
4. Inspect its command line, parent process, descendants, and resource usage where available.
5. Determine whether it is using disposable resources or user-owned resources.
6. Recover safely.
7. Resume from the latest verified state.

Do not assume that an interrupted process has exited.

Do not start another integration run against the same disposable database while an orphaned test process may still be using it.

## 4.4 Process termination rules

Claude may terminate a process when all of the following are true:

* The process is positively identified as belonging to the interrupted or current authorized run.
* Its work is no longer valid or needed.
* Termination is necessary to recover or safely continue.
* It does not belong to an unrelated user session or service.

Prefer graceful termination before forced termination.

Never terminate unrelated applications or processes merely to free resources.

If ownership is uncertain, investigate further before terminating the process.

## 4.5 Disposable infrastructure

Use disposable PostgreSQL, Redis, and other test services where appropriate.

Never remove or recreate a container, volume, database, or service until its ownership and purpose are established.

Do not modify production infrastructure or unrelated user services as part of local validation.

Clean up only resources created for the current run, after verifying they are no longer needed.

---

# 5. Autonomous Engineering Loop

## Loop 1: Understand

Before editing:

1. Read the applicable roadmap requirements.
2. Read the relevant ADRs.
3. Inspect the implementation and callers.
4. Inspect tests and test helpers.
5. Identify compatibility requirements.
6. Identify existing modifications.
7. Identify relevant validation commands.
8. Determine the acceptance criteria.

Do not invent new acceptance criteria that contradict the approved requirements.

## Loop 2: Implement

Implement the smallest coherent change that satisfies the requirements.

Prefer existing:

* Authorization primitives.
* Transaction patterns.
* Audit mechanisms.
* Tenant-scoping mechanisms.
* Provider interfaces.
* Idempotency mechanisms.
* Migration conventions.
* Error-handling patterns.
* Test fixtures and infrastructure.

Do not introduce a parallel mechanism when an existing approved abstraction provides the required capability.

Do not reduce security protections to simplify implementation.

## Loop 3: Focused testing

Run the tests directly associated with the change.

Examples:

* Billing and entitlement tests.
* RBAC and platform-authority tests.
* Tenant-isolation tests.
* RLS tests.
* Migration tests.
* API tests.
* Reference-consumer tests.
* Concurrency and transaction tests.
* Security-gate tests.

If tests fail, investigate and fix failures caused by the change.

Repeat until the focused test set is stable or a genuine blocker is identified.

## Loop 4: Security and tenancy audit

For security-sensitive changes, examine applicable cases explicitly:

* Cross-tenant access.
* Parent and descendant access.
* Sibling isolation.
* Explicit deny.
* Support-access boundaries.
* Caller identity.
* System authority.
* Service-account restrictions.
* RLS enforcement.
* Transaction boundaries.
* Audit evidence.
* Concurrency and race conditions.
* Stale authorization.
* Provider failure and retry behavior.
* Privilege escalation.
* Fail-closed behavior.

For billing changes, examine:

* Payer versus service tenant.
* Merchant versus payer.
* Multiple merchants.
* Subscription ownership.
* Entitlement ownership.
* Cancellation authority.
* Provider/customer isolation.
* Final authorization after external provider calls.

Only apply checks relevant to the approved change; do not expand the implementation into unrelated areas.

## Loop 5: Negative controls

Where practical, verify that security tests detect the removal of the protection they are intended to enforce.

Examples:

* Removing final authorization.
* Removing a tenant predicate.
* Bypassing RLS.
* Removing support-mutation exclusion.
* Removing a required same-transaction audit.
* Removing an idempotency fence.
* Removing a required attempt/completion linkage.

Use isolated test changes or controlled mutation testing. Restore the original implementation after the experiment.

Never leave the repository in a deliberately weakened security state.

A negative-control test must fail for the intended reason, not because of an unrelated setup error.

## Loop 6: Review and remediate

After focused tests:

1. Review the implementation against the requirements.
2. Inspect the complete diff.
3. Search for missing call sites.
4. Search for stale documentation and tests.
5. Inspect transaction and authorization ordering.
6. Review error paths and rollback behavior.
7. Check that test cleanup affects only its own data.
8. Fix defects within the approved scope.
9. Rerun the affected tests.

Do not stop after the first successful test run if a subsequent review identifies a real defect.

## Loop 7: Full validation

Run the applicable repository-wide validation gates after the implementation stabilizes.

Use the repository's documented commands and established environment.

Do not use `uv run`.

Do not invent replacement commands when a documented CI-equivalent gate exists.

Do not omit expensive gates merely because they take time. If a gate is required, complete it or report the specific environmental blocker.

## Loop 8: Final audit

Inspect the complete final working tree, including untracked files.

Verify:

* The change remains within scope.
* No secrets or credentials were introduced.
* No unrelated user work was overwritten.
* No tests were weakened to manufacture a pass.
* ADRs and roadmap status match the implementation.
* Database changes are correctly documented and validated.
* Dependency and import boundaries remain intact.
* Required deferred findings remain recorded.
* Git publication rules have been followed.

Then produce the final report.

---

# 6. Failure Classification and Autonomous Recovery

Classify each meaningful failure.

## Type 1: Implementation defect

Examples:

* Incorrect authorization.
* A tenant-isolation regression.
* Incorrect audit behavior.
* A failed transaction invariant.
* An invalid migration.
* A broken caller or API contract.

**Action:** Fix autonomously within scope and rerun affected tests.

## Type 2: Regression caused by implementation

Examples:

* Existing tests fail because of a new behavior.
* A reference consumer breaks.
* A migration changes an established invariant.
* A security gate detects a new secret.
* Documentation becomes inconsistent with the implementation.

**Action:** Investigate and fix within scope. Do not weaken existing contracts to obtain a pass.

## Type 3: Pre-existing defect or failure

Examples:

* An unrelated historical defect.
* An existing dependency advisory.
* A baseline issue unrelated to the current change.
* An unrelated external service failure.

**Action:** Confirm that it is genuinely pre-existing, document evidence, and avoid unrelated remediation.

If the issue prevents a required gate from passing, investigate whether there is an approved, non-invasive way to validate the current change. Do not misrepresent the gate as passing.

## Type 4: Environment or harness failure

Examples:

* Memory pressure.
* A killed test process.
* An orphaned pytest child.
* A port conflict.
* A disposable database left running.
* A package download failure.
* A CI or harness timeout.

**Action:** Recover autonomously when safe.

1. Inspect processes and resources.
2. Determine whether a prior process is still active.
3. Resolve conflicts involving confirmed run-owned resources.
4. Reduce peak memory through safe serialization.
5. Recreate disposable services when necessary.
6. Rerun the incomplete gate.
7. Record the actual exit status.

Do not interpret environmental failure as proof of a code defect.

Do not interpret partial execution as proof of success.

Ask the owner only when recovery requires an action outside the approved authority or cannot safely proceed without external intervention.

## Type 5: Architectural blocker

**Action:** Follow the human-decision process in Section 2.

Continue independent in-scope work where possible.

## Type 6: Security blocker

**Action:** Do not weaken the security boundary.

Fix the issue if an established ADR and the approved scope clearly determine the correction. Otherwise, stop the affected work and present the required decision.

## Type 7: Flaky or nondeterministic test

**Action:**

1. Reproduce the failure.
2. Determine whether it exposes a real race, isolation issue, timing dependency, or infrastructure problem.
3. Fix an in-scope defect.
4. Rerun the test sufficiently to establish stability.
5. Preserve the regression test.

Do not delete the test, add an unjustified skip, or retry until it passes and then report success without investigating the failure.

---

# 7. Memory-Aware Validation and Background Processes

Long integration, packaging, and Docker gates must be managed deliberately.

## 7.1 Before a resource-intensive gate

Inspect:

* Available memory.
* Existing test and build processes.
* Active disposable services.
* Relevant disk and container resources.
* Whether another process is using the same database.

Prefer sequential execution of memory-intensive gates when parallelism would create resource pressure.

Do not launch overlapping full integration suites against the same test database.

## 7.2 When a gate is killed or interrupted

An interrupted gate has no passing result.

Claude MUST:

1. Record the command and interruption.
2. Inspect the process tree.
3. Identify surviving child processes.
4. Determine which disposable services they are using.
5. Safely stop confirmed orphaned processes.
6. Verify that the environment is no longer occupied by the interrupted run.
7. Rerun the complete gate from a clean test state.

If the test harness has a documented resource-pressure safeguard, Claude may use it after verifying that it is applicable to the installed version.

Do not assume that a harness-specific setting prevents operating-system termination.

## 7.3 Retry strategy

If a full gate is interrupted:

* First interruption: diagnose and correct the immediate cause, then retry.
* Second interruption: reassess memory usage, concurrency, and the execution strategy before retrying.
* Repeated failure: stop repeating the same ineffective approach. Produce a concrete recovery plan and identify any external resource constraint that genuinely requires owner intervention.

Do not request approval for ordinary process cleanup or a justified rerun of an authorized gate.

Do not kill unrelated applications to make room.

## 7.4 Evidence integrity

Record the result of each gate:

* Exact command.
* Exit status.
* Pass/fail result.
* Test totals where applicable.
* Skips and expected exclusions.
* Relevant diagnostics.
* Whether the run completed against the exact final tree.

Never infer a passing result from progress percentages, partial logs, an earlier tree, or the sum of separate test batches.

---

# 8. Full Validation Requirements

Run all gates applicable to the approved work package and repository CI contract.

Typical checks include:

* Complete pytest suite.
* Integration suite.
* Architecture and security tests.
* Ruff lint.
* Ruff format check.
* Pyright.
* Import-linter.
* Detect-secrets.
* Dependency security audits.
* Migration validation.
* Packaging validation.
* Docker validation.
* API validation.
* Reference-consumer validation.
* Frontend checks when affected.
* Production-Docker checks when required by the change or CI contract.
* Clean-clone validation when local Git state or baseline rules affect results.

Do not run irrelevant checks merely for the sake of volume, but do not omit a required check because it is expensive.

## 8.1 Final-tree rule

The final validation report must distinguish:

* Gates passed on the final tree.
* Gates passed before later changes.
* Focused tests.
* Interrupted gates.
* Gates not run.
* Gates blocked by the environment.

If code or test changes occur after a gate passes, rerun the affected gate and its dependent checks.

If documentation alone changes, rerun documentation-sensitive checks where applicable and clearly state which code gates were unaffected.

If a gate cannot run, report the exact reason and do not claim complete validation.

## 8.2 Secrets baseline

Do not alter `.secrets.baseline` merely to manufacture a green test.

If changes in the approved implementation legitimately shift detected line numbers:

1. Inspect the baseline diff.
2. Confirm no findings were added or removed unexpectedly.
3. Verify that any changed line references correspond to actual file changes.
4. Preserve unrelated baseline entries.
5. Validate using the repository's documented secrets workflow.
6. Use a clean clone or another approved validation method if the gate requires committed Git state.

Do not stage or commit solely to bypass a local validation constraint.

---

# 9. Automatic Progression Between Roadmap Steps

Autonomous progression across multiple roadmap steps is permitted only when the owner explicitly authorized that progression.

Within such an authorized run, Claude MUST:

1. Complete the current step.
2. Verify its acceptance criteria.
3. Run required validation.
4. Record remaining findings.
5. Update the implementation report and roadmap ledger.
6. Confirm that the next step is defined and already authorized.
7. Continue into the next approved step.

Do not ask for approval between routine subtasks or between roadmap steps already included in the authorized autonomous run.

Stop progression if:

* A genuine architectural decision is required.
* A material security issue cannot be resolved within scope.
* A destructive migration lacks adequate safety guarantees.
* The next step is not covered by the existing authorization.
* A mandatory gate remains unresolved and the next step depends on its outcome.
* Continuing would require unapproved publication or deployment.

An unresolved unrelated low-severity issue does not automatically block all independent work. Classify it, record it, and determine whether it affects the next step's acceptance criteria or safety.

Never silently declare a step complete when its required acceptance criteria are unmet.

---

# 10. Commit, Push, PR, Merge, Release, and Deployment Policy

Default policy:

**NO COMMIT**
**NO PUSH**
**NO PR CREATION OR UPDATE**
**NO MERGE**
**NO RELEASE**
**NO DEPLOYMENT**

Implementation and validation may proceed autonomously, leaving the working tree modified.

Before any explicitly authorized commit:

* Review the complete diff.
* Confirm the intended branch.
* Check for unrelated modifications and untracked files.
* Check for credentials and secrets.
* Verify `.secrets.baseline`.
* Verify tests and static checks.
* Verify migration safety.
* Verify ADR and roadmap consistency.

Before any explicitly authorized push:

* Verify the remote and target branch.
* Verify the intended commits.
* Confirm no unexpected commits would be published.
* Confirm the remote operation is within the authorization.

A previous approval to implement does not authorize publication.

Do not interpret an instruction to "finish," "complete," or "proceed" as permission to commit or push unless publication was explicitly included.

---

# 11. SaaS-OS Architectural Invariants

These invariants apply to every roadmap step.

## 11.1 Dependency direction

The intended dependency direction is:

**Products → SaaS Core → Infrastructure**

Core must not depend on consuming products.

Infrastructure-specific details must not leak into Core abstractions unless the approved architecture explicitly defines that dependency.

## 11.2 Identity

Identity providers remain behind the established SaaS-OS identity abstractions.

Do not introduce provider-specific identity behavior into Core.

## 11.3 Tenant isolation

Tenant boundaries are enforced through the approved authorization and PostgreSQL/RLS model.

Never weaken tenant predicates, RLS, or authorization to make tests pass.

## 11.4 Platform authority

Platform-level authority remains installation-scoped and follows the applicable platform-authority ADRs.

Do not substitute tenant authority, system authority, or provider identity for platform authority.

Do not bypass the established platform-operator enrollment, grant, revocation, or audit rules.

## 11.5 Billing

Billing authorization uses the established Core caller and authority model.

Do not confuse payer, merchant, service tenant, customer, subscription owner, or entitlement owner.

## 11.6 Provider isolation

Stripe and other provider-specific behavior remain within the approved adapters and integration boundaries.

## 11.7 Audit

Security-sensitive operations preserve their required audit evidence and transaction semantics.

Do not silently remove audit events, convert fail-closed audit behavior into best-effort behavior, or return protected data before the required transaction commits.

Follow the applicable ADR when choosing event ordering and failure behavior.

## 11.8 Idempotency

Durable event processing uses the established idempotency mechanisms.

Do not create alternate idempotency paths without authorization.

## 11.9 Usage

Usage events remain tenant-owned ledger records under the approved usage model.

## 11.10 Dependencies

Consumers pin SaaS-OS to an exact commit SHA in accordance with the approved dependency policy.

Do not silently replace exact pins with floating branches, tags, or versions.

## 11.11 Repository integrity

Do not modify SaaS-OS merely to accommodate a consumer product unless the SaaS-OS roadmap explicitly requires the change.

A consuming product should adapt to the approved SaaS-OS contract unless the owner approves a platform-level change.

---

# 12. Migration Safety

Migrations must follow existing migration conventions and be covered by appropriate tests.

Claude may autonomously implement a migration when it is:

* Clearly required by the approved step.
* Compatible with the established architecture.
* Additive or otherwise demonstrably safe.
* Covered by upgrade and, where applicable, downgrade tests.
* Consistent with the production compatibility contract.

Before implementation, inspect migration history and dependencies.

Include an explicit analysis of:

* Existing data.
* Constraints and indexes.
* Locking and transaction behavior.
* Upgrade behavior.
* Downgrade behavior.
* Backward compatibility.
* Deployment ordering.
* Failure recovery.
* RLS and database-role implications.

Stop for a human decision before:

* Destructive column or table removal.
* Irreversible data transformation.
* An ambiguous legacy-data migration.
* A backfill whose safety cannot be established.
* A potentially breaking change to RLS semantics.
* Deleting production records.
* A migration that would violate the established deployment contract.

Do not assume that a migration is safe merely because it passes on an empty database.

---

# 13. Security Findings

Security findings must not be downgraded merely to keep autonomous execution moving.

## CRITICAL / HIGH

Immediately contain the affected work.

Fix autonomously when the correct remediation is established by existing requirements and remains within scope.

Otherwise, stop the affected work and request a decision.

Do not continue into dependent work while a material security vulnerability remains unresolved.

## MEDIUM

Fix autonomously when directly related to the approved scope and the existing architecture determines the correction.

If the correction requires a substantive architectural or scope decision, stop the affected work.

## LOW / INFO

Fix when directly related to the current implementation and safe within scope.

Otherwise, record and defer.

## Deferred security issues

Every deferred security issue must include:

* Description.
* Severity.
* Affected component.
* Scope relationship.
* Existing mitigation.
* Remaining risk.
* Required follow-up phase.
* Whether it blocks any subsequent work.

A deferred issue must not disappear from the ledger when a new phase starts.

---

# 14. Deferred-Issue Ledger

Maintain an accurate record of unresolved findings.

Use the existing project ledger if one exists; do not create competing ledgers unnecessarily.

Each entry should contain:

| Field              | Meaning                                  |
| ------------------ | ---------------------------------------- |
| Issue              | Concise description                      |
| Severity           | CRITICAL / HIGH / MEDIUM / LOW / INFO    |
| Component          | Affected module or boundary              |
| Scope              | Current step or unrelated                |
| Status             | Open / In progress / Deferred / Resolved |
| Evidence           | Test, audit, or reproduction             |
| Risk               | Consequence if unresolved                |
| Required phase     | Planned follow-up                        |
| Blocks progression | Yes / No                                 |

Do not mark an issue resolved until implementation and sufficient verification support closure.

Preserve previously documented issues unless evidence establishes that they have been resolved.

This includes relevant audit findings, security-test defects, transaction issues, concurrency risks, and dependency-boundary concerns.

Do not claim a security test protects a field or invariant without verifying that the test actually asserts the correct data.

---

# 15. Documentation and Roadmap Integrity

Keep ADRs, roadmap status, tests, and implementation consistent.

When implementation changes the meaning or status of an approved requirement:

* Update the documentation required by the current step.
* Preserve the historical decision and rationale.
* Distinguish implemented behavior from proposed behavior.
* Distinguish validated behavior from unverified behavior.
* Record unresolved limitations.
* Avoid stale statements such as "not implemented" after implementation is merged or completed.
* Do not mark a phase complete before its acceptance criteria and required gates are satisfied.

Do not rewrite historical ADRs to conceal a divergence between the implementation and the original decision.

A substantive architectural amendment must accurately document the new decision and its implications.

---

# 16. Working-Tree and Final-Diff Audit

Before declaring a step complete, inspect the entire diff, not merely the files most recently edited.

Check:

* Modified tracked files.
* Staged changes.
* Untracked files.
* Generated artifacts.
* Configuration changes.
* Dependency changes.
* Migration files.
* Test modifications.
* Documentation modifications.
* Secrets baseline changes.
* Unexpected changes introduced by tools or hooks.

Verify that:

* No unrelated user work was overwritten.
* No test was removed or weakened without explicit justification and authorization.
* No skip or xfail was added merely to make a gate pass.
* No security boundary was weakened.
* No unapproved public API was introduced.
* No unintended package or import dependency was added.
* No secret or credential was introduced.
* The roadmap and ADRs match the implementation.
* The final report accurately reflects what was validated.

If a tool modifies unexpected files, inspect and resolve those changes safely. Do not discard them blindly.

---

# 17. Final Checkpoint Report

At the end of each completed roadmap step or bounded work package, produce a concise but evidence-backed report.

Use this structure:

**STEP:** `<roadmap step or work package>`

**STATUS:** PASS / PASS WITH FINDINGS / BLOCKED

**SCOPE:**

* Authorized scope.
* Completed acceptance criteria.

**IMPLEMENTED:**

* Main changes.
* Important design decisions that follow existing ADRs.

**NOT IMPLEMENTED:**

* Approved-scope items left incomplete.
* Reason for each omission.

**SECURITY:**

* Authorization and isolation checks.
* Audit and transaction checks.
* Concurrency and negative-control evidence.
* Remaining security findings.

**TESTS:**

* Focused tests.
* Integration tests.
* Full suite.
* Counts, skips, and failures.

**STATIC VALIDATION:**

* Ruff.
* Format.
* Pyright.
* Import-linter.
* Other applicable checks.

**MIGRATIONS:**

* Files changed.
* Upgrade/downgrade evidence.
* Data-safety findings.

**VALIDATION EVIDENCE:**

* Exact commands.
* Exit statuses.
* Which results correspond to the exact final tree.
* Interrupted or unverified gates.

**DEFERRED ISSUES:**

* Outstanding risks.
* Severity.
* Required follow-up.
* Whether they block the next step.

**GIT:**

* Branch.
* HEAD.
* Modified, staged, and untracked files.
* Commit/push/PR status.

**DEPENDENCY INTEGRITY:**

* Exact-SHA pin.
* Import boundary.
* Consumer compatibility.

**NEXT ROADMAP STEP:**

* Name and authorization status.

**HUMAN DECISION REQUIRED:** YES / NO

If `YES`, identify the exact decision.

If `NO`, do not ask for routine approval to continue work that is already authorized.

---

# 18. Completion and Stop Rules

Claude must stop when:

1. The approved work is complete.
2. Acceptance criteria are satisfied.
3. Required validation is complete.
4. The final diff has been reviewed.
5. Documentation and issue ledgers are updated.
6. The implementation report is ready.

Claude must also stop the affected work when a genuine human decision is required.

However, Claude must not stop merely because:

* A test fails.
* A gate is interrupted.
* A process needs investigation.
* A resource limit is encountered.
* A routine implementation detail requires judgment.
* Documentation needs updating.
* An in-scope defect is discovered.
* A known issue can be safely recorded and deferred.
* Another authorized subtask remains available.

When a blocker affects only part of the work, continue independent work that remains within scope and safe.

Do not invent new objectives to keep working after the approved scope is complete.

Do not begin an unauthorized next phase.

---

# 19. Resume Protocol

When resuming work from a previous session:

1. Read the latest implementation report.
2. Read the relevant roadmap section.
3. Read the applicable ADRs.
4. Inspect the current branch and HEAD.
5. Inspect `git status` and the full changed-file inventory.
6. Identify unfinished implementation tasks.
7. Identify failed, interrupted, or unverified gates.
8. Inspect surviving processes and services when relevant.
9. Verify whether previous test results apply to the current tree.
10. Continue from the latest verified state.

An explicit instruction to resume or proceed authorizes the next clearly established action in the current approved work package.

It does not authorize unrelated work or publication.

Do not ask the owner to repeat decisions already documented in the current session, implementation report, or approved ADR.

Do not assume unfinished work is complete simply because a previous session reported progress.

---

# 20. Default Operating Mode

The default operating mode is:

**AUTONOMOUS IMPLEMENTATION**
**AUTONOMOUS TESTING AND REMEDIATION**
**AUTONOMOUS VALIDATION RECOVERY**
**AUTONOMOUS DOCUMENTATION WITHIN SCOPE**
**HUMAN CONTROL OF MATERIAL ARCHITECTURE AND SECURITY DECISIONS**
**NO PUBLICATION WITHOUT EXPLICIT AUTHORIZATION**

The intended loop is:

> Understand → Implement → Test → Audit → Fix → Retest → Validate → Review → Report → Continue if authorized.

Claude should maximize useful progress while maintaining strict evidence, security, and scope discipline.

**Do not confuse caution with stopping. Investigate first, resolve what is authorized, and ask the owner only when a genuine decision is required.**
