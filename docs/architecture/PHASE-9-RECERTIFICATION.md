# Phase 9 re-certification

Date: 2026-10-21. Authorized by the repository owner the same day ("my go for all points left"), closing the deferred item "Phase 9.1–9.9 self-learning not re-certified against its recovered specification" (`docs/P-ROADMAP.md`, ledger and P8 blocker 8c).

## Standard and method

The original Phase 9 acceptance criteria are not recoverable. The standard is the recovered specification in `docs/IMPLEMENTATION-ROADMAP.md`, section "Phase 9 — Self-Learning / Continuous Improvement": objectives, non-goals, security and audit requirements, and module locations, including the passages marked "recovered, verbatim".

For every recovered requirement of 9.1–9.9 the implementing code under `saas_os/control_plane/self_learning/` and the tests under `tests/control_plane/self_learning/` were read. A requirement counts as **met** only when the code implements it and a test body asserts it. A test that merely runs the code does not count. Verdicts:

- **Met**: code and an asserting test.
- **Met, untested**: code, but no asserting test.
- **Not met**: the code does not do what the specification says.
- **Not verifiable**: the specification is too vague, or the text is unrecoverable.

## Result

66 requirements across 9.1–9.9.

| Verdict | Count | Notes |
|---|---|---|
| Met | 51 | |
| Met, untested | 4 → 0 | Asserting tests added the same day (below) |
| Not met | 2 | 9.5 evidence source; 9.7 input provenance (partial) |
| Not verifiable | 9 | The acceptance criteria of each sub-phase, unrecoverable |

No default-deny bypass, no cross-tenant access and no grant of authority was found. Tier 3 is refused both by the Policy Gate evaluator and by the decision type's constructor. Tables exist only where the specification allows persistence:

- 9.4 adaptations: migration `582f6b7865e7`.
- 9.6 experiments: migration `c0804e84948b`.
- 9.8 canaries: migration `426db78eb60f`.

Each of these is tenant-owned under `tenant_rls_statements()`. 9.1–9.3, 9.5, 9.7 and 9.9 define no table.

### Per sub-phase

| Sub-phase | Met | Untested → covered | Not met | Main evidence |
|---|---|---|---|---|
| 9.1 Package and schema | 3 | — | — | `test_self_learning_ownership.py`; import-linter forbids Core → self-learning |
| 9.2 Learning Authorization | 7 | — | — | `test_learning_authorization_unit.py` and `_integration.py`: default deny, same-tenant ALLOW provenance, exact cross-tenant policy, one audit row per decision |
| 9.3 Evaluation | 6 | 2 (no table; no database access) | — | `evaluation/` tests: benchmark mismatch is INVALID, a regression never passes |
| 9.4 L1 Adaptive learning | 7 | — | — | Allowlist of seven surfaces; activation through tier-1 approval; FORCE RLS |
| 9.5 L2 System learning | 7 | — | 1 | Proposals are data, never applied; the target type is closed |
| 9.6 Experimentation | 6 | — | — | Zero production-binding effect; INVALID marks the experiment failed |
| 9.7 Policy Gate | 4 | 1 (never activates) | 1 (partial) | Default deny, tiers 0–3, tier 3 always refused |
| 9.8 L3 Canary | 6 | — | — | Tier 2 only; fresh authorization at start and rollback (CP-03) |
| 9.9 Continuous loop | 5 | 1 (zero mutations) | — | Kill switch denies by default; cross-tenant seeds never leak |

### Tests added

`tests/control_plane/self_learning/test_phase9_recertification_structure.py` reads imports with `ast`, recursively over each package:

- 9.3: `evaluation/` imports neither `sqlalchemy` nor `saas_os.infra.db` and defines no `__tablename__`.
- 9.7: `policy_gate/` imports no service that changes learning state (`adaptive.service`, `experiments.service`, `autonomous_improvement.service`).
- 9.9: `continuous_loop/` imports none of those, nor `policy_gate.service`.

Negative control: one planted forbidden import in each package made the matching test fail (3 failed); the plants were removed.

## Not met

1. **9.5, evidence source.** The specification says recurring-failure evidence "is read through `core.audit_log`'s `list()`". The implementation takes observations from the caller (`system_learning/service.py`, around lines 109–113). Its own docstring (`system_learning/__init__.py`, lines 59–62) repeats the specification's claim. There is no second store either way, so this is a divergence between documentation and implementation, not a security defect. Either the service reads the audit log as specified, or the specification and docstring are corrected. That is an owner decision; it is recorded in the ledger.
2. **9.7, input provenance (partial).** The specification says inputs from 9.2–9.6 are "consumed only as an already-authoritative typed input". The gate verifies the provenance of the learning-authorization decision (`policy_gate/service.py`, around lines 212–221). It trusts an `EvaluationComparison` and an `ApprovalRequest` on their fields alone (around lines 142–166). See finding S1.

## Security findings

| Id | Severity | Finding | Mitigation today |
|---|---|---|---|
| S3 | MEDIUM | Every persisted self-learning change commits in `tenant_session_scope` and then audits with `record()` in a second transaction. This covers adaptation activation and rollback (`adaptive/service.py`, `activate_adaptation`), experiments and canaries. If the audit write fails, the change stays committed with no audit row. `start_canary` spans three transactions, so a failure between them can leave an adaptation ACTIVE while its canary is still CONFIGURED. ADR-0031's same-transaction rule (`record_in_transaction`) is written for Core and does not cover the control plane, so this is not an ADR violation, but it falls short of the audit-completeness standard Core meets. Options and a recommendation: `CONTROL-PLANE-AUDIT-DECISION-BRIEF.md` (2026-10-30). | None in code. The audit failure is raised, not swallowed |
| S1 | LOW | The Policy Gate's audited entry point verifies only learning-authorization provenance. An in-process caller with a hand-built PASS `EvaluationComparison`, or an unpersisted `ApprovalRequest`, gets a genuine audited ALLOW. | `start_canary` rebuilds the comparison from the database, and `activate_adaptation` re-reads status and PASS, so forged inputs reach no activation. The remaining impact is on the audit evidence |
| S2 | LOW | `create_canary` checks the status fields of caller-supplied `Experiment` and `Adaptation` objects without re-reading them, so a canary row can be created from an in-memory forgery. | Activation is still blocked by the database check in `activate_adaptation` |
| S4 | LOW | `withdraw_system_learning_proposal` accepts any in-memory proposal without a provenance or open-tenant check, so it can write spurious `learning.proposal_state_changed` rows. | Grants no authority |
| S5 | INFO | `activate_adaptation` and `rollback_adaptation` perform no approval check themselves; tier-1 enforcement lives in the orchestration tool path. | The canary path calls them deliberately, behind the tier-2 gate |
| S6 | INFO | The "no forbidden helper" tests compare exact public names, so a helper named, say, `deploy_candidate` would pass them. | The new structural tests cover the 9.7 and 9.9 boundaries by import instead |
| S7 | INFO | The 9.2 docstring and the roadmap say request evidence is "never read". It is read for type and presence validation, which can only produce a deny. | — |

## Conclusion

Phase 9 is **re-certified with findings** against its recovered specification. Every security-relevant boundary the specification states holds and is asserted:

- default deny
- tenant isolation
- tier limits
- no authority grant
- no production-binding effect before 9.8

The two "not met" items and the findings above are recorded in the deferred-issue ledger, with S3 as the one MEDIUM item. None blocks other work.
