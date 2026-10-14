# P Roadmap — Reusability

Status: three runs on 2026-10-11. **Run 3** (security remediation and the full final-tree validation) is recorded under "Run 3" below and supersedes run 2's validation table and its two open MEDIUM findings. Earlier text:  two runs on 2026-10-11. **Run 1** (authorized as P1–P8 with two reserved decisions) prepared the decisions and built the scaffold; its record is the per-phase "Outcome" entries below. **Run 2** (after the repository owner approved ADR-0038, ADR-0040, ADR-0041, ADR-0042 and confirmed ADR-0039) implemented them; its record is "Run 2" directly below, which supersedes any earlier "BLOCKED" or "awaiting decision" wording. Created from the eight gaps of the SaaS-OS reusability audit of 2026-10-11 (HEAD `4fccc93`, branch `tier2/tls-validation-infrastructure`). Nothing in either run is committed. It does not replace `docs/IMPLEMENTATION-ROADMAP.md`: Phases 0–9 there keep their own status, and every item that roadmap defers stays deferred (see "Deferred issue ledger").

The question this roadmap answers is narrow: **can an independent product, in its own repository, be built on SaaS-OS without modifying SaaS-OS?** No real product exists on top of the platform yet (ADR-0015 rule 12 keeps products out of this repository), so every phase below is validated against fixtures and clean environments, never against a product.

Every phase follows the template of `docs/IMPLEMENTATION-ROADMAP.md`: Objective, Files/Modules Affected, Dependencies, Tests, Security Requirements, Acceptance Criteria, Rollback Strategy, Outcome.

Status labels: **PASS** (all required checks ran and passed), **PASS WITH LIMITATIONS** (no known blocking defect; named checks unverified), **BLOCKED** (a decision, dependency or environment capability is missing), **FAIL** (an acceptance criterion is unmet).

## Execution boundaries

- No commit, push, tag, release, deployment or pull request. Nothing is staged.
- Pre-existing working-tree changes are preserved: `.secrets.baseline` (modified; damaged and restored in run 1, see P8) and `CLAUDE.md` (untracked). Run 2 did not touch either; the baseline's SHA-256 is `2d9dcb80…1cc474` before and after.
- **Reserved decision A — Python package namespace**: decided 2026-10-11 (ADR-0038, Option B) and implemented in run 2.
- **Reserved decision B — public HTTP API contract**: decided 2026-10-11 (ADR-0040, Option B) and implemented in run 2 for the scoped stage-1 set. Tenant lifecycle, invitation accept, API-key request authentication and the inbound billing webhook stay blocked on their own prerequisites.
- External product repositories and existing consumer pins were not modified.
- `CLAUDE.md` governs: scope firewall, migration gate, security-finding severity rules, deferred issue ledger.

## Baseline (2026-10-11, before any change)

| Check | Result |
|---|---|
| `ruff check .` / `ruff format --check .` | clean (650 files) |
| `pyright` | 0 errors |
| `lint-imports` | 13 contracts kept, 0 broken |
| `pytest` (default, hermetic) | 2526 passed, 89 skipped, 2 failed |
| Integration suite (`pytest -m integration`), packaging, Docker, frontend | not run at baseline |
| CI on HEAD | none — the last CI run is 2026-09-26 (`b126f1a`, `main`); 15 later commits are pushed to the branch with no pull request, and CI triggers only on `main` pushes and pull requests |

Baseline failures (pre-existing, Type 3 under `CLAUDE.md` §4, not caused by this roadmap):

- `tests/architecture/test_secrets_gate.py::test_clean_repository_gate_succeeds`
- `tests/architecture/test_secrets_gate.py::test_approved_false_positive_remains_accepted`

Both report "Your baseline file (.secrets.baseline) is unstaged". The cause is the uncommitted `.secrets.baseline` modification (line-number shifts only) already present in the working tree. Staging or committing it is outside this roadmap's authorization.

The 89 skips are 88 Caddy/openssl-dependent tests in `tests/architecture/test_identity_proxy_routing.py` and one POSIX-permission test.

## Dependency order

```
P1 (decision prep) ──┐
P2 ──▶ P3 ───────────┼──▶ P8 (certification)
P4 (decision prep) ──┤
P5, P6, P7 ──────────┘
```

P2 precedes P3 because the scaffold reuses the installation proof. P1 and P4 produce decisions and block only their own implementation halves. P5–P7 are independent. P8 runs last.

---

## Example pins moved to `3677c86` (2026-10-14)

Authorized by the repository owner. Both example manifests moved from `58d134f` to `3677c861a024985654019c7f0fa47e6cf1adbfe4`, `main` after pull request #21: ADR-0045 Phases B to F merged (#9, #13, #15, #17, #18, #19, with their documentation follow-ups) and the execution protocol committed (#21).

- **Why.** Since ADR-0045 Phase C, `create_tenant`, `transition_tenant_status`, `move_tenant` and the feature-flag mutations take a required `caller`. Both examples were updated for it in the same pull requests and pass against the working tree, but code that passes a caller does not run on `58d134f`, so the pin named a commit the examples could not use.
- **Classification.** `saas-os-update check --candidate 3677c86`, run on a copy of each example in a repository of its own (the tool requires the consumer to be a repository root): `REVIEW_REQUIRED` for both, with authorization, public API, tenancy and RLS, migration, billing, architecture and toolchain paths changed. That is the expected answer for this change. The review is the record of the pull requests above, each of which passed an independent review, the full local gates and all seven CI checks; so, as in run 7, the manifests were edited to the reviewed commit rather than by `saas-os-update update`, which applies only `SAFE` candidates.
- **Proofs.** `tests/test_consumer_pins_unit.py` (exact 40-character SHA, parsed by the update tool's own parser), and the wheel-based scaffold and reference-consumer integration tests, which prove the code as it is now.
- **Pinned-commit proof (manual, Windows, 2026-10-14).** `pip install "saas-os @ git+https://github.com/aelboum/saas-os@3677c86..."` into a new Python 3.13 virtual environment outside the repository; `direct_url.json` records commit `3677c861a024985654019c7f0fa47e6cf1adbfe4`. From that install: `saas_os` imports from the installed package; the platform-admin router builder exists with 27 routes; `create_tenant` requires a caller; `stripe` and `boto3` are absent without extras. The reference consumer's own end-to-end driver (the text of `tests/test_reference_consumer_integration.py`), run from a copy of the fixture outside the repository on that install, against a new disposable PostgreSQL 16 and Redis 7, exited 0 and printed `REFERENCE_CONSUMER_OK`: both migration histories applied, the tool ran, and the route served an authorized member.

## Run 7 (2026-10-12) — release: ruff pin, merge, example pins

Authorized by the repository owner: pin ruff, merge pull request #6, move the example pins to the merged commit.

- **Ruff pinned.** The `dev` extra names `ruff==0.17.0` instead of `ruff>=0.6`. CI had picked up 0.17.0 while local environments held 0.16.x, and an untouched file failed `ruff format --check`. Commit `ef31d29`; all seven CI jobs passed on it.
- **Published.** Pull request #6 was merged into `main` with a merge commit, on the head that CI had passed (`ef31d29`): merge commit `58d134ff12afdb28e9edd0309f2b1d4b5bc0bd49`. Its tree is identical to that head.
- **Example pins moved.** `examples/reference-consumer` and `examples/consumer-scaffold` pin `58d134f`; the stale-pin notices are removed. `saas-os-update check` classifies the move from `4fccc93` as `REVIEW_REQUIRED` (authorization, migrations, tenancy, billing and public API all changed), as it should; the owner's approval is that review, so the manifests were edited by hand rather than with `saas-os-update update`.
- **Pinned-commit proof (manual, Windows, 2026-10-12).** `pip install "saas-os @ git+https://github.com/aelboum/saas-os@58d134f…"` into a new virtual environment outside the repository; `direct_url.json` records that commit. From that install: the five `saas_os` roots import and no old top-level package exists; `stripe` and `boto3` are absent, and present after installing `saas-os[all]` from the same commit; the opt-in routers, the worker seam and `build_platform_app` import; a product job registers through `register_tenant_job`; `saas-os-migrate upgrade head` applies the platform migrations to a fresh PostgreSQL; and the reference consumer, copied outside the repository, passes the same end-to-end driver `tests/test_reference_consumer_integration.py` runs (its own migrations, its tool, its permission-gated route, a 401 for an anonymous request). Not repeated in CI: it needs network access to the repository.

A manifest cannot name the commit it belongs to, so each example pin trails the examples by at least one commit; CI keeps proving the current code against a wheel built from the working tree.

---

## Run 6 (2026-10-11) — hierarchy-wide administrator rule, applied exception, baseline, publication

Authorized by the repository owner the same day, including the decisions run 5 left open: close B13, apply the `braces` exception, replace and commit the secrets baseline, commit and publish.

### Administrator rule across the tenant hierarchy (B13 — closed)

Decision and design: ADR-0043, extended. The invariant is now: after every supported change, each tenant that had an administrator still has one. All eight scenarios demonstrated in run 5 are refused with `LastTenantAdministratorError`, which names the tenant that would be emptied:

| Scenario | Now |
|---|---|
| Parent: remove a SUBTREE role, revoke its permission, suspend the member, revoke a SUBTREE delegation, SUBTREE deny | Refused while it would empty a descendant; allowed once that descendant has an administrator of its own |
| `move_tenant` (away from the parent the authority came from, or under a parent that denies it) | Refused; the ancestry change is rolled back |
| Suspending or closing a parent tenant | Refused for the sake of a descendant; the tenant itself is exempt |
| A delegation of `membership_role:create` with an expiry | Never counted as the administrator a tenant may be left with, so the last non-expiring administrator cannot be removed |

How: the guard (`saas_os/core/rbac/administrators.py`) judges the mutation's tenant and every descendant in which an affected user is an active member; `move_tenant` and `transition_tenant_status` judge the moved subtree, respectively the descendants. Per-tenant advisory locks are taken ancestor first, before the tenant-row locks. `can()` gained one optional argument, `ignore_expiring_delegations` (default `False`, passed only by the guard). No migration, no role hierarchy, no change to any authorization decision.

Behaviour change to note: a parent tenant, and an operator moving or suspending a tenant, can now be refused. The remedy is in the error — give the named tenant an administrator of its own first.

Evidence: `tests/core/rbac/test_last_administrator_hierarchy_integration.py`, 47 tests, with the two earlier files 104 in total; five cross-tenant races, 28 runs, each ending with an administrator.

**Found by CI, fixed:** the first CI run of these tests hit a deadlock once, in the race between a parent's deny and a child's deny. The invariant held (PostgreSQL failed one transaction) but a caller would have received a database error. Cause: `create_deny` locked the denied user's row before the administrator locks of the tenants it reaches. The order was reversed; a test now forces that interleaving and fails with the old order. Two narrower deadlocks of the same kind remain possible and are described in ADR-0043; they abort one transaction and change nothing. Negative controls: with the check removed, a parent mutation, a move and a suspension each empty the child; with the descendant search off, a parent mutation empties the child. **One control did not fail:** with the descendant locks removed by hand, the cross-tenant races still pass (44 runs) — the row locks `can()` takes already serialize them, so no administrator is lost without those locks. What their order decides is waiting versus deadlocking, which the forced-interleaving test demonstrates.

Not covered (ADR-0043): user deactivation (no Core function), purge and erasure, and a tenant attached beneath a tenant in the instant it is suspended.

### `braces` exception (B12 — applied, not fixed)

`scripts/security-exceptions.json` holds one entry: GHSA-vfj7-8cjw-p6xm in `braces`, expiring 2027-01-11. `scripts/npm_audit_gate.py` enforces the same threshold as before (high and critical) and accepts that advisory only while it stays out of production dependencies, `npm` offers no non-breaking fix, and the date has not passed; a stale or malformed entry fails the gate. The advisory is printed on every run as accepted and not fixed. Re-verified in this run: `3.0.3` is still the newest `braces`; `npm audit --omit=dev` reports 0. Document: `docs/SECURITY-EXCEPTION-braces.md`. Tests: `tests/architecture/test_npm_audit_gate.py` (20).

### Security script

- The secret scan passes file names through a list and `xargs` instead of one command line, which exceeded the Windows limit. Verified on Windows with the real script: the scan now runs to completion. A test feeds it 4,000 names and checks each is scanned once.
- Found while doing this: `detect-secrets-hook` rewrites the baseline file it is given when findings do not match. The script is therefore run for validation in a copy of the tree, never against the working copy's baseline.

### Secrets baseline (B8 — replaced)

The run-5 proposal was stale after this run's edits, so a new one was generated from the final tree, outside the repository, and audited before use: 152 files and 286 entries before and after; 0 entries added, 0 removed; 29 paths re-keyed to their `saas_os/…` location with identical secret hashes; every entry marked not a secret; plugins and filters unchanged; `detect-secrets-hook` passes against it across the whole tree. `.secrets.baseline` was then replaced with it (SHA-256 `f481a2b2…34d8`) and committed alone. The two secrets-gate tests that failed throughout this roadmap pass once it is committed.

### Validation of the final tree (run 6)

| Check | Result |
|---|---|
| ruff, ruff format, pyright, import-linter | Clean; 700 files; 13 contracts kept |
| Default suite | 2812 passed, 89 skipped, 2 failed before the baseline was replaced (the known secrets-gate pair); after it was committed: 2814 passed, 89 skipped, 0 failed |
| Worker-registration suite | 38 passed; negative control (guard disabled) 5 of 17 fail; restored byte for byte |
| Packaging (wheel contents, minimal install, extras) | 7 passed |
| Migrations gate, fresh database | Passed |
| Full integration gate, fresh database | 1990 passed, 0 skipped, 0 failed; after the lock-order fix found by CI: 1991 passed, 0 skipped, 0 failed |
| Frontend (typecheck, lint, tests, build) | Passed; 52 tests |
| Docker check | Passed, with the two-stage frontend image |
| Production Docker check, TLS (ADR-0027) | Passed |
| Production Docker check, plain | Fails by design (ADR-0021, ADR-0027): `server does not support SSL, but SSL was required` |
| Security script | Before the baseline was replaced: pip-audit clean, frontend gate passed (one accepted exception), secret scan ran to completion and failed on the stale baseline, script exit non-zero. After: passes, exit 0 (one accepted exception printed as not fixed) |

Skipped in the default suite: 88 tests that need the Caddy binary and 1 POSIX-only test.

Not run locally: live Stripe, ZITADEL and GitHub integrations. Remote CI: see the pull request; its result is not claimed here.

---

## Run 5 (2026-10-11) — runtime image, security script, hierarchy audit of the administrator rule

Authorized by the repository owner the same day. Nothing is staged, committed or pushed; `.secrets.baseline` is untouched.

### Frontend runtime image

`frontend/Dockerfile` is now two-stage. The `build` stage installs everything and runs `next build`; the final stage installs production dependencies only (`npm ci --omit=dev`) and copies the built `.next/`.

Verified in the built image: `braces`, `micromatch`, `fast-glob`, `eslint`, `eslint-config-next` and `typescript` are absent (43 packages in `node_modules`, none of the first three anywhere on the filesystem). Started with networking disabled, it reports ready and serves `/` (200) and an unknown path (404).

`frontend/next.config.ts` became `frontend/next.config.mjs`. This was required, not cosmetic: with a TypeScript configuration file and no compiler in the image, `next start` runs `npm install` for the development dependencies at container start, which silently restored all of them — found on the first attempt and the reason the no-network start is part of the evidence.

The advisory itself is unchanged (no patched release) and still present in the development tree used by lint and CI. The exception in `docs/SECURITY-EXCEPTION-braces.md` remains **proposed, not applied**; its exposure section is updated.

### Security script

`scripts/check-security.sh` stopped at the first failing command, so a failing `npm audit` meant the secret scan never ran. It now runs all three checks every time: the two dependency audits record their failure and the script continues; the secret scan runs last, unguarded, under `set -e`, exactly as `tests/architecture/test_secrets_gate.py` requires. The script exits non-zero if any of the three fails. The threshold (`--audit-level=high`), the flags and the baseline argument are unchanged, and nothing is exempted.

Evidence: `tests/architecture/test_security_script_reporting.py` runs the real script against stubbed tools for all eight pass/fail combinations (9 tests).

Run for real, in a copy of the tree outside the repository so the protected baseline could not be rewritten: pip-audit clean; `npm audit` fails on `braces`; the secret scan now starts — and on this Windows machine stops with `Argument list too long`, because the script passes every tracked file name on one command line (35,836 characters against a 32,767 limit). That limit does not apply on the Linux CI runner. It is a pre-existing property of the invocation, hidden until now because the script never reached that line; it was not changed here. The scan's actual result for the final tree is in the baseline section below.

### Administrator rule and the tenant hierarchy (B13)

Audited by demonstration: `tests/core/rbac/test_last_administrator_hierarchy_integration.py`, 10 tests. Every scenario asked about is possible. In each, a tenant that has an administrator ends with none and no error is raised:

| Scenario | Possible |
|---|---|
| Parent: remove a SUBTREE role the child's only administrator depends on | Yes |
| Parent: revoke the permission from that role | Yes |
| Parent: suspend that member's parent membership | Yes |
| Parent: revoke a SUBTREE delegation | Yes |
| Parent: SUBTREE deny against the child's administrator — even one whose role was granted in the child and who is not a member of the parent | Yes |
| Move the tenant away from its parent (`move_tenant`) | Yes |
| Suspend the parent tenant (`transition_tenant_status`) | Yes |
| A delegation of `membership_role:create` expiring | Yes |

Contrast, also tested: the same deny made inside the child is refused; and a parent administrator who is not a member of the child is not counted as the child's administrator, though they can still assign roles there — a child emptied from above is repairable from above, not from inside.

**No Core change was made.** Closing the parent cases requires judging a mutation against every descendant it reaches: several tenants' administrator locks in one transaction, a cost that grows with the subtree, and new refusals of operations a parent may perform today. That changes what the hierarchy permits, so it is recorded as an owner decision with four options in ADR-0043, not implemented. The shared guard, the per-tenant lock and the approved behaviour inside a tenant are unchanged.

### Baseline proposal (final, not applied)

See the run's final report for full hashes and the entry-level comparison. The proposal was regenerated from the final tree into a new directory outside the repository; the run-3 and run-4 files are superseded.

### Validation (run 5)

Run against the final tree unless the row says otherwise.

| Check | Result | Run on the final tree |
|---|---|---|
| ruff, ruff format, pyright, import-linter | Clean; 698 files; 13 contracts kept | Yes |
| Default suite | 2791 passed, 89 skipped, 2 failed (the known secrets-gate pair) | Yes |
| Last-administrator integration tests (three files) | 67 passed | Yes |
| Frontend (typecheck, lint, tests, build) | Passed; 52 tests | Yes |
| Docker check | Passed, with the two-stage frontend image | Yes |
| Production Docker check, TLS (ADR-0027) | Passed, with the two-stage frontend image | Yes |
| Security script | Fails on `braces` as before; all three checks now run (above) | Yes, in a copy of the tree |
| Full integration gate | 1944 passed, 0 skipped — run 4, before run 5 | **No.** Run 5 changed no file under `saas_os/`; its one new integration file was run on its own (10 passed) |
| Worker-registration suite, packaging, migrations gate | Passed in run 4 | **No.** Nothing they exercise changed |
| Production Docker check, plain | Fails by design (run 4) | No |

The two default-suite failures remain the known secrets-gate pair (unstaged baseline). Skipped: 88 Caddy-binary tests, 1 POSIX-only test. Not run: live Stripe, ZITADEL and GitHub; remote CI.

---

## Run 4 (2026-10-11) — invariant completion, advisory and Docker dispositions, final validation

Authorized by the repository owner the same day: complete the last-administrator invariant across every Core mutation that can remove administrative authority, settle how the `braces` advisory is treated without changing the gate, verify the baseline proposal, explain the plain production Docker failure, and validate the final tree again in full. Nothing is staged, committed or pushed.

### Last-administrator invariant audit (ADR-0043, extended)

One rule: a tenant that has an administrator (an active member, an active user, for whom `can(membership_role:create)` holds) must still have one after the mutation. One mechanism, `saas_os/core/rbac/administrators.py`: per-tenant advisory lock `tenant.administrators` before authorization, a record of one current administrator immediately before the change, a re-check after the flush, `LastTenantAdministratorError` and rollback if the tenant had one and has none.

| Mutation | Disposition |
|---|---|
| `suspend_membership`, `revoke_membership` | Guarded (run 3; moved onto the shared mechanism) |
| `remove_role` | Guarded |
| `revoke_permission` | Guarded — a shared role removes several administrators at once, and is judged on the result |
| `create_deny` | Guarded |
| `revoke_delegation` | Guarded — a delegated `membership_role:create` makes an administrator |
| `delete_role` | No guard needed: the foreign keys refuse a role that is assigned or still grants a permission (tested) |
| Mutations that only add authority | Not restricted |
| User deactivation | No Core function sets `core.users.is_active`; nothing to guard. A future one must use the guard |
| Service-account role and deny mutations | Not applicable: a service account is not a member |

No authorization rule changed: `can()` is called, not modified. No schema change, no fixed administrator role.

Evidence: `tests/core/identity/test_last_administrator_integration.py` (25) and the new `tests/core/rbac/test_last_administrator_rbac_integration.py` (32) — each mutation refused for the last administrator and allowed while another remains, a tenant with no administrator, tenant isolation, an unauthorized caller and a no-op causing no search, and five concurrent scenarios (same and different mutations racing), five runs each. Negative controls: with the check replaced by a no-op the last administrator is removed; with the advisory lock removed, 10 of the 25 concurrency runs end with no administrator; restored, all 57 pass.

One existing test needed a compatible change: `tests/core/rbac/test_role_assignment_authorization_integration.py::test_explicit_deny_on_manage_role_assignments_overrides_allow` denied `membership_role:create` to its tenant's only administrator, which the rule now refuses. The grantor is made a second administrator first; what the test asserts is unchanged.

Limits, recorded in ADR-0043 and not closed here: changes made in an ancestor tenant (SUBTREE roles, denies and delegations reach descendants, and descendants are not checked); `move_tenant`; a delegation expiring; tenant purge and identity erasure; a possible cross-tenant deadlock between two deny grants, which PostgreSQL resolves by aborting one.

### `braces` advisory (GHSA-vfj7-8cjw-p6xm)

Verified: installed `braces@3.0.3`; affected range `<= 3.0.3`; `3.0.3` is the newest release; the latest `micromatch`, `fast-glob` and `@next/eslint-plugin-next` all still lead to it. One path, under the development dependency `eslint-config-next`. `npm audit --omit=dev` reports 0 vulnerabilities.

| Context | Exposure |
|---|---|
| Production runtime | Not executed. Present on the image's disk, because `frontend/Dockerfile` installs development dependencies and does not prune them (a correction to run 3, which said "development tooling only") |
| Build and CI | Executed by the lint step on glob patterns from this repository's own configuration; no external input |
| Consumers of the Python package | None |

Disposition: **no change to the gate.** `scripts/check-security.sh` still fails on it. `docs/SECURITY-EXCEPTION-braces.md` proposes one expiring exception for this advisory identifier only (expiry 2027-01-11, three conditions, review triggers) and rejects the wider alternatives (`--omit=dev`, a lower threshold, the forced downgrade of `eslint-config-next`). It takes effect only if the owner approves it and the script is changed in a separate commit.

### Baseline proposal (verified, not applied)

The run-3 proposal file still exists outside the repository with the hash reported then (`38e7caf6…08c7`), but it is superseded: later edits moved line numbers. A new proposal was generated from the final tree into a new directory outside the repository; the protected `.secrets.baseline` was not read for writing, staged or replaced.

| | |
|---|---|
| Current `.secrets.baseline` SHA-256 | `2d9dcb80…c474` (unchanged throughout) |
| Proposed file SHA-256 | `01f5f90c…2daa (changes on every regeneration: the file embeds its generation time)` |
| Entries | 286 before, 286 after; 0 new, 0 removed |
| Files re-keyed | 29, each old path matched to its `saas_os\…` counterpart with the same secret hashes |
| Marked as real secrets | 0; every entry keeps its existing review flag |
| Plugins and filters | Unchanged |

Full hashes are in the run's final report rather than here, so this file does not itself add findings to the scan.

### Plain production Docker check

`scripts/check-docker-prod.sh` fails at its migration step with `server does not support SSL, but SSL was required`. This is the intended behaviour, not a regression: production mode refuses a plaintext database connection and ships no opt-out (ADR-0021), the reference Compose file's own `db`/`redis` services carry no TLS material, and ADR-0027's Context records that this script "therefore stops at the backend/worker step". ADR-0027 added `scripts/check-docker-prod-tls.sh`, which supplies disposable TLS for both services and passes. No TLS requirement was changed and the script was not edited; `README.md` now names the TLS script as the production validation and explains why the older one stops.

### Validation of the final working tree (run 4)

Run after the last code change. The integration gate was run twice: the first run found the one test above, the second ran after its fix. Earlier runs' results are not counted.

| Check | Result |
|---|---|
| ruff, ruff format, pyright, import-linter | Clean; 696 files; 13 contracts kept |
| Default suite | 2782 passed, 89 skipped, 2 failed (the two known secrets-gate tests, below); rerun after the last documentation edit, same result |
| Worker-registration suite | 38 passed; negative control (guard disabled) 5 of 17 fail; restored byte for byte |
| Packaging (wheel contents, minimal install, extras) | 7 passed |
| Migrations gate, fresh database | Passed |
| Full integration gate, fresh database | First run: 1943 passed, 1 failed (the test above). After the fix: 1944 passed, 0 skipped, 0 failed |
| Frontend (typecheck, lint, tests, build) | Passed; 52 tests |
| Docker check | Passed |
| Production Docker check, TLS (ADR-0027) | Passed |
| Production Docker check, plain | Fails by design (above) |
| Security script | Fails: pip-audit clean; `npm audit` stops on `braces`; the secrets scan after it did not run |

The two default-suite failures are `tests/architecture/test_secrets_gate.py::test_clean_repository_gate_succeeds` and `::test_approved_false_positive_remains_accepted`, both because `.secrets.baseline` is modified and unstaged. They are unchanged since before this roadmap and are not regressions.

Skipped: 88 tests that need the Caddy binary and 1 POSIX-only test, in the default suite. Not run: live Stripe, ZITADEL and GitHub; remote CI (nothing is pushed); the frontend production image without development dependencies.

### Unchanged

The four deferred route groups (tenant lifecycle, invitation acceptance, API-key request authentication, inbound billing webhooks) remain unexposed. No consumer pin and no external repository was touched.

---

## Run 3 (2026-10-11) — security remediation and final-tree validation

Authorized by the repository owner the same day: fix the two MEDIUM findings of run 2, treat the npm advisories, re-validate the final tree in full, prepare (not apply) a baseline update, and keep the four deferred route groups unexposed.

### What changed

**Last tenant administrator (ADR-0043, Accepted, implemented).** A membership cannot be suspended or revoked while it is the tenant's only active administrator — an ACTIVE member, an active user, for whom `can(membership_role:create)` holds. Enforced in `saas_os/core/identity/service.py::_transition_membership_status`, in the transition's own transaction, after taking a per-tenant advisory lock and before the status changes; `LastTenantAdministratorError`; `409` from `saas_os/api/v1/members.py`. No schema change, no role hierarchy.
 - Evidence: `tests/core/identity/test_last_administrator_integration.py`, 25 tests on real PostgreSQL — self-revocation, another member removing the sole administrator, suspended and deactivated administrators not counting, tenant isolation, one user judged per tenant, and two concurrent scenarios run five times each. Negative controls: guard replaced by a no-op (in-tree) — the sole administrator is revoked; advisory lock removed (by hand) — 5 of 10 concurrency runs end with no administrator, restored 10 of 10 pass. Route test: 409 for suspend and revoke, by the administrator and by another member.
 - Not covered, by scope: role removal, permission revocation, role deletion, deny grants and user deactivation can still leave a tenant without an administrator (ADR-0043, "What this does not cover").

**CSRF (ADR-0044, Accepted, implemented).** An unsafe-method request authenticated by the session cookie must carry an `Origin` equal to the application's origin (`PUBLIC_APP_ORIGIN`, else the callback's origin) and, when sent, `Sec-Fetch-Site: same-origin`. `Authorization: Bearer` clients and safe methods are exempt; a request with no credential still gets 401. Implemented as a sub-dependency of `get_current_session` / `get_current_actor` in `saas_os/api/dependencies.py`, so every authenticated route has it and no router opts in.
 - Evidence: `tests/api/test_csrf_unit.py`, 85 tests — same origin accepted; unrelated site, sibling subdomain, parent domain, look-alike suffix, other port, downgraded scheme, missing `Origin`, nine malformed values and non-same-origin fetch metadata refused, with the state change observed not to happen; Bearer unaffected; each of the ten state-changing capability routes refusing four forged variants before any database access; negative control with the check removed. Integration: four forged cookie requests against membership suspend change nothing and audit nothing; the genuine one works; a Bearer client needs no `Origin`.
 - Behaviour change: `POST /auth/logout` authenticated by cookie now needs a matching `Origin`. Three existing logout tests were updated to send it, as a browser does.

**Frontend advisories.** `npm audit fix` without `--force`; `package.json` unchanged, `package-lock.json` updated.

| Advisory (root) | Severity | Path | Before → after | Result |
|---|---|---|---|---|
| `next` — SSG/ISR cache poisoning (GHSA-4jqv-mc3x-m676 and related) | moderate | direct | 15.x < 15.5.27 → 15.5.27 | fixed |
| `sharp` — librsvg (GHSA-wq5f-xc86-pv6w) | high | `next` → `sharp` | < 0.35.5 → 0.35.5 | fixed |
| `source-map-js` — event-loop DoS (GHSA-68fv-2mgg-jv7q) | high | transitive | 1.2.1 → 1.2.2 | fixed |
| `brace-expansion` — quadratic expansion (GHSA-q2hr-2g5m-vwhr) | high | transitive (two copies) | → 1.1.21 and 5.0.12 | fixed |
| `braces` — stack exhaustion on nested patterns (GHSA-vfj7-8cjw-p6xm) | high | `eslint-config-next` → `@next/eslint-plugin-next` → `fast-glob` → `micromatch` → `braces@3.0.3` | no patched release exists (3.0.3 is the latest) | **remains** |

 `npm audit` counts the `braces` advisory five times (once per package on that path), hence "5 high" from 9. Exposure: development tooling only — the path exists solely under the ESLint configuration; `npm audit --omit=dev` reports **0 vulnerabilities**; the glob patterns `braces` expands come from this repository's own lint configuration, not from user input. The only "fix" `npm` offers is `--force`, which downgrades `eslint-config-next` to 14.2.35 against Next 15 — not applied. Not suppressed; the security script still fails on it. Recommendation: upgrade when `braces` or `micromatch` publishes a fix, or replace `eslint-config-next` if a release drops `fast-glob`.

**Deferred routes.** Tenant lifecycle, invitation acceptance, API-key request authentication and the inbound billing webhook remain unexposed. The decisions each needs are in ADR-0040, "Decisions needed for each deferred route group".

### Validation of the final working tree (run 3)

One pass, on the code as it is now. After it, four comment-or-prose-only edits were made (the auth routes' CSRF docstring, two `# pragma: allowlist secret` comments, one README sentence); static checks and the default suite were then re-run and are the figures below.

| Check | Command | Result |
|---|---|---|
| Lint, format | `ruff check .`, `ruff format --check .` | **pass** (693 files) |
| Types | `pyright` | **pass** — 0 errors |
| Import boundaries | `lint-imports` | **pass** — 13 kept, 0 broken |
| Default suite | `pytest` | 2782 passed, 89 skipped, **2 failed** (the pre-existing secrets-gate pair, below) |
| Worker registration | `pytest tests/api/test_worker_consumer_jobs_unit.py tests/api/test_worker_unit.py` | **pass** — 38 |
| Worker negative control | identity guard disabled, same file | 5 of 17 fail; restored byte for byte, 17 pass |
| Packaging | `pytest -m packaging tests/test_wheel_contents.py` | **pass** — 7 (wheel contents, top-level names, minimal install, each extra) |
| Migrations gate | `scripts/check-migrations.sh`, fresh PostgreSQL 16 | **pass** — 7 + 7 + 1 |
| Full integration gate | `scripts/check-integration.sh`, fresh PostgreSQL 16 + Redis 7 | **pass** — 1912 passed, 0 failed, 0 skipped |
| Frontend | `scripts/check-frontend.sh` | **pass** — typecheck, lint, 52 tests, build |
| Docker | `scripts/check-docker.sh` | **pass** — including "worker executed the job" |
| Production Docker, TLS | `scripts/check-docker-prod-tls.sh` | **pass** (exit 0) |
| Production Docker, plain | `scripts/check-docker-prod.sh` | **fail** — migration step: "server does not support SSL, but SSL was required" |
| Security script | `scripts/check-security.sh` | **fail** — `pip-audit` clean; `npm audit` 5 high (the `braces` chain); stops before its secrets scan |
| Live Stripe / ZITADEL / GitHub | 4 files the gate excludes | **not run** — no credentials |
| Remote CI | — | **not run** — nothing is published |

The full integration gate includes every RLS and tenant-isolation suite, both consumer end-to-end tests and the capability-router suite (34 tests).

- **Default suite, 2 failed**: `test_clean_repository_gate_succeeds` and `test_approved_false_positive_remains_accepted`, both "Your baseline file (.secrets.baseline) is unstaged" — the same two as before run 1. Not cleared: staging was not authorized. The 89 skips are 88 Caddy-binary tests and one POSIX-only test.
- **Plain production Docker**: production mode requires TLS to PostgreSQL (ADR-0021) and this script's database has none; the TLS variant (ADR-0027) is the one that validates the production path, and passes. Whether the plain script passed at HEAD was not established.
- **Security script**: fails for the one unpatched development-only advisory above. Its secrets scan therefore did not run; see the proposed baseline.

### Proposed `.secrets.baseline` (prepared, not applied)

Generated into a temporary file outside the repository with `detect-secrets` 1.5.0, the current baseline's own plugins and filters, over the 772 files now on disk (tracked and not deleted, plus untracked and not ignored). Review flags were carried over by secret type and hash.

| | Current (protected) | Proposed |
|---|---|---|
| SHA-256 | `2d9dcb8020581062b9254d9d9497f6338dfe265e22217d35b14e9fe8dd1cc474` | `38e7caf6cc693e8e56381385ace370a1dde12aea066f41a5e40ff7b0f2af08c7` |
| Size | 101,977 bytes | 102,590 bytes |
| Files / entries | 152 / 286 | 152 / 286 |

- **New findings: 0. Removed findings: 0.** Every entry is the same (type, hash) as today.
- **29 files re-keyed** from the old layout to `saas_os/…`; line numbers refreshed.
- **Entries marked `is_secret: true`: 0. Entries without a review flag: 0.**
- Three strings written during this work would have been new keyword false positives (`API_KEY = "api_key"` — a permission resource name; `https://user:pw@…` — a malformed-`Origin` test value; a README sentence). Two now carry an inline `# pragma: allowlist secret`, the third was reworded, so nothing new needs accepting.
- The repository's own hook (`detect_secrets.pre_commit_hook`) run with the proposed file over all 772 files exits 0 and leaves the file unchanged.
- The protected file was not replaced, staged or modified; its hash is unchanged. The run-1 recovery backups are intact.

---

## Run 2 (2026-10-11) — owner decisions implemented

### What changed, by phase

**P1 — namespace (ADR-0038, Accepted, implemented).** The five top-level packages are now subpackages of one package, `saas_os/` (`saas_os.core`, `saas_os.infra`, `saas_os.api`, `saas_os.contracts`, `saas_os.control_plane`). Hard cut: no alias, no `package-dir` mapping. About 600 Python files and 70 configuration, script and documentation files rewritten by a syntax-aware codemod; database schema names, migrations, permission resources, audit names, job names and lock keys are unchanged (an independent AST comparison of all 266 moved modules against HEAD found no change outside module paths; every migration is AST-identical). Regression tests: `tests/architecture/test_namespace_contract.py` (Python imports, packaging, import-linter targets exist), `tests/architecture/test_namespace_text_files.py` (Dockerfile, Compose, CI, systemd, shell), and the wheel top-level-name test (`{saas_os}`). The update policy moved to version 3; an old-layout path classifies as `unknown`.
 - Found on the way: the import-linter negative controls and two "module X is not imported" assertions matched the old names and had gone vacuous — fixed and seen to fail again; a stale ignored `build/` directory made wheels ship the old packages next to `saas_os` — removed; three old-name references in integration tests that only the full gate exercises (a table-name key the codemod wrongly prefixed, a migration path, one test driver) — fixed.

**P2 — consumer proof.** Both example manifests still pin `4fccc93` and are marked **STALE** in place: that commit predates the `saas_os` root, the worker seam and the extras, and no newer commit is published. Proof for the current code is the working-tree wheel: `tests/test_reference_consumer_integration.py` and `tests/test_consumer_scaffold_integration.py`, each from an isolated venv outside the repository. The run-1 pinned-SHA install is not repeatable for the renamed code until it is pushed.

**P3 — scaffold and guide.** `examples/consumer-scaffold/` and `docs/CONSUMER-GUIDE.md` moved to `saas_os.*` imports; the guide gained the import-root section (replacing "reserved names"), the extras, the opt-in routers with their two security caveats, and the stale-pin warning. The guide's 11 scaffold samples and its router registration example are checked against the code. ADR-0039 confirmed: the worker seam stays, with identity-based registration validation (negative control: 5 of 17 tests fail with it disabled).

**P4 — opt-in HTTP routers (ADR-0040, Accepted, stage 1 implemented as scoped).** `saas_os/api/v1/{members,invitations,api_keys,billing,usage}.py`: 18 routes, none mounted by `build_platform_app()`. One `require_permission` per route; three new permissions (`membership:read`, `invitation:read`, `api_key:self_manage`), each stricter than Core. Not exposed, with the reason in ADR-0040: tenant lifecycle (no authority model), invitation accept, API-key request authentication, inbound billing webhook, webhook subscriptions, feature-flag administration, usage ingestion. Tests: 25 contract (hermetic) and 31 integration, including a six-case denial matrix on every route.

**P5 — optional dependencies (ADR-0041, Accepted, implemented).** `stripe` and `boto3` are extras (`saas-os[stripe]`, `[s3-backup]`, `[all]`); constraints unchanged; `dev` installs both; this repository's image installs `[all]`; CI's security job installs `[all,security]`. Each adapter raises an `ImportError` naming its extra. Tests: 9 hermetic; packaging test installs the same wheel with no extra, then each extra, in one isolated venv. Constraints file and versioning: not adopted.

**P6 — frontend (ADR-0042, Accepted).** Frontend is product-owned; no shared package. `docs/ARCHITECTURE.md` no longer presents Next.js as the product default with an ADR required to deviate.

**P7 — providers.** No code beyond P5. `build_billing_router(provider=...)` makes the billing provider an explicit argument at registration.

**P8 — hygiene.** README layout and import-root note rewritten; ADR index updated; `scripts/check-docker.sh` fixed in run 1.

### Validation of the final working tree

Two passes. **Pass A** ran everything, before the independent review's fixes. **Pass B** re-ran on the final code; at the owner's instruction it used a targeted integration selection instead of the 30-minute full gate.

| Check | Command | Pass A | Pass B (final code) |
|---|---|---|---|
| Lint, format | `ruff check .`, `ruff format --check .` | clean | clean (689 files) |
| Types | `pyright` | 0 errors | 0 errors |
| Import boundaries | `lint-imports` | 13 kept | 13 kept |
| Default suite | `pytest` | 2648 passed, 89 skipped, 2 failed | **2697 passed, 89 skipped, 2 failed** (last run, after the final test edits) |
| Packaging | `pytest -m packaging tests/test_wheel_contents.py` | 7 passed | **7 passed** |
| Migrations gate | `scripts/check-migrations.sh`, fresh PostgreSQL 16 | passed (7 + 7 + 1) | not re-run (no migration or migration-runner change after pass A) |
| Full integration gate | `scripts/check-integration.sh`, fresh PostgreSQL 16 + Redis 7 | 1877 passed, **3 failed**, 0 skipped | **not re-run** |
| Targeted integration | `pytest -m integration` on the 3 failed tests, `tests/api`, both consumers, `tests/infra/jobs`, `tests/core/{usage,billing,api_keys}` | — | **703 passed, 1 skipped, 0 failed** |
| Frontend | `scripts/check-frontend.sh` | typecheck, lint, 52 tests, build passed | not re-run (untouched) |
| Docker | `scripts/check-docker.sh` | **failed** — worker container: `No module named 'saas_os'` | pass A's failure was a stale worker image: the script built only `backend` and reused a `worker` image left by an earlier, pre-rename run. Script fixed to build both; **passed** — "All Docker checks passed", including "worker executed the job" |
| Security script | `scripts/check-security.sh` | **failed** — see below | not re-run |
| Production Docker | `scripts/check-docker-prod.sh` | **failed** at the migration step — see below | — |
| Production Docker, TLS | `scripts/check-docker-prod-tls.sh` | — | **passed** (exit 0) after fixing one old-layout bind-mount path in the script; one step skipped by the script itself: "host python cannot import saas_os.infra.db.backup — environment gap" (the backup-against-validation-database step) |
| Live Stripe / ZITADEL / GitHub | 4 files `check-integration.sh` excludes | not run — no credentials | not run |
| Remote CI | — | not run — nothing is pushed | not run |

Reading the failures:

- **Default suite, 2 failed**: `test_clean_repository_gate_succeeds` and `test_approved_false_positive_remains_accepted` — "baseline file is unstaged", the same two as before either run. The 89 skips are 88 Caddy-binary tests and one POSIX-only test.
- **Integration gate, 3 failed (pass A)**: all three were old-name references left by the rename in integration-only tests; fixed; all three pass in pass B. The other 1877 tests of the gate were not re-run on the final code. What changed between the two passes is confined to `saas_os/api/v1/`, four test files, one docstring in `deploy/`, one comment in `pyproject.toml` and documentation.
- **Targeted integration, 1 skipped**: `tests/core/billing/test_billing_stripe_integration.py` — no `STRIPE_API_KEY`.
- **Security script (pass A)**: `pip-audit` — no known vulnerabilities. `npm audit --audit-level=high` — **9 vulnerabilities (1 moderate, 8 high)** in the frontend's dependency tree (`brace-expansion`, `sharp` and others; `npm audit fix` is offered for most). `frontend/package.json` and its lock file are untouched by both runs: pre-existing, newly published advisories. The script stops there, so its secrets scan did not run. Not fixed: a dependency upgrade outside P scope.
- **Production Docker (pass A)**: images build with the new namespace and the stack starts; the migration container then fails with "server does not support SSL, but SSL was required". Production mode requires TLS to PostgreSQL (ADR-0021); this script's database has none, which is what `check-docker-prod-tls.sh` (ADR-0027) exists for. Not a consequence of this work, but not confirmed against HEAD either.

### Independent review (run 2)

A separate agent reviewed the routers, the rename and the extras from the diff. No CRITICAL or HIGH finding: no cross-tenant read or write, no secret in a response, no Core check weakened, no database identifier or migration altered. Fixed after it: weak or vacuous assertions in the router integration test; a plan-existence oracle on subscribe; an unmapped `TenantInaccessibleError` and a bare `except ValueError`; control characters reaching PostgreSQL; the idempotency header examined before authentication. Two MEDIUM findings need an owner decision and are recorded in ADR-0040 ("Open security findings") and the blocker register below.

---

## P1 — Package namespace and public import contract

- **Objective**: resolve the collision risk of the shipped top-level import names `core`, `infra`, `api`, `contracts` (and `control_plane`). Investigate the alternatives and prepare the ADR. The breaking migration itself is not part of this phase until the decision is approved.
- **Files/Modules Affected**: `docs/ADR/0038-*.md` (new, Proposed); `docs/ADR/README.md` (index row). No source file.
- **Dependencies**: none.
- **Tests**: a reproducible demonstration that the collision is real (a consumer-side top-level package named like a SaaS-OS one shadows or is shadowed by it in a clean install).
- **Security Requirements**: the ADR must state how import-linter contracts, the tenant-session boundary scan and the route-policy scan survive each option — a rename must not create a window in which a boundary check silently matches nothing.
- **Acceptance Criteria**:
  1. The shipped top-level names are established from a real installed distribution, not from `pyproject.toml` alone.
  2. The collision is demonstrated, with the exact failure mode recorded.
  3. ADR-0038 lists at least three options with compatibility implications, a migration plan, a rollback strategy and a recommendation.
  4. No import rename is performed.
- **Rollback Strategy**: delete the ADR; nothing else changes.
- **Outcome**: **PASS** for this phase's scope (decision preparation). The migration itself is **BLOCKED** on reserved decision A.
  1. Shipped names established from a real install of `4fccc93`: `top_level.txt` is `api`, `contracts`, `control_plane`, `core`, `infra`. Now pinned by `tests/test_wheel_contents.py::test_wheel_owns_exactly_the_documented_top_level_import_names` (`packaging` marker; passes).
  2. Collision demonstrated in that clean environment: a project directory with its own empty `api/__init__.py` makes `import api.platform` fail with `ModuleNotFoundError: No module named 'api.platform'`.
  3. `docs/ADR/0038-package-namespace-and-public-import-contract.md` (Proposed): four options, three failure modes, measured blast radius (about 3,180 import statements, about 800 module-path strings, 13 import-linter contracts), a nine-step migration plan, a rollback strategy, and the runtime effects (pickled queued jobs, logger names, process commands). Recommendation: one `saas_os` root, hard cut, before the first consumer.
  4. No import renamed. Interim protection: the reserved-names rule in `docs/CONSUMER-GUIDE.md` §2 and `tests/test_consumer_scaffold_unit.py::test_scaffold_declares_no_top_level_package_that_saas_os_owns`.

## P2 — Real consumer and installation proof

- **Objective**: replace the reference consumer's placeholder pin with a verifiable, immutable Git SHA, and prove installation and execution from a clean environment that does not rely on this repository's root or its development environment.
- **Files/Modules Affected**: `examples/reference-consumer/pyproject.toml`, `examples/reference-consumer/README.md`; one new hermetic test.
- **Dependencies**: none.
- **Tests**: hermetic pin-format test; a clean-venv install from the exact pinned `git+https` reference; the reference consumer's end-to-end driver run from a directory outside the repository against a disposable PostgreSQL and Redis; the existing `tests/test_reference_consumer_integration.py` (working-tree wheel).
- **Security Requirements**: the pin is a 40-character commit SHA, never a branch or tag (ADR-0015 rule 8).
- **Acceptance Criteria**:
  1. The manifest pins a 40-character SHA that exists on the remote.
  2. A hermetic test fails if the pin regresses to a placeholder, tag or branch.
  3. `pip install` of that exact reference succeeds in a clean virtual environment created outside the repository.
  4. From that environment, with the consumer package copied outside the repository: SaaS-OS migrations, consumer migrations, tool invocation and the consumer route all succeed against a disposable database.
  5. The existing working-tree wheel proof still passes.
- **Rollback Strategy**: restore the placeholder line.
- **Outcome**: **PASS WITH LIMITATIONS**.
  1. `examples/reference-consumer/pyproject.toml` pins `4fccc9370f3acf82cbc03fedd5c3adbade223d97`, confirmed on the remote (`git ls-remote`: head of `tier2/tls-validation-infrastructure`).
  2. `tests/test_consumer_pins_unit.py` (7 tests) parses both example manifests with `infra.update.pins.find_pin` — the parser `saas-os-update` uses — and rejects a placeholder, a branch, a tag and a short SHA.
  3. Clean install: `pip install --no-cache-dir "saas-os @ git+https://github.com/aelboum/saas-os@4fccc93…"` into a new Python 3.13 venv outside the repository succeeded; `direct_url.json` records the commit; 45 distributions, 159 MB.
  4. From that venv, with `reference_consumer/` copied outside the repository and the driver of `tests/test_reference_consumer_integration.py` run against a disposable PostgreSQL 16 and Redis 7: SaaS OS migrations, consumer migrations, tool invocation, 401 without a credential and 200 for a permitted member — `REFERENCE_CONSUMER_OK`; `core.__file__` resolved inside the venv's `site-packages`.
  5. Working-tree wheel proof: see P8 (`tests/test_reference_consumer_integration.py`).
  - **Limitations**: (a) the pinned-SHA proof is manual — it needs network and repository read access, so it is not a CI job; (b) the pin predates this roadmap's changes by construction, so it does not contain `api.worker`'s consumer-job seam; the pin must move after these changes are committed and pushed; (c) the install was run on Windows only; (d) there is still no real product — the consumer is a fixture.

## P3 — Consumer scaffold and developer documentation

- **Objective**: provide a minimal reusable consumer scaffold and a practical integration guide covering database grants, migrations, RLS, permissions, background jobs and tenant-purge participation.
- **Files/Modules Affected**: `examples/consumer-scaffold/` (new, not shipped), `docs/CONSUMER-GUIDE.md` (new), `docs/ADR/0039-*.md` (scaffold location, ADR-0015 rule 9's open item), `api/worker.py` (additive worker-composition seam, if the inspection confirms a consumer cannot add its own jobs without re-implementing the entrypoint), tests.
- **Dependencies**: P2.
- **Tests**: hermetic structural tests of the scaffold (layering, no direct SQLAlchemy outside migrations, route policy declared, pin format); an integration test that installs a real wheel, copies the scaffold outside the repository and runs migrations, permission registration, the route, a tenant job and tenant purge against real PostgreSQL and Redis; a cross-tenant negative test on the scaffold's table.
- **Security Requirements**: the scaffold's table is created with forced RLS through `infra.db.tenant_rls_statements`; every route goes through `api.dependencies.require_permission`; the application role stays non-superuser and non-BYPASSRLS; a consumer job can never replace a platform job of the same name.
- **Acceptance Criteria**:
  1. The scaffold lives outside the shipped package and outside `[tool.importlinter] root_packages`.
  2. It imports SaaS-OS only through the installed package's published surface.
  3. The integration test passes from a scratch directory outside the repository.
  4. Cross-tenant read of a scaffold row returns nothing under RLS; removing the tenant predicate does not expose it (negative control).
  5. The guide covers each of: grants, migrations, RLS, permissions, jobs, purge; every code sample in it is taken from the tested scaffold.
- **Rollback Strategy**: delete the new directory, guide and ADR; revert the additive `api/worker.py` parameters (no caller depends on them).
- **Outcome**: **PASS**.
  1. `examples/consumer-scaffold/` is outside `[tool.setuptools] packages` and `[tool.importlinter] root_packages` (`tests/test_consumer_scaffold_unit.py`, 44 tests, AST only).
  2. It imports only `api.*`, `core.*`, `infra.*`, `fastapi`, `alembic` and, inside `migrations/`, `sqlalchemy`.
  3. `tests/test_consumer_scaffold_integration.py` passes from a scratch directory outside the repository, against an installed wheel, PostgreSQL 16 and Redis 7, in a database of its own: both migration histories (run twice), the permission registered by the migration step, forced RLS, exactly four table privileges for the application role, 401 / 403 / 200 / 404 on the route, the job on a real worker, tenant purge.
  4. Isolation: as the application role, `SELECT id FROM my_product.items` with no predicate returns only the bound tenant's row; an `INSERT` for another tenant is rejected by RLS; a job running as tenant B cannot change tenant A's item. **Negative control**: with the `tenant_rls_statements` call removed from the scaffold's migration, the test fails.
  5. `docs/CONSUMER-GUIDE.md` covers grants, migrations, RLS, permissions, routes, jobs and purge; each of its 11 Python samples is checked to be a verbatim excerpt of a scaffold file.
  - **Worker seam** (ADR-0039): `api.worker.build_production_worker()` and `main()` take `extra_functions` / `extra_cron_jobs`. `tests/api/test_worker_consumer_jobs_unit.py` (17 tests). **Negative controls**: with the name-collision check disabled, 5 tests fail. With the identity-based registration check (`is_registered_job`) disabled, 5 of 17 fail (raw function under a registered name, raw cron job under a registered name, coroutine carrying a `name` attribute, unregistered arq function, bare coroutine); with it restored byte for byte, 17 of 17 pass. This control was re-run after the review fix; the first run, against the earlier name-only check, had 2 failures.
  - **Independent review** (a separate agent, on the diff): no CRITICAL or HIGH finding. Two MEDIUM findings, both fixed and retested: the registration check was by name only, so a raw arq function reusing a registered name passed it (now checked by wrapped-coroutine identity, `infra.jobs.queue.is_registered_job`); and an extra cron job could shadow an extra function of the same name (now one shared name set). LOW findings fixed: a vacuous permission assertion in the integration test, and five overstated documentation claims.
  - **Limitations**: the scaffold's pin (`4fccc93`) predates the worker seam, so `my_product/worker.py` runs only once the pin moves to a commit that contains it (stated in the scaffold README and the guide). The scaffold has one read route; it shows no mutating route.

## P4 — Reusable HTTP platform capabilities

- **Objective**: audit the missing tenant, member, invitation, API-key, billing, webhook, feature-flag and usage HTTP capabilities; define which belong in SaaS-OS and which stay product responsibilities; prepare the ADR for the public-contract change. No route is added by this phase.
- **Files/Modules Affected**: `docs/architecture/HTTP-CAPABILITY-MATRIX.md` (new), `docs/ADR/0040-*.md` (new, Proposed), `docs/ADR/README.md`.
- **Dependencies**: none.
- **Tests**: none (documentation phase); the matrix cites the Core functions and their authorization model by file and line.
- **Security Requirements**: each candidate endpoint records its authorization primitive, tenant scope, one-time-secret exposure, idempotency and enumeration risk before it can be proposed.
- **Acceptance Criteria**:
  1. Every one of the eight areas has a matrix row set: Core capability, current HTTP exposure, proposed owner (platform / product / operator-only), security notes.
  2. ADR-0040 states the proposed platform route set, the compatibility policy and the security preconditions.
  3. No public route is added or changed.
- **Rollback Strategy**: delete the two documents.
- **Outcome**: **PASS** for this phase's scope (decision preparation). Route implementation is **BLOCKED** on reserved decision B.
  1. `docs/architecture/HTTP-CAPABILITY-MATRIX.md`: all eight areas, each capability with its Core function, how Core authorizes it, whether the ingress chain can front it, one-time-secret exposure, and a proposed owner (platform / product / operator-only). Citations spot-checked against the code.
  2. `docs/ADR/0040-reusable-http-platform-capabilities.md` (Proposed): opt-in capability routers, an ownership rule, three implementation stages behind four named gaps (G1 no platform authority over HTTP, G2 no non-member route policy, G3 no API-key authentication, G4 no provider-event ledger), contract rules and security preconditions.
  3. No public route added or changed (`git diff` touches no file under `api/` except `api/worker.py`).
  - Finding recorded for the decision: `docs/API-ARCHITECTURE.md:17` assigns capability routes to Core modules, while every Core module states it owns no HTTP surface. ADR-0040 proposes resolving it in favor of the modules.

## P5 — Dependency and packaging modularity

- **Objective**: evaluate optional dependencies, reproducible dependency constraints, versioning, release metadata, supported Python versions and installation size. Implement only what is justified and non-breaking.
- **Files/Modules Affected**: `docs/ADR/0041-*.md` (new, Proposed); possibly packaging tests.
- **Dependencies**: P2 (uses its clean install for measurements).
- **Tests**: measurements from a real clean install; the existing `packaging` marker tests.
- **Security Requirements**: no dependency is loosened or removed without `pip-audit` still covering it; no change may alter which package versions an existing consumer resolves.
- **Acceptance Criteria**:
  1. Installation size and the per-dependency share are measured from a clean install.
  2. Each runtime dependency is classified by which SaaS-OS module actually imports it, and whether that import is lazy.
  3. ADR-0041 records options and a recommendation for extras, constraints, versioning and Python support.
  4. Anything implemented is additive and covered by a test.
- **Rollback Strategy**: delete the ADR; revert any additive packaging change.
- **Outcome**: **PASS** for evaluation; the packaging changes themselves await the ADR-0041 decision.
  1. Measured from the P2 clean install: 159 MB, 45 distributions; `stripe` 28 MB and `boto3`/`botocore`/`s3transfer` 30 MB are 36% of it.
  2. Each runtime dependency mapped to its importing modules. Importing every Core, Infra and API package leaves `stripe`, `boto3`, `botocore` and `uvicorn` unloaded.
  3. `docs/ADR/0041-dependency-and-packaging-modularity.md` (Proposed): extras for `stripe` and `boto3`, a CI-generated constraints file, manual version bumps with a changelog, Python `>=3.13` unchanged, no split of the control plane.
  4. Implemented (additive): `tests/architecture/test_optional_sdk_imports.py` (2 tests, with a non-vacuity control) pins the lazy-import property the extras recommendation depends on. `pyproject.toml` is unchanged.

## P6 — Reusable frontend strategy

- **Objective**: decide whether SaaS-OS needs a reusable frontend package or whether frontend code stays product-owned. Implement only a clearly justified, approved solution.
- **Files/Modules Affected**: `docs/ADR/0042-*.md` (new, Proposed).
- **Dependencies**: none.
- **Tests**: `scripts/check-frontend.sh` (the current frontend must stay green).
- **Security Requirements**: any shared frontend code that touches the session cookie or the auth routes is a security surface and needs its own review.
- **Acceptance Criteria**:
  1. The current frontend's reusable content is inventoried.
  2. ADR-0042 records options and a recommendation.
  3. No frontend package is created without approval.
- **Rollback Strategy**: delete the ADR.
- **Outcome**: **PASS** for evaluation; nothing to implement without a decision.
  1. Inventory: `frontend/` is about 1,160 lines — an i18n module (locale resolution, dictionaries, formatting, direction), one `LanguageSwitcher` component, one placeholder page. It calls no `/auth/*` or `/v1/*` route and is not published.
  2. `docs/ADR/0042-reusable-frontend-strategy.md` (Proposed): frontend stays product-owned; a copy-once frontend scaffold with the first product; a headless client only if two products duplicate the same glue; no component library.
  3. No package created. `scripts/check-frontend.sh` passes on the final tree.
  - Finding: ten frontend files cite "docs/IMPLEMENTATION-ROADMAP.md Phase 10.1", a phase that roadmap does not define. Recorded in the deferred ledger; not fixed here, because writing the missing phase would be inventing roadmap text.

## P7 — Provider extensibility

- **Objective**: evaluate the provider interfaces for identity, billing, email, secrets and backup destinations from a consumer's point of view. Preserve the existing abstractions; implement only necessary, in-scope improvements.
- **Files/Modules Affected**: `docs/architecture/PROVIDER-EXTENSIBILITY-REVIEW.md` (new).
- **Dependencies**: none.
- **Tests**: existing provider-substitution tests are identified; any change made is covered by a test.
- **Security Requirements**: provider selection must never fall back silently to a weaker provider; provider-specific code stays in adapters (`CLAUDE.md` §9).
- **Acceptance Criteria**:
  1. For each of the five seams: interface, shipped adapters, selection mechanism and whether a consumer can substitute an implementation without editing SaaS-OS.
  2. Provider-specific leakage outside adapters is listed with file and line, or stated absent.
  3. Each non-pluggable seam has either a non-breaking fix implemented and tested, or a recorded decision request.
- **Rollback Strategy**: delete the review; revert any additive change.
- **Outcome**: **PASS**. No code change was necessary.
  1. `docs/architecture/PROVIDER-EXTENSIBILITY-REVIEW.md`: interface, shipped adapters, selection mechanism and consumer substitutability for identity, billing, email, secrets and backup destination, plus `KeyProvider` and `PullRequestProvider`.
  2. Leakage listed: the `"stripe"` default-provider literal in `core/billing/commercial.py`; `verify_stripe_webhook_signature()` returning `stripe.Event` (already recorded in ADR-0008). No provider name in any migration, table or column.
  3. Billing and backup destination are consumer-pluggable today. Identity (any OIDC issuer, one class) and secrets (environment-selected) are not class-pluggable by documented design. Email is pluggable for product-sent mail and SMTP-only for platform notification mail. Each non-pluggable seam has a recorded decision request in the review's §4; the recommendation for all of them is no change now.

## P8 — Repository hygiene and final certification

- **Objective**: address stale documentation, CI coverage, the unresolved Phase 9 self-learning specification, the stray `Caddyfile;C` directory and the other audit findings; distinguish fixes from items needing separate authorization; finish with a roadmap-wide audit and a consumer-readiness assessment.
- **Files/Modules Affected**: `README.md`, `docs/ADR/README.md`, this document.
- **Dependencies**: P1–P7.
- **Tests**: `ruff`, `pyright`, `lint-imports`, default `pytest`, `pytest -m integration` against disposable PostgreSQL and Redis, `pytest -m packaging`, `scripts/check-frontend.sh`, `scripts/check-security.sh`, and the Docker checks where the environment allows.
- **Security Requirements**: an independent review of the final diff; no security gate or test weakened.
- **Acceptance Criteria**:
  1. `README.md` no longer contradicts the implemented state.
  2. Every audit finding is either fixed, converted into a decision request, or recorded as deferred with a reason.
  3. Validation results distinguish passed, failed, skipped, not run, environment-blocked, pre-existing and newly introduced.
  4. No pre-existing working-tree change was lost or absorbed.
  5. A consumer-readiness assessment is recorded.
- **Rollback Strategy**: revert the documentation edits.
- **Outcome**: **PASS WITH LIMITATIONS**.
  1. `README.md`: the layout table, the "no entrypoint/schema/worker exists yet" paragraph, the `infra/db` configuration paragraph, the CI job list (five → seven) and the secrets paragraph now match the implemented state; a pointer to the consumer guide and the reserved import names was added.
  2. Audit findings: see "Original audit findings" below for each one's disposition.
  3. Validation of the final working tree (2026-10-11):

     | Check | Result |
     |---|---|
     | `ruff check .`, `ruff format --check .` | clean (677 files) |
     | `pyright` | 0 errors |
     | `lint-imports` | 13 kept, 0 broken |
     | `pytest` (default) | 2596 passed, 89 skipped, 2 failed — the two baseline failures in `tests/architecture/test_secrets_gate.py`, unchanged from before this roadmap (see below) |
     | `pytest -m packaging tests/test_wheel_contents.py` | 5 passed |
     | `scripts/check-migrations.sh`, fresh PostgreSQL 16 | passed (7 + 7 + 1; includes `tests/test_reference_consumer_integration.py`) |
     | `scripts/check-integration.sh`, fresh PostgreSQL 16 and Redis 7 | 1853 passed, 0 skipped, gate green; run twice, before and after the review fixes |
     | `scripts/check-frontend.sh` | typecheck, lint, 52 tests, build: passed |
     | `scripts/check-docker.sh` | **passed** after the fix below: both images build; backend liveness, readiness, 401 route check and database-outage check; worker healthy, no host port, "worker executed the job", no secret in logs or image history, clean SIGTERM exit; frontend; Compose config. No container left behind |
     | `scripts/check-security.sh` (`pip-audit`, `npm audit`, secrets scan) | **not run** |
     | `scripts/check-docker-prod.sh`, `check-docker-prod-tls.sh`, `check-single-origin.sh` | **not run** (no file they cover changed) |
     | Four integration files `check-integration.sh` itself excludes (live Stripe, live ZITADEL, live GitHub) | **not run** — need external accounts |
     | 88 Caddy-dependent tests, 1 POSIX-permission test | skipped — no `caddy` binary on this host; Windows |
     | CI | **not run** — nothing was pushed |

  4. Pre-existing work: `CLAUDE.md` untouched. `.secrets.baseline` was damaged by this run and **restored** — see "Baseline incident" below.
  5. Consumer-readiness assessment: see the section of that name below.
  - **Secrets-gate failures.** The two remaining failures (`test_clean_repository_gate_succeeds`, `test_approved_false_positive_remains_accepted`) both report "Your baseline file (.secrets.baseline) is unstaged" and are the baseline failures recorded before any change. They need the owner to stage or commit the baseline; staging was outside this roadmap's authorization and was not done.
  - **Stray `Caddyfile;C` directory**: empty, untracked, referenced nowhere; removed with `rmdir`.
  - **`scripts/check-docker.sh` fixed** (authorized separately on 2026-10-11): the job-execution step called `core.usage.ingest_event(tenant_id, metric, quantity)`, the signature Phase 5.2 replaced. It now calls `ingest_event(session, tenant_id, metric, quantity)` inside `infra.db.tenant_session_scope`, as the integration tests do. No assertion was removed or relaxed and the 30-second deadline is unchanged; the step now also exercises the outbox dispatch cycle, because that is how ingestion reaches the worker since ADR-0032/0033.
  - **Baseline incident.** `detect-secrets scan --baseline .secrets.baseline <files>`, run to check new files, rewrote the owner's uncommitted baseline (101,977 bytes) to 3,179 bytes. It was rebuilt from the copy `tests/architecture/test_secrets_gate.py` had written three minutes earlier (the baseline minus one entry; that entry re-added from HEAD after re-scanning its file). Verified before restoring: 101,977 bytes; 2,724 CRLF lines; 27 changed lines against HEAD (26 `line_number`, 1 `generated_at`), the first five matching the diff seen at the start of the run; the same 152 files and 286 entries as HEAD with identical type, hash and review flags; `generated_at` equal to the original file's modification time. Restored on the owner's instruction (SHA-256 `2d9dcb80…1cc474`); the two tests the damage had broken pass again; the in-repository recovery copy was removed and backups are kept outside the repository. There is no byte-for-byte copy of the original to compare against, so this is a reconstruction with strong evidence, not a proven identity.
  - **Not fixed, needs separate authorization**: CI on HEAD (needs a pull request); Phase 9 re-certification; the `Phase 10.1` references in `frontend/`; the latent test-selection defect described in the ledger.

---

## Progress checklist

| Phase | Implementation | Tests | Audit | Status |
|---|---|---|---|---|
| P1 | `saas_os` root, hard cut (ADR-0038) | namespace contract + text-file tests; wheel top-level names; full integration gate green on the final tree | independent AST comparison of every moved module | **PASS WITH LIMITATIONS** — `.secrets.baseline` must be replaced by the owner (proposal prepared) |
| P2 | pins marked stale; working-tree wheel proofs | both consumer integration tests pass in the full gate | reviewed | **PASS WITH LIMITATIONS** — no published commit contains this code |
| P3 | scaffold, guide, worker seam (ADR-0039) | 44 static, 38 worker; negative control | two independent reviews | **PASS** |
| P4 | 5 opt-in routers, 18 routes (ADR-0040); last-administrator rule (ADR-0043); CSRF check (ADR-0044) | 25 contract, 34 integration, 25 + 85 for the two controls | independent review; both MEDIUM findings resolved | **PASS WITH LIMITATIONS** — four route groups blocked on decisions |
| P5 | extras (ADR-0041) | 9 hermetic; minimal + each extra install | reviewed | **PASS** |
| P6 | ADR-0042 accepted; architecture doc aligned; 4 of 5 frontend advisories fixed | frontend checks pass | reviewed | **PASS WITH LIMITATIONS** — one unpatched dev-only advisory |
| P7 | provider bound at router registration | covered by P4/P5 tests | reviewed | **PASS** |
| P8 | README, ADR index, Docker check fixes, full final-tree validation | run-3 table | independent review | **PASS WITH LIMITATIONS** — security script fails on the unpatched advisory; plain production check fails; CI not run |

## Blocker register

| # | Item | Blocks | Needs |
|---|---|---|---|
| B7 | Publication | — | **Done in run 6**: committed in a logical sequence and pushed; see the pull request for CI |
| B8 | `.secrets.baseline` keyed by the old file paths | — | **Resolved in run 6**: replaced with the verified re-keyed file, in its own commit |
| B11 | Tenant lifecycle (G1), invitation accept (G2), API-key request authentication (G3), inbound billing webhook (G4) | Those routes | The decisions listed per group in ADR-0040 |
| B12 | `braces` advisory GHSA-vfj7-8cjw-p6xm, no patched release | Nothing while the exception holds | **Accepted until 2027-01-11** (run 6); not fixed; review per `docs/SECURITY-EXCEPTION-braces.md` |
| B13 | The last-administrator rule was judged per tenant | — | **Resolved in run 6**: hierarchy-wide (ADR-0043) |
| — | Resolved: B1 (baseline damage, run 1), B2–B6 (ADR decisions), B9 (last administrator → ADR-0043), B10 (CSRF → ADR-0044) | — | — |

## Original audit findings (2026-10-11), preserved, with disposition

| # | Finding | Disposition |
|---|---|---|
| 1 | No real consumer has ever existed; the reference consumer pinned a placeholder; no Git tag exists | **Partly closed (P2)**: real exact-SHA pin, proven by a clean Git install. Still no real product and no tag — by design (ADR-0015 rule 12) and not in scope |
| 2 | The HTTP surface is health, auth and one tenant-status route; API-key HTTP authentication is an explicit non-goal; no inbound billing webhook route | **Decision prepared (P4)**: matrix and ADR-0040. Nothing implemented |
| 3 | Top-level import names `core`, `infra`, `api`, `contracts` are generic | **Decision prepared (P1)**: ADR-0038; names pinned by a test; reserved-names rule documented |
| 4 | No scaffold and no consumer guide; grants and application-role handling hand-written per product | **Closed (P3)**. Grants are still written per migration, now from a tested pattern; no grant helper was added |
| 5 | Dependencies all-or-nothing; lower bounds only; static version; no changelog; Python 3.13+ only | **Decision prepared (P5)**: ADR-0041. Lazy-import property pinned by a test |
| 6 | The frontend is a placeholder plus i18n and is not distributed | **Decision prepared (P6)**: ADR-0042 |
| 7 | One adapter per provider seam | **Reviewed (P7)**: adequate for OIDC, Stripe or a product's own billing adapter, SMTP, environment-injected secrets, S3-compatible backup. No change |
| 8a | 15 commits without a CI run | **Open** — needs a pull request (B7). The same suites were run locally instead |
| 8b | Stale `README.md` sections | **Closed (P8)** |
| 8c | Phase 9 not certified against its recovered specification | **Open, deferred**. Its integration tests pass as part of the full gate; re-certification against the recovered criteria was not attempted |
| 8d | Stray `Caddyfile;C` directory | **Closed (P8)** |
| 8e | Secrets-gate tests failing on the uncommitted baseline | **Open, unchanged** — the same two tests fail for the same reason as before the roadmap. This run damaged the baseline and restored it (P8, "Baseline incident") |

## Consumer-readiness assessment

**Can an independent product be built on SaaS OS without modifying SaaS OS?** Yes for the backend. The work is published: `main` at `58d134f` (run 7), and with ADR-0045's platform authority at `3677c86` (2026-10-14), which both example pins name.

Proven on the final working tree, from an installed wheel outside the repository and on the full integration gate: one unambiguous import root; installation with or without each provider SDK; both migration histories; a product schema with forced RLS; a permission-gated product route; a product job on the platform worker; tenant purge of product data; platform routers for membership, invitations, a member's own API keys, billing subscriptions and usage, each refused without its permission and to other tenants; a tenant that cannot lose its last administrator through membership changes; and cookie-authenticated mutations that cannot be forged from another origin.

What a first product still has to do or accept:

1. **Pin `3677c86` or later.** Earlier commits lack ADR-0045's required callers and platform authority; before `58d134f` they also lack the `saas_os` import root, the worker seam and the extras.
2. **Send `Origin` on cookie-authenticated mutations** — a browser does; a script must, or use a Bearer header.
3. **Give `membership_role:create` to more than one person per tenant.** Since run 6 a change that would leave a tenant without an administrator is refused, including from a parent tenant; an expiring delegation does not count (ADR-0043).
4. **Write its own**: sign-up and tenant creation, invitation acceptance, machine-to-machine authentication, webhook and feature-flag administration, usage ingestion, the inbound billing webhook, and its whole frontend.

Unproven: any real product; live Stripe, ZITADEL and GitHub paths. Remote CI (Linux) passed on the merged head; the local runs were on Windows.

## Deferred issue ledger

Carried forward unchanged from `docs/IMPLEMENTATION-ROADMAP.md` and earlier audits; this roadmap does not close them unless a row says so.

| Issue | Severity | Scope | Status | Required phase |
|---|---|---|---|---|
| Phase 9.1–9.9 self-learning not re-certified against its recovered specification; original acceptance criteria unrecoverable | MEDIUM | Later | Deferred | Separate authorization (recorded under P8) |
| Autonomous support, incident-resolution and DevOps agents | LOW | Later | Deferred | Phase 9+ |
| Auto-update CLI: commits/pushes/PRs, lock-file rewriting, migration execution, release channels and semantic versioning, multi-repository orchestration, scheduling, remote fetch, signature verification, `--source` identity proof | LOW | Later | Deferred | Post-5.3 item, unscheduled |
| Private package index (ADR-0015 "not decided") | LOW | Later | Deferred | When multi-project friction justifies it |
| Major-version support-window policy (ADR-0015 "not decided") | LOW | Later | Deferred | With P5's versioning decision |
| Whether `infra/db/backup` ships in the consumer package (ADR-0015 "not decided") | LOW | Later | Deferred | With P5's extras decision |
| Physical split of `api/` into library and application packages (ADR-0017 "not decided") | LOW | Later | Deferred | With P1's namespace decision |
| Classification of `api/v1/tenant_status.py` (ADR-0017 "not decided") | LOW | Later | Deferred | With P4's decision |
| Observability backend vendor (ADR-0009) | LOW | Later | Deferred | Unscheduled |
| Redis has no persistence in the development Compose file; queued and dead-lettered jobs are lost on restart (`README.md`) | MEDIUM | Later | Deferred | Production perimeter/DR remediation |
| Product Contract (Phase 6.1) has one test file — coverage gap, not a functional gap | LOW | Later | Deferred | Unscheduled |
| Audit-PII test-field finding (`CLAUDE.md` §12) | LOW | Later | Deferred | Unscheduled |
| ADR-0023 (Draft) and ADR-0026 (Draft, not accepted) identity alternatives | — | Later | Open decisions | Unscheduled |
| Secrets-gate tests fail while `.secrets.baseline` is modified but unstaged | LOW | Current | Pre-existing, documented | User action (stage/commit the baseline) |
| HEAD has no CI run (15 commits past `main`, no pull request) | MEDIUM | Current | Documented | User action (open a pull request) |
| `.secrets.baseline` damaged during the P-roadmap run | MEDIUM | Current | **Resolved** — restored from a verified reconstruction; backups kept outside the repository | — |
| `scripts/check-docker.sh` called `core.usage.ingest_event` with its pre-Phase-5.2 signature, so the Docker check (and CI's `docker` job) failed with `TypeError` on HEAD | MEDIUM | Current | **Resolved** — corrected and the full Docker check passes (P8). CI itself has still not run | — |
| Narrow pytest selections that include a top-level `tests/test_*.py` file put `tests/` on `sys.path`, where `tests/control_plane/` shadows the `control_plane` package: `pytest tests/test_wheel_contents.py tests/infra/jobs/test_typed_job_contexts_unit.py` fails 2 tests on untouched files. The full default suite is unaffected | LOW | Later | Pre-existing, found during P3 | Unscheduled |
| Ten `frontend/` files cite "docs/IMPLEMENTATION-ROADMAP.md Phase 10.1", which that roadmap does not define | LOW | Later | Found during P6 | With ADR-0042's decision |
| `system_cron` sets arq `max_tries=1` while the job wrapper allows three attempts, so a failed scheduled run (including the platform outbox dispatch cycle) is dropped by arq without a dead-letter record. Reported by the independent review from reading the code, not reproduced by a test; pre-existing | MEDIUM | Later | Deferred — `infra/jobs` reliability semantics (ADR-0033) are outside P scope | Reliability follow-up |
| `docs/API-ARCHITECTURE.md:17` assigns capability routes to Core modules; every Core module says it owns no HTTP surface | LOW | Later | Found during P4 | With ADR-0040's decision |
| Notification email is SMTP-only; `"stripe"` literal in `core/billing/commercial.py`; `verify_stripe_webhook_signature()` returns `stripe.Event` | LOW | Later | Recorded in `docs/architecture/PROVIDER-EXTENSIBILITY-REVIEW.md` | With Billing Foundation v2 Phase 6 / first need |
| `examples/reference-consumer` migration uses `ALTER DEFAULT PRIVILEGES`, which `docs/CONSUMER-GUIDE.md` advises against | LOW | Later | Found by the independent review | Unscheduled |
| `my_product/worker.py` imports its jobs before `api.worker.main()`, so a missing `REDIS_URL` is a traceback (still a non-zero exit) instead of the structured `worker_startup_failed` log line | LOW | Later | Found by the independent review | Unscheduled |
| Narrow pytest selections put `tests/` on `sys.path`, where `tests/control_plane/` shadowed the `control_plane` package | LOW | — | **Resolved by ADR-0038** — the package is `saas_os.control_plane` | — |
| `.secrets.baseline` paths are stale after the rename (blocker B8) | MEDIUM | Current | **Resolved in run 6** (blocker register, B8): replaced with the verified re-keyed file. The secrets gate has passed against the committed baseline on every pull request since | — |
| No last-administrator guard on membership suspend/revoke | MEDIUM | — | **Resolved in run 3** (ADR-0043) | — |
| The last-administrator rule did not cover role removal, permission revocation, deny grants or delegation revocation | MEDIUM | — | **Resolved in run 4** (ADR-0043 extended); role deletion needs no guard; user deactivation has no Core function | — |
| The last-administrator rule did not protect a tenant from ancestor mutations, `move_tenant`, ancestor suspension or delegation expiry (B13) | MEDIUM | — | **Resolved in run 6** (ADR-0043 extended) | — |
| Two deny grants in unrelated tenants, each denying a user who is a member of the other, can deadlock on user-row locks; PostgreSQL aborts one and nothing changes | LOW | Later | Documented in ADR-0043 | Unscheduled |
| Core has no user-deactivation function; when one is added it must call the administrator guard | LOW | Later | **Resolved in ADR-0045 Phase C (merged, pull request #13)** -- `deactivate_user` guards every tenant the user is an active member of (`guard_tenants`) and is refused for a last administrator; race tests in `tests/core/platform_authority/` | — |
| `frontend/Dockerfile` left development dependencies in the production image | LOW | — | **Resolved in run 5** — two-stage build; `next.config.mjs` | — |
| `scripts/check-security.sh` stopped at the first failing step, hiding the secrets scan | LOW | — | **Resolved in run 5** — all three checks run; any failure fails the script | — |
| `scripts/check-security.sh` passed every tracked file name on one command line, exceeding the Windows limit | LOW | — | **Resolved in run 6** — file list through `xargs` | — |
| `detect-secrets-hook` rewrites the baseline it is given when findings do not match, so running `scripts/check-security.sh` locally with a stale baseline modifies `.secrets.baseline` | LOW | Later | Found in run 6; behaviour of the tool | Unscheduled |
| CSRF on cookie-authenticated unsafe methods | MEDIUM | — | **Resolved in run 3** (ADR-0044) | — |
| `npm audit`: 9 findings in run 2 → 4 advisories fixed in run 3; one remains (`braces`, GHSA-vfj7-8cjw-p6xm, no patched release, development tooling only, counted five times) (B12) | HIGH by advisory; no production exposure (`npm audit --omit=dev`: 0) | Current | Open — not suppressed | Upstream fix |
| Capability list routes page in Python over unbounded Core lists | LOW | Later | Found by the run-2 review | Core `limit`/`offset` |
| API keys issued over HTTP never expire and outlive a membership suspension | LOW | Later | Found by the run-2 review | With API-key request authentication (G3) |
| `scripts/check-docker-prod.sh` fails at its migration step without TLS to PostgreSQL | LOW | — | **Dispositioned in run 4** — intended (ADR-0021, ADR-0027); `scripts/check-docker-prod-tls.sh` is the production validation | — |
| `tests/core/billing/test_billing_projections_unit.py:120` names a module (`core.billing.lifecycle_writer`) that exists in neither layout | LOW | Later | Pre-existing dead entry, found by the run-2 review | Unscheduled |
| ADR-0041's startup check for a configured-but-missing provider SDK is not implemented; the failure is at first use | LOW | Later | Open | Unscheduled |
| Constraints file and versioning policy (ADR-0041 options 2C, 3B) | LOW | Later | Not adopted | Owner decision |
| The tenant RBAC transitive import contract conflicts with ADR-0045 section 12a. Core enforcement requires `saas_os.core.tenancy` to call `authorize_platform_caller`, but the merged import-linter contract "Tenant RBAC does not depend on platform authority" is transitive and `saas_os.core.rbac` imports `saas_os.core.tenancy`, so the contract prohibits that dependency path. Blocks ADR-0045 Phases C–F. Found 2026-10-12 before any Phase C change | MEDIUM | — | **Resolved 2026-10-12** — merged into `main` (pull request #11, merge commit `da2c8c1`). The owner approved a direct-import rule (`allow_indirect_imports = true`) with a pinned list of direct importers, documented in ADR-0045. Local validation: 15 import contracts kept; default suite 3017 passed; integration gate 2138 passed with zero skips. Remote CI passed all seven checks on the pull request head (`bbc7b65`). Phases C–F remain unimplemented and unauthorized | — |
| `revoke_api_key` locks the key row before the caller's user row, the opposite of the order `deactivate_user` uses; a user revoking their own key while being deactivated can deadlock, and PostgreSQL aborts one of the two (fails closed) | LOW | Later | Found in ADR-0045 Phase C; pre-existing order, documented in ADR-0045 | Unscheduled |
| `deactivate_user` can deadlock with a guarded mutation the user runs by inherited authority, and with a guarded mutation in a subtree moved while it runs; PostgreSQL aborts one, no invariant is violated, and a caller sees a database error instead of a refusal | LOW | Later | **Unresolved concurrency risk; locking unchanged by owner decision 2026-10-13.** Forced by test (race cases 5 and 7): one transaction is aborted, nothing is left half-done, a repeat succeeds with one success row. Preconditions, lock sequences, reachability and what would eliminate each cycle are in ADR-0045, "Residual concurrency risks" | Future owner/ADR decision: a deadlock retry, or a lock-order change in ADR-0043 (case 5) or the hierarchy lock in the deactivation (case 7) |
| ADR-0045 sections 8 and 9d disagree on when an oversight read's audit row is written: 9d inserts it before the page read, 8 has it record the number of entries returned. One immutable row cannot do both. Phase C writes it after the global page read and before any tenant scope; the final audit found no way to meet both sections without a second event, a changed row or a new mechanism | LOW | Current | **Resolved in ADR-0045 Phase C (merged, pull request #13)** -- owner decision 2026-10-13: both sections amended to two rows, an attempt committed before the read and a completion in the read transaction carrying the count and the attempt's id. Implemented for both reads; tested in `tests/core/platform_authority/test_oversight_audit_events_integration.py` | — |
| `erase_user_identity` does not refuse a user who has a non-revoked platform operator row (ADR-0045 section 6) | MEDIUM | Later | **Resolved in ADR-0045 Phase C (merged, pull request #13)** -- owner decision 2026-10-13: refused before anything is erased, with one `denied` row; tested in `tests/core/platform_authority/test_operator_erasure_integration.py` | — |
| No limit on API keys per user: platform key revocation and its per-key evidence are bounded by one user's key count, not by a constant | LOW | Later | Found in ADR-0045 Phase C; stated in the function's documentation | Unscheduled |
| `transition_tenant_status` reads the tenant and validates the edge before it authorizes (the read is required to select the operation): a caller with no authority learns whether a tenant exists and its status from `TenantNotFoundError` or `InvalidTenantTransitionError`, and no `denied` row is written for that call. In-process only; there is no route | LOW | Later | **Resolved before ADR-0045 Phase D (merged, pull request #15)**, 2026-10-13: a preliminary gate refuses a caller who could be authorized for no operation the target can select, before the tenant is read or locked, with one `denied` row and the same answer for a missing tenant and for every status; the decision is repeated under lock. Tested in `tests/core/platform_authority/test_transition_disclosure_integration.py`; with the gate removed its control fails. A target no edge leads to (`PENDING`) is refused as an invalid request before anything is read. Residual, accepted and documented in ADR-0045 section 12: for an `ACTIVE` target a caller who holds, under lock, the activation or the reactivation authority can learn that a tenant is missing, its status when the edge is invalid, or that it needs the other one | — |
| `move_tenant` takes the subtree's administrator locks after the authorization row locks, against the order ADR-0045 section 11c fixes; an operator moving a subtree they are a member of, while being deactivated, can deadlock with the deactivation. PostgreSQL aborts one; nothing is left half-done | LOW | Later | **Resolved in ADR-0045 Phase C (merged, pull request #13)** -- owner decision 2026-10-13: the subtree's administrator locks are taken before the authorization. Both orderings of the race are forced in `test_user_deactivation_race_integration.py` (race 8) with no transaction aborted; with the correction removed, both tests fail | — |
| `read_tenant_registry_entry` for a tenant id that does not exist raises `TenantNotFoundError` after authorization and writes no audit row, so an authorized operator can probe ids without evidence | LOW | Current | **Resolved in ADR-0045 Phase C (merged, pull request #13)** -- both audit rows of the call (the completion with `returned: 0`, the id as `target_id`) are committed before `TenantNotFoundError` is raised; an unauthorized caller is refused before the lookup. Tested in `tests/core/platform_authority/test_flags_and_oversight_integration.py` | — |
| `move_tenant` accepts a `SUSPENDED` new parent. ADR-0045 section 12a says nobody attaches a child to a suspended tenant, and states it for creation only | LOW | Later | Found by the Phase C final audit; the ADR is silent for a move | Owner ruling |
| `_transition_operation` falls through to the purge operation for any target it does not match. A target that is not a `TenantStatus` is refused today only because a later attribute access fails before any change | LOW | Current | **Resolved in ADR-0045 Phase C (merged, pull request #13)** -- every edge of the lifecycle graph is named and there is no default; a pair that is not an edge, and a target that is not a `TenantStatus`, are refused. Tested in `tests/core/tenancy/test_transition_operation_unit.py` | — |
| The oversight transactions carry no statement timeout. ADR-0045 section 9d says they should and leaves the helper to Phase C; the repository has none | LOW | Later | **Resolved before ADR-0045 Phase D (merged, pull request #15)**, 2026-10-13; the accepted deferral is closed. Both transactions of each oversight read set a transaction-local statement timeout (`PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS`, default 5000 ms, 100 to 60000, validated at startup) and raise `OversightReadTimeoutError` when PostgreSQL cancels a statement. Tested in `tests/core/platform_authority/test_oversight_read_timeout_integration.py`; with the timeout removed the same call waits for as long as the lock is held | — |
| `purge_tenant` makes its `PURGING` and `PURGED` transitions inline, takes no caller and writes no `platform.tenant.purge_transition` row; only a direct `transition_tenant_status` call does | LOW | Later | Disclosed in ADR-0045 ("Implementation status"); `purge_tenant` is outside the Phase C code list | Owner decision on the phase |
| A tenant's self-service suspension leaves no platform audit row (ADR-0045 section 5b): who suspended it and why is recorded only in that tenant's own trail, which no platform permission reads | LOW | Later | As the ADR specifies; recorded for the reactivation workflow | ADR-0045 Phase D design |
| `rotate_api_key` issues a new live key from a key that is already revoked, so after `revoke_user_api_keys` an active owner can obtain a key by rotation as well as by creation | LOW | Later | Rotation behaviour predates Phase C; ADR-0045 section 11f names the creation case only | Unscheduled |
| `erase_user_identity` checks for an enrolled operator before it erases, under the platform-owners lock, but erasure spans several transactions: an enrollment of the same user that commits after the check and before the erasure finishes is not seen, and leaves an operator whose identity link is gone. The same state is reached with no race: erasure leaves the `core.users` row in place and active, and `enroll_operator` requires only an existing, active user, so a user who was already erased can be enrolled and granted afterwards. **The implementation does not enforce the invariant that an enrolled operator has a valid external identity**; the owner predicate does not look at the identity link, so such an operator can count as a platform owner who cannot log in | LOW | Later | **Accepted as LOW for Phase C (owner decision, 2026-10-13); not corrected, no locking or contract changed.** Found while implementing the ADR-0045 section 6 safeguard and extended by the pre-publication review; the safeguard guarantees only that an operator row committed and not revoked at the check refuses the erasure. Erasure is an operator-run command and enrollment needs a platform owner, so both are deliberate acts by trusted people; recovery is the bootstrap `recover` command. Detail in ADR-0045, "Implementation status" | Future owner/ADR decision, with the packaged erasure command: enrollment refusing a user with no external identity (a change to the enrollment contract) and erasure removing the identity link in the transaction of its check. Does not block Phase C |
| An oversight read whose attempt row is committed and whose process then stops leaves an attempt with no completion, `denied` or `failure` row; a reader of the platform audit must treat that as a read that did not complete | LOW | Later | By design of the two-event model (ADR-0045 section 8); nothing reads the platform audit yet | Open. A reader of `GET /v1/platform/audit` treats an attempt with no completion, `denied` or `failure` row as a read that did not complete; documented in ADR-0045 section 8. No further work planned |
| `EnrolledOperatorErasureError` carries the operation name `user.erase`, which is not a key of the declared operation table (erasure is not a platform operation); a handler that looks every refusal's operation up in the table would not find it | LOW | Later | **Resolved before ADR-0045 Phase D (merged, pull request #15)**, 2026-10-13: `user.erase` stays outside the operation table; it is one of a closed, declared set of four refusal labels that are not operations (`NON_OPERATION_REFUSALS`), a refusal cannot be constructed with any other label, and a handler maps a refusal by type and code. Proved by `tests/architecture/test_platform_refusal_labels.py` | — |
| `move_tenant` reads the subtree and takes its administrator locks before it authorizes (required by the lock order of ADR-0045 section 11c), so a caller with no authority causes that work before being refused; `erase_user_identity` takes the platform-owners lock for its check and waits behind a running deactivation | LOW | Later | Found by the review; in-process only, discloses nothing | Open. Neither function has a route (ADR-0045 section 7), so no rate limit applies; future owner decision with the packaged operator commands |
| Outside the oversight reads no platform transaction carries a statement or lock timeout: the writers of `denied` and `failure` rows (`record_platform_refusal`) and every platform mutation wait for a lock for as long as it is held. Observed while testing the oversight timeout: an `ACCESS EXCLUSIVE` lock on `core.tenants` held an audit insert until it was released | LOW | Later | Found before ADR-0045 Phase D, 2026-10-13. Not changed: ADR-0045 section 9d asks for the timeout on the oversight reads only, and a timeout on a mutation or on a best-effort evidence writer changes what those do when they are slow. Existing mitigation: such locks are taken by migrations and by the short transactions of the platform operations themselves | Owner decision, with the Phase D error mapping: whether platform mutations and the refusal writers get a timeout. Does not block Phase D |
| `transition_tenant_status` admits every member of a tenant whose membership is not revoked to its preliminary gate when the target is `SUSPENDED` (the self-service rule can only admit one of them). Such a caller is then refused by the decision under lock, after the administrator locks and the tenant's row lock were taken: a member without the permission can make the transaction take those locks briefly | LOW | Later | **Mitigated in ADR-0045 Phase D milestone 2 (merged, pull request #18)**: the self-service route requires `tenant:suspend` in the tenant chain before Core is called, and is rate limited per tenant and path; a member without the permission is refused by the chain (`403`) and never reaches the transaction. An in-process caller still can. Discloses nothing | — |
| `list_platform_audit` pages by keyset on the primary key, as ADR-0045 section 9d fixes it. The key is random, so a page is not chronological, and a page in key order may not use the indexes the table has on its filter columns (`created_at`, `actor_user_id`, the target, `target_tenant_id`) | LOW | Later | Found by the review of ADR-0045 Phase D milestone 1, 2026-10-13; corrected at the Phase F review, which found that this row had wrongly said the table had no index besides its key. Bounded by the oversight statement timeout and the page maximum | Owner decision: whether the keyset of section 9d becomes chronological (`created_at`, `id`), which changes a cursor contract. Does not block anything |
| Every call of `list_platform_audit` writes two rows into the table it reads; paging the whole table with a very small page size inflates it | LOW | Later | **Mitigated in ADR-0045 Phase D milestone 2 (merged, pull request #18)**: the route `GET /v1/platform/audit` is rate limited per actor and route, failing closed, and offers the filters, so a filtered read is the ordinary use. By design of the two-event audit (ADR-0045 section 8); a minimum page size was not imposed | Future owner decision, only if growth is observed. Does not block Phase E |
| A holder of `platform.feature_flag:read` learns whether a tenant id exists from `read_tenant_flag_overrides` (`TenantNotFoundError`, after both audit rows), without holding `platform.tenant:read` | LOW | Later | As the failure table of ADR-0045 section 9d specifies for a named tenant; every such call leaves two rows | Future owner decision, only if the two permissions are to be separable. Does not block Phase D |
| A caller who is not an operator can tell a platform path from an unknown one by answers given before the operator check: `401` without a credential, `405` for a method the path does not serve, `422` for a body that is not JSON, `403` for a cross-origin cookie mutation, `429` or `503` from the rate limit | LOW | Later | By the chain order ADR-0045 section 7 fixes and by the framework's own routing; listed in ADR-0045 ("Implementation status", Phase D milestone 2) and pinned by a test. The route set is not secret: it is in the source. Everything behind a route is concealed | Future owner decision, only if the route set is to be concealed (a custom route class under `/v1/platform`). Does not block Phase E |
| The tenant chain's `can()` admits a delegate or an inherited role to `POST /v1/tenants/{tenant_id}/suspend`, which Core's narrower self-service rule then refuses; such a caller makes the transition take the tenant's administrator locks and row lock briefly before the refusal | LOW | Later | Found implementing ADR-0045 Phase D milestone 2. Fails closed (`403`, one `denied` platform row); bounded by the tenant rate limit | Future owner decision: a route-level pre-check with Core's own rule. Does not block Phase E |
| A deployment identifier checked against platform grants, so that a cloned or restored database carries no usable authority into another environment (ADR-0045, deferred, "reconsider after Phase F") | LOW | Later | Reconsidered at the Phase F closure audit, 2026-10-13: two deployments share nothing (`test_cross_deployment_isolation_integration.py`), and a copy of a database is a copy of its authority by design; `docs/RUNBOOKS.md` ("Restoring or cloning a database") gives the procedure. Not implemented | Owner decision. Does not block anything |
