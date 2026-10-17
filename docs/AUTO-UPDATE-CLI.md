# SaaS-OS consumer auto-update CLI (`saas-os-update`)

Status: implemented (post-Phase 5.3 roadmap item). Decision record: [ADR-0015](ADR/0015-saas-os-distribution-and-consumer-boundary.md), "Amendment (2026-10-03): consumer update tooling". Policy source of truth: `saas_os/infra/update/policy.py`.

## Purpose

`saas-os-update` lets a consuming project move its SaaS-OS dependency pin to a newer revision safely. The pin is the `saas-os @ git+<url>@<sha>` requirement (ADR-0015 rules 7–8).

The tool is not a `git pull`, a merge tool or a code migrator. It does six things:

1. finds the candidate commit and inspects what changed;
2. classifies the change;
3. decides **SAFE**, **REVIEW_REQUIRED** or **BLOCKED**;
4. applies only a SAFE update, by rewriting the single pin to the candidate's exact SHA;
5. runs the project's own validation;
6. rolls the pin back, and verifies the rollback, if anything fails.

It never commits, pushes, fetches, stashes, resets, opens pull requests or edits any other file.

## Commands

```text
saas-os-update check  --source <saas-os clone> --candidate <sha|ref> [--consumer <dir>] [--format text|json]
saas-os-update update --source <saas-os clone> --candidate <sha|ref> [--consumer <dir>] [--format text|json]
```

- **`check`** analyzes and explains the decision. It changes nothing; this is also the *plan/explain* view.
- **`update`** runs the full transaction (below).
- **`--source`** is a local clone of SaaS-OS that the caller has already fetched. The tool makes no network access, uses no hosting-provider API and needs no credentials.
- **`--candidate`** may be an exact SHA or, for discovery, a branch or tag. A ref is resolved to its commit in `--source`, and **the pin always records the exact 40-character SHA**, never the ref.
- **`--consumer`** must be the root of the consuming project's Git working tree (default: the current directory).

## Consumer configuration

In the consumer's `pyproject.toml`:

```toml
[tool.saas-os-update]
validation = [
    ["python", "-m", "pytest", "-q"],
    ["python", "-m", "ruff", "check", "."],
    ["python", "-m", "pyright"],
]
timeout_seconds = 1800          # optional, per check (default 3600)
pin_files = ["pyproject.toml"]  # optional; default: pyproject.toml, requirements*.txt, requirements/*.txt
```

- Each validation command is an argument vector, never a shell string. Commands run in the consumer root with no stdin.
- Their output is discarded: it is never echoed or stored, so it cannot leak secrets into the report.
- `update` refuses to run without at least one validation command (`validation_not_configured`): an update is never accepted unvalidated.
- Parsing is strict. An unknown key or a wrong type is `config_malformed` (BLOCKED).
- The table configures *what to run*. It cannot change the safety policy.

## Decisions

A decision only ever moves towards caution. Once any condition makes it REVIEW_REQUIRED or BLOCKED, nothing makes it SAFE again. Every reason is reported with a stable `code`.

### SAFE

All of these hold:
- the consumer root is a Git repository;
- the configuration is valid;
- exactly one pin exists and it is an exact SHA;
- both SHAs resolve to commits in `--source`;
- the candidate is a descendant of the pinned SHA;
- every changed path is in an automatic category (see Classification);
- no lock file also records the pinned SHA;
- the working tree is clean.

For `update`, additionally: validation is configured and the pin file is a regular file, so a byte-exact rollback is possible.

### UP_TO_DATE

The consumer already pins the candidate (`already_current`).

### REVIEW_REQUIRED

The tool stops before changing anything when:
- any changed path is in a category that requires review (`category:<name>`);
- the candidate is older than the pinned SHA (`candidate_older`, a downgrade);
- history has diverged (`candidate_diverged`);
- the candidate differs from the pin but changes no file (`no_file_changes`);
- the consumer has staged, modified or untracked files (`dirty_working_tree`). Local work is never stashed, reset or overwritten.

A human reviews the candidate and updates the pin through the normal repository workflow. The tool has no override flag.

### BLOCKED

The tool refuses when:
- the consumer is not a repository root (`consumer_not_repository`);
- the configuration is malformed (`config_malformed`);
- the pin is missing (`pin_missing`), is in more than one place (`pin_ambiguous`), cannot be read (`pin_unreadable`), or is not an exact SHA (`pin_not_exact_sha`); a pin file pattern is invalid (`pin_files_invalid`). A pin file must resolve inside the consumer root: a symlink or junction pointing outside it is never a pin file;
- `--source` is not a repository (`source_not_repository`);
- the candidate is an invalid ref (`candidate_invalid`) or names no commit (`candidate_unresolvable`);
- the pinned SHA is not in `--source` (`current_unverifiable`);
- a lock file also records the pinned SHA (`lock_file_references_pin`). The tool does not rewrite lock files.
- validation is not configured (`validation_not_configured`);
- rollback cannot be guaranteed (`rollback_not_guaranteed`);
- the analyzed state changed before applying (`stale_state`);
- the update failed after the pin was written (`update_failed`).

## Classification

Classification uses the **changed paths** between the pinned and candidate SHAs, never commit messages. Renames count as a deletion plus an addition, and deletions are classified like any other change. Each path takes the category of the first matching rule in `saas_os/infra/update/policy.py`; the order runs from the most security-sensitive rule to the broadest.

| Category | Examples | Automatic? |
|---|---|---|
| `updater_policy` | `saas_os/infra/update/` | no |
| `migration` | `saas_os/infra/db/migrations/`, `alembic.ini` | no |
| `tenant_rls` | `saas_os/infra/db/rls.py`, `saas_os/infra/db/session.py`, `saas_os/core/tenancy/` | no |
| `provider_boundary` | `saas_os/core/billing/provider*.py`, `saas_os/core/billing/stripe_provider.py`, `saas_os/infra/secrets/`, `saas_os/control_plane/inference/` | no |
| `billing` | `saas_os/core/billing/`, `saas_os/core/usage/` | no |
| `authorization` | `saas_os/core/authority/`, `saas_os/core/rbac/`, `saas_os/core/platform_authority/`, `saas_os/core/identity/`, `saas_os/core/api_keys/`, `saas_os/core/audit_log/`, `saas_os/api/auth/` | no |
| `security_control` | `saas_os/infra/db/init/` (application DB role), `saas_os/infra/db/backup/encryption.py`, `saas_os/core/webhooks/`, `saas_os/core/idempotency/`, `saas_os/core/outbox/`, `saas_os/infra/ratelimit/`, `saas_os/infra/egress/` | no |
| `autonomous_orchestration` | `saas_os/control_plane/orchestration/`, `development/`, `self_learning/` | no |
| `architecture` | `docs/ADR/`, `docs/ARCHITECTURE*.md` | no |
| `dependency_toolchain` | `pyproject.toml`, requirements, lock files, `scripts/`, CI, Docker | no |
| `public_api` | `saas_os/contracts/`, `saas_os/api/`, `saas_os/inference/`, package `__init__.py` exports | no |
| `tests` | `tests/`, `examples/` | **yes** |
| `documentation` | other `docs/`, `*.md` | **yes** |
| `internal` | other `saas_os/core/`, `saas_os/infra/`, `saas_os/control_plane/` | **yes** |
| `unknown` | anything else (e.g. `frontend/`, `deploy/`) | no |

- **Migrations** always require review, so migration validation never runs unattended.
- **A security fix** is applied automatically only if every path it touches falls in an automatic category. A fix inside an authorization, RLS, billing or provider path requires review.
- **Updater self-protection.** The policy is code in the SaaS-OS installation that runs the tool; it is never read from the candidate. A candidate that changes `saas_os/infra/update/` requires review, so a newer revision can never approve its own policy. Changing the policy means editing `policy.py`, bumping `POLICY_VERSION`, and going through normal human review. Policy version 2 (final closure audit, M1) added the `security_control` and `autonomous_orchestration` categories: security controls and the control plane's autonomous-execution machinery are never automatic. Tests and documentation about them, in `tests/` and `docs/`, stay automatic. Policy version 4 (ADR-0054, AI-B to AI-H) classifies the shared egress module `saas_os/infra/egress/` as `security_control`, the internal AI inference package `saas_os/control_plane/inference/` as `provider_boundary`, the platform authority package `saas_os/core/platform_authority/` as `authorization`, and the public inference interface `saas_os/inference/` as `public_api`. Before it, the first three matched the automatic `internal` rule (the platform authority package had since ADR-0045) and the last no rule.

## The update transaction

1. **Preflight** (`check` and `update`). The tool records:
   - the pinned SHA and the pin file's digest;
   - the consumer's HEAD;
   - the resolved candidate SHA.

   It then computes the diff, classifies it and decides.
2. **Stale-state check** (`update`, SAFE only). Immediately before writing, it re-resolves the candidate ref and re-reads the consumer's HEAD, the pin file's digest, the pinned SHA and the working tree. If any of them changed, it aborts with `stale_state` and writes nothing.
3. **Apply.** It replaces exactly the pin's ref, byte for byte elsewhere, with an atomic write. It then verifies that the pin reads back as the candidate and that the pin file is the only tracked change.
4. **Validate.** It runs the configured commands in order. After the first failure the remaining checks are reported `not_run`. A timeout or a command that cannot start is a failure. If validation changes any tracked file besides the pin file, that is also a failure.
5. **Accept or roll back.**
   - On success the outcome is `applied`. The pin change is left uncommitted for the project's normal review and commit.
   - On any failure the original bytes are restored and verified: `rolled_back` (exit 40). If the restore cannot be verified, the outcome is `rollback_failed` (exit 50), which needs manual intervention.

## Output and exit codes

`--format json` prints one JSON object (`schema_version: 1`). Its keys are:
- `command`, `policy` (version and SHA-256 digest of the rules), `decision`, `outcome`, `exit_code`;
- `consumer` (pin file, line, redacted URL, current SHA);
- `candidate` (ref, SHA, relationship, commit count, subject, commit date);
- `changes` (files with status and category, category counts, review categories);
- `reasons` (code, decision, detail);
- `checks` (argv, status, exit code, duration);
- `rollback` (attempted, verified).

A decision is reproducible from the current SHA, the candidate SHA, the classification, the policy version and digest, and the check results.

| Exit | Meaning |
|---|---|
| 0 | `check`: SAFE to apply. `update`: applied and validated |
| 2 | invalid command line |
| 10 | UP_TO_DATE |
| 20 | REVIEW_REQUIRED (nothing changed) |
| 30 | BLOCKED (nothing changed) |
| 40 | update applied, then validation (or the post-write verification) failed; rollback verified |
| 50 | rollback failed: the pin file may be modified, so fix it manually |

**Output hygiene.**
- Credentials embedded in a URL's user-info part (anything before `@` in the authority) are redacted in every field.
- The report never contains environment variables or validation command output.
- Commit metadata is limited to the subject and committer date (no author e-mail).

## CI usage

```sh
git -C ../saas-os fetch origin
saas-os-update check  --source ../saas-os --candidate origin/main --format json > update-check.json
saas-os-update update --source ../saas-os --candidate origin/main --format json > update.json
```

Branch on the exit code, not on prose. Exit 0 from `update` leaves a modified pin file for the pipeline's own commit and review step. The tool never commits or pushes.

## Limitations and deferred work

- **Repository identity.** The tool cannot prove that `--source` is the repository the pin URL names, because it has no network access. The consumer's validation installing the pinned SHA from the pin URL (dependency resolution) is that check.
- **No signature verification** of the candidate commit.
- **Pins.** Only one `git+` pin is supported. Lock files that record the pin block the update rather than being rewritten.
- **Validation output** is discarded; re-run a failing check locally to see it.
- **No override for REVIEW_REQUIRED.** Reviewed updates go through the normal workflow.
- **Explicitly deferred:**
  - automatic commits, pushes, pull requests and merges;
  - lock-file rewriting;
  - migration execution and consumer source migration;
  - release channels and semantic-version rules;
  - multi-repository orchestration;
  - scheduling or daemons;
  - remote fetching and hosting-provider integration;
  - commit-signature policy.
