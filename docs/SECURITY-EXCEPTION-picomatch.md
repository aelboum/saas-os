# Security-gate exception: `picomatch` GHSA-fc5q-39xc-vjpf

Status: **CLOSED** on 2026-11-20: GitHub withdrew the advisory on 2026-11-18, and the entry was removed from `scripts/security-exceptions.json` (section 7). It was **APPLIED** from 2026-11-17, by decision of the repository owner, until then, with an expiry of 2026-12-17. It was never fixed: no patched `picomatch` exists, and no dependency changed. The rest of this document is the record of the exception as it applied.

Where it lives: one entry in `scripts/security-exceptions.json`, enforced by `scripts/npm_audit_gate.py`, called from `scripts/check-security.sh`. Tests: `tests/architecture/test_npm_audit_gate.py`. The mechanism, its conditions and the options that were rejected for the earlier `braces` exception are in `docs/SECURITY-EXCEPTION-braces.md`, sections 4 to 6; they apply unchanged.

## 1. The advisory

| | |
|---|---|
| Identifier | GHSA-fc5q-39xc-vjpf |
| Package | `picomatch` |
| Title | picomatch vulnerable to ReDoS through single-branch repeated extglobs |
| Weakness | CWE-1333 (inefficient regular expression complexity) |
| Severity | High: CVSS 3.1 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) |
| Affected range | `<= 4.0.7` |
| Installed | `picomatch@2.3.2` and `picomatch@4.0.7` |
| Patched version | **None.** `4.0.7` is the newest release on the registry (`npm view picomatch dist-tags` gives `latest: 4.0.7`) |
| Published / updated | 2026-10-19 / 2026-11-17T15:56:44Z (GitHub advisory API) |

The gate first failed on it on 2026-11-17, in the security checks of release pull request #287 (run 44145997545: `UNACCEPTED: GHSA-fc5q-39xc-vjpf (picomatch, high)`). Main CI had passed on `06f0a95` earlier the same day with the same lockfile.

## 2. Dependency paths

Every path is under a development dependency (`frontend/package.json` `devDependencies`); `package-lock.json` marks all four installed copies `"dev": true`:

```
saas-os-frontend
├─ vitest (dev)                     -> picomatch@4.0.7, tinyglobby -> fdir/picomatch@4.0.7, vite -> picomatch@4.0.7
├─ @vitejs/plugin-react (dev)       -> vite -> picomatch@4.0.7
├─ eslint-config-next (dev)         -> @next/eslint-plugin-next -> fast-glob -> micromatch -> picomatch@2.3.2
└─ TypeScript ESLint tooling (dev)  -> @typescript-eslint/typescript-estree, eslint-import-resolver-typescript -> tinyglobby -> picomatch
```

`npm audit` counts the one advisory once per package on these paths (12 "high" findings); `picomatch` is the only package with an advisory at high or critical. The five "moderate" findings (GHSA-g3hv-75wg-m249 in `minimatch` and its dependents) are below the gate's threshold and were never blocking.

What `npm` offers: `npm audit fix --force`, which installs `vitest@3.1.4`, a major-version downgrade. Not applied: `vitest@3.1.4` still depends on `tinyglobby`, which depends on `picomatch`, and the `vite` and lint paths would remain, so it would not remove the advisory.

## 3. Exposure, by context

| Context | Is `picomatch` present? | Executed? | With input from whom? | Exposure |
|---|---|---|---|---|
| **Production runtime** (`next start`) | No: the runtime stage of `frontend/Dockerfile` runs `npm ci --omit=dev`; `npm audit --omit=dev` reports **0 vulnerabilities** | No | none | None |
| **Development and build** (`next dev`, `next build`, `npm run lint`, `npm test`) | Yes | Yes: Vitest, Vite and ESLint match file globs | Glob patterns from this repository's own configuration | A maintainer could slow their own run with their own pattern; no external input reaches it. `next dev` serves the app; Vite's dev server is not used (`npm run dev` is `next dev`) |
| **CI** (`frontend` and `security` jobs) | Yes (`npm ci`) | Yes | The same repository-controlled patterns | Same as build |
| **Consumers of `saas-os`** | No | none | none | None: the frontend is not part of the Python distribution (ADR-0042) |

The precondition of the advisory, an attacker choosing an extglob pattern that the application then compiles, is not met in any context. The runtime image was not rebuilt for this record; the claim rests on the Dockerfile's `--omit=dev` stage and `npm audit --omit=dev`, the same evidence the gate itself checks on every run.

## 4. The exception

**Scope.** One advisory identifier, GHSA-fc5q-39xc-vjpf, in one package, `picomatch`, in `frontend/`. Every other advisory at high or critical still fails the gate, including another advisory in `picomatch` and the same identifier reported against another package.

**It applies only while all of these are true** (the gate fails the moment one is not):

1. Today is on or before **2026-12-17**.
2. `npm audit --omit=dev` does not report the advisory.
3. `npm` offers no non-breaking fix: `fixAvailable` for `picomatch` is not `true`.
4. The advisory is still reported. If it is withdrawn, the stale entry fails the gate until it is deleted.

**Owner.** The repository owner approved it on 2026-11-17 (choice "Dev-only exception", 30 days) and owns its review. Moving the expiry is the owner's decision, in a reviewed commit.

**Review before expiry when:** a `picomatch` release addresses the advisory; the advisory's severity or range changes, or it is withdrawn; `vite`, `vitest` or `eslint-config-next` is upgraded.

**Remediation.** When a patched release exists: update `frontend/package-lock.json`, confirm with `npm audit` that the advisory is gone, delete the entry and run `scripts/check-security.sh`. Conditions 3 and 4 make the gate fail until that is done. If nothing has changed by 2026-12-17, the gate fails and the owner decides again.

## 5. Controls

`tests/architecture/test_npm_audit_gate.py` checks the checked-in entry itself:

- the file holds exactly this entry, approved on 2026-11-17 and expiring on 2026-12-17;
- it passes for the report as it stands (development only, breaking fix only) and is reported as not fixed;
- it fails on 2026-12-18, when the advisory reaches production dependencies, when a non-breaking fix exists, and when the advisory is no longer reported;
- it does not cover another advisory in `picomatch` or the same identifier in another package.

The general controls of the mechanism (run against the former `braces` entry) are unchanged.

## 6. Evidence

Commands run on 2026-11-17 in `frontend/`:

- `python scripts/npm_audit_gate.py` (repository root), before the entry: `UNACCEPTED: GHSA-fc5q-39xc-vjpf (picomatch, high)`, exit 1. With the entry: `ACCEPTED EXCEPTION: ... NOT FIXED; accepted until 2026-12-17`, exit 0.
- `npm audit --omit=dev`: `found 0 vulnerabilities`.
- `npm audit --json`: 12 high, 5 moderate, 0 critical; the only advisory at high is GHSA-fc5q-39xc-vjpf in `picomatch`, `fixAvailable` `{"name": "vitest", "version": "3.1.4", "isSemVerMajor": true}`.
- `npm view picomatch dist-tags`: `{ latest: '4.0.7' }`.
- `npm view vitest@3.1.4 dependencies`: includes `tinyglobby`.
- `gh api advisories/GHSA-fc5q-39xc-vjpf`: severity high, range `<= 4.0.7`, no patched version, not withdrawn.

## 7. Closed 2026-11-20: the advisory was withdrawn

On 2026-11-20 the security gate failed on this exception's stale-entry condition (section 5), in the security checks of pull request #290: `UNACCEPTED: GHSA-fc5q-39xc-vjpf (picomatch) -- exception is stale: the advisory is no longer reported; remove it from security-exceptions.json`. That is the designed behavior: an entry for an advisory that is no longer reported fails until it is deleted. Every CI run on main and on pull requests failed the same way until this change.

- **Advisory source.** GitHub's advisory API (`gh api advisories/GHSA-fc5q-39xc-vjpf`) reports `withdrawn_at` 2026-11-18T15:38:56Z (updated 2026-11-19T16:07:41Z). Severity high, range `<= 4.0.7`, no patched version: the record is unchanged except for the withdrawal.
- **`npm audit` in `frontend/`.** It reports no high or critical advisory, and nothing for `picomatch`. It reports seven moderate ones (`minimatch`, the TypeScript ESLint packages, `next`), below the gate's threshold, which the gate never blocked; `npm audit --omit=dev` reports one of them, moderate, in `next`.
- **Installed tree.** Unchanged: `picomatch@2.3.2` and `picomatch@4.0.7` on the same development-only paths (section 2); `npm view picomatch dist-tags` still gives `latest: 4.0.7`. The lockfile and every dependency version are as before.
- **Change.** The one entry was removed from `scripts/security-exceptions.json`, which now holds `"npm": []`. The gate itself, its threshold and every other check are unchanged.
- **Tests.** `tests/architecture/test_npm_audit_gate.py` asserts that the checked-in file holds no exception, and that with it the `picomatch` and `braces` advisories would block the gate if either were ever reported again. The exception controls of the mechanism (expiry, production dependencies, a non-breaking fix, a stale entry, other advisories and packages) keep running against the former `braces` entry written to a temporary file.

No exception is accepted now. A new one needs the repository owner's decision.
