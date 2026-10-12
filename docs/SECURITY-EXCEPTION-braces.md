# Security-gate exception: `braces` GHSA-vfj7-8cjw-p6xm

Status: **APPLIED** on 2026-10-11 by decision of the repository owner. **Expires 2027-01-11.** The advisory is **not fixed**; it is accepted for a limited time under the conditions in section 5, and the security gate prints it on every run.

Where it lives: one entry in `scripts/security-exceptions.json`, enforced by `scripts/npm_audit_gate.py`, called from `scripts/check-security.sh`. Tests: `tests/architecture/test_npm_audit_gate.py`.

Prepared in run 4 of `docs/P-ROADMAP.md`, exposure updated in run 5, applied in run 6.

## 1. The advisory

| | |
|---|---|
| Identifier | GHSA-vfj7-8cjw-p6xm |
| Package | `braces` |
| Title | Stack-exhaustion denial of service through deeply nested patterns |
| Weakness | CWE-674 (uncontrolled recursion) |
| Severity | High — CVSS 3.1 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) |
| Affected range | `<= 3.0.3` |
| Installed | `braces@3.0.3` |
| Patched version | **None.** `3.0.3` is the newest release on the registry (`npm view braces dist-tags` → `latest: 3.0.3`) |

The CVSS vector describes the general case, an application that passes attacker-supplied text to `braces` over a network. Whether that applies here is section 3.

## 2. Dependency path

One path, entirely under a development dependency:

```
saas-os-frontend
└─ eslint-config-next@15.5.27          (devDependency)
   └─ @next/eslint-plugin-next@15.5.27
      └─ fast-glob@3.3.1
         └─ micromatch@4.0.8
            └─ braces@3.0.3
```

`npm audit` reports five "high" findings. They are this one advisory counted once per package on the path (`braces`, `micromatch`, `fast-glob`, `@next/eslint-plugin-next`, `eslint-config-next`); there are no other open advisories.

Upstream state, checked on the registry:

- `micromatch@4.0.8` (latest) depends on `braces ^3.0.3`.
- `fast-glob@3.3.3` (latest) depends on `micromatch ^4.0.8`.
- `@next/eslint-plugin-next` (latest) depends on `fast-glob 3.3.1`.

So no newer version of any package on the path removes `braces`.

What `npm` offers: `npm audit fix --force`, which installs `eslint-config-next@14.2.35` — a major-version downgrade of the lint configuration against Next.js 15. Not applied: it pairs a Next 14 lint configuration with Next 15, and whether that older plugin still reaches `braces` by another route was not established.

## 3. Exposure, by context

| Context | Is `braces` present? | Is it executed? | With input from whom? | Exposure |
|---|---|---|---|---|
| **Production runtime** (`next start` serving requests) | **No** — since the image became two-stage (below) the runtime image holds production dependencies only; verified absent | **No** | — | None. `npm audit --omit=dev` reports **0 vulnerabilities** |
| **Build** (`next build`, `npm run lint`; the image's discarded `build` stage) | Yes | Yes — ESLint's Next plugin resolves file globs | Glob patterns from this repository's own ESLint and Next configuration | A maintainer could hang their own build with their own pattern; no external input reaches it |
| **CI** (`frontend` job, `security` job) | Yes (`npm ci`) | Yes, in the lint step | The same repository-controlled patterns | Same as build. A pull request can already run arbitrary code in CI by editing a script, so a crafted glob adds nothing |
| **Consumers of `saas-os`** | No | — | — | None: the frontend is not part of the Python distribution (ADR-0042) |

The denial-of-service precondition — an attacker choosing a deeply nested brace pattern that the application then expands — is not met in any context: no request, upload, header or tenant data is passed to a glob matcher.

**Runtime image, verified.** `frontend/Dockerfile` is two-stage: the `build` stage installs everything and runs `next build`; the final stage runs `npm ci --omit=dev` and copies the built `.next/`. In the built image, `braces`, `micromatch`, `fast-glob`, `eslint`, `eslint-config-next` and `typescript` are absent from `node_modules` (43 packages remain) and a search of the whole filesystem finds no directory named after the first three. Started with networking disabled, the container reports ready, serves `/` with 200 and an unknown path with 404.

Two things had to change for that to hold. First, the configuration file is now `next.config.mjs`: with a `next.config.ts` and no TypeScript compiler, `next start` runs `npm install` for the development dependencies at container start — which brought all of them back, `braces` included, in the first attempt. Second, starting the image without a network is part of the evidence, because it proves nothing is fetched at startup.

So the advisory no longer concerns anything that runs or ships; it concerns the lint step on developer machines and in CI, and the gate that scans the full dependency tree.

## 4. Options

| Option | Effect | Assessment |
|---|---|---|
| A. Leave the gate failing | `check-security.sh` and CI's `security` job stay red until upstream ships a fix | Honest, but a permanently red gate hides the next real dependency finding. (It no longer hides the secret scan: the script now runs it regardless) |
| B. `npm audit fix --force` | Downgrades `eslint-config-next` to 14 | Rejected: an incompatible downgrade against Next 15 |
| C. Drop `eslint-config-next` | Removes the path | Rejected for now: discards the framework's lint rules to silence an advisory with no exposure |
| D. Gate on production dependencies only (`--omit=dev`) | Green today | Rejected: silently exempts every future development-dependency advisory. That is a policy change, not an exception |
| E. Lower the threshold (`--audit-level=critical`) | Green today | Rejected: exempts every high advisory |
| **F. An explicit, expiring exception for exactly this advisory** | The gate accepts GHSA-vfj7-8cjw-p6xm, and only it, under stated conditions | **Chosen and applied** |

## 5. The exception

**Scope.** One advisory identifier, GHSA-vfj7-8cjw-p6xm, in one package, `braces`, in one dependency tree (`frontend/`). Every other advisory at `high` or `critical` still fails the gate — including any other advisory in `braces`, and the same identifier reported against any other package.

**Mechanism.** `scripts/npm_audit_gate.py` reads `npm audit --json` for the full tree and for production dependencies only, collects every advisory at `high` or `critical` (the same threshold as the `npm audit --audit-level=high` it replaces), and fails unless each one is listed in `scripts/security-exceptions.json` and still meets every condition below. An accepted advisory is printed as `ACCEPTED EXCEPTION … NOT FIXED; accepted until 2027-01-11`.

**The exception applies only while all of these are true.** The gate fails again the moment one is not:

1. Today is on or before the expiry date, **2027-01-11**.
2. The advisory is not reachable from production dependencies: `npm audit --omit=dev` does not report it.
3. `npm` offers no non-breaking fix: `fixAvailable` for `braces` is not `true`.
4. The advisory is still reported. An entry for an advisory that has disappeared is stale and fails the gate until it is deleted.

A missing or malformed exceptions file fails the gate; it is never read as "no exceptions" or "all excepted".

**Owner.** The repository owner approved it and owns its review. Adding an entry, or moving an expiry date, is a decision of the owner made in a reviewed commit to `scripts/security-exceptions.json`; nothing extends it automatically.

**Review before expiry when:** a release of `braces`, `micromatch` or `fast-glob` addresses the advisory; `eslint-config-next` or `@next/eslint-plugin-next` stops depending on `fast-glob`; `next` is upgraded; the advisory's severity or affected range changes.

**Remediation plan.** When a patched release exists: upgrade (through `eslint-config-next` if that is where it arrives), run `npm audit` to confirm the advisory is gone, delete the entry from `scripts/security-exceptions.json`, and run `scripts/check-security.sh`. Condition 3 or 4 makes the gate fail until that is done, so the exception cannot outlive the fix unnoticed. If no fix exists by the expiry date, the gate fails and the owner decides again, with the options in section 4.

**What it does not grant.** It does not change the threshold, does not exempt development dependencies as a class, and does not apply to any other advisory.

## 6. Controls

`tests/architecture/test_npm_audit_gate.py`, 20 tests, on constructed audit reports:

- positive: the accepted advisory passes, is reported as not fixed, and holds through 2027-01-11;
- negative: it fails on 2027-01-12; another high or critical advisory fails; another advisory in `braces` fails; the same identifier in another package fails; the advisory appearing in production dependencies fails; a non-breaking fix becoming available fails; a stale entry fails; a malformed exceptions file is an error; the gate exits non-zero when `npm` cannot be run;
- unchanged threshold: low and moderate advisories do not block, as before; with an empty exceptions list the `braces` advisory fails exactly as it did before the exception.

`tests/architecture/test_security_script_reporting.py` shows the script still runs pip-audit, this gate and the secret scan every time, and fails if any of them fails.

## 7. Evidence

Commands run on 2026-10-11 in `frontend/`:

- `npm audit` → `5 high severity vulnerabilities`, all on the path in section 2.
- `npm audit --omit=dev` → `found 0 vulnerabilities`.
- `npm ls braces` → the single path in section 2.
- `npm view braces dist-tags` → `{ "latest": "3.0.3" }`; last publish 2024.
- `npm view micromatch@latest dependencies`, `npm view fast-glob@latest dependencies`, `npm view @next/eslint-plugin-next@latest dependencies` → as quoted in section 2.

The four other advisories found in the same audit (`next`, `sharp`, `source-map-js`, `brace-expansion`) were fixed by `npm audit fix` without `--force`; only `frontend/package-lock.json` changed.
