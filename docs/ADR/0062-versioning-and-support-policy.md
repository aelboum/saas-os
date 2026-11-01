# ADR-0062: Versioning and support policy

Status: Proposed; support model decided (owner, 2026-11-01): Option 1, maintenance branches. Q2 and Q3 open.
Date: 2026-11-01
Supersedes / Superseded by: none. Would amend ADR-0015 (it decides the support window ADR-0015 leaves open; it changes none of ADR-0015's accepted rules). Numbered 0062 because pull request #187 proposes 0060 and 0061.

## Context

SaaS OS is a package that products pin by exact commit SHA (ADR-0015 rule 8). Releases are annotated, signed tags with a changelog entry, published through a fail-closed workflow (ADR-0015 amendments of 2026-10-19, 2026-10-20, 2026-10-21 and 2026-10-31). Before 1.0, ADR-0015's release-labels amendment says:

> `0.Y.0` for a release with a migration, a removed or changed public signature, or a new required deployment step; `0.Y.Z` (Z > 0) for fixes and documentation only. No support window is promised for earlier releases (still open, as above).

The deferred-issue ledger records the support window and versioning policy as undecided (`docs/P-ROADMAP.md`: "Major-version support-window policy (ADR-0015 "not decided")"; "Constraints file and versioning policy (ADR-0041 options 2C, 3B)"). A consumer therefore cannot know how long a release it pins will receive security fixes, or what a version number promises after 1.0.

On 2026-11-01 the owner set the policy below and asked for it as a Proposed ADR, with its relation to ADR-0015 explained and any conflict named.

## Proposed policy

1. **Version numbers after 1.0** (semantic versioning):
   - PATCH: bug fixes, security fixes and compatible corrections;
   - MINOR: backward-compatible capabilities;
   - MAJOR: breaking changes.
2. **Version numbers before 1.0:** ADR-0015 stays authoritative. A documented breaking change may ship in a minor (`0.Y.0`) release when it comes with an explicit migration path in `docs/CONSUMER-GUIDE.md` section 14 and `CHANGELOG.md`. A security fix that needs a migration, a changed public signature or a new deployment step is therefore a `0.Y.0` release, not a patch.
3. **Support window:**
   - the newest minor release receives full support;
   - the previous minor release receives security and critical bug-fix support for at least 90 days after the newer minor is published;
   - older versions receive best-effort support unless a release says otherwise;
   - a high-impact security issue is assessed separately for each older version still pinned by a known consumer, and the assessment is recorded in the deferred-issue ledger.
4. **No automatic updates.** A consumer never moves its pin automatically; every pin move is an explicit, reviewed change in the consumer (ADR-0015 rule 8; `saas-os-update` classifies, it never commits).
5. **Where a release states its support:** each `CHANGELOG.md` entry names the release that leaves full support and the date its 90-day window ends.

## Relation to ADR-0015

- **Consistent:** exact-SHA pins, tags as never-moving labels, signed tags, the approval environment, one changelog as the only source of release notes, and the pre-1.0 numbering rule (kept by rule 2).
- **Decided here, open there:** the support window (rule 3), which ADR-0015 records as not decided in its Consequences and in its release-labels and GitHub-Releases amendments.
- **Conflict, to be resolved before acceptance:** rule 3 requires releasing a fix for the previous minor after a newer minor exists, for example `0.6.1` after `0.7.0`. ADR-0015's accepted process does not allow that: a release tag must be on "a first-parent commit of `main`", one pull request per release is merged into `main`, and `scripts/release.py` validates the release pull request's merge commit and "the previous release and its full SHA in the changelog" against the linear release history on `main`. A fix built from `v0.6.0` is not a first-parent commit of `main`.

## Options Considered (for the conflict)

### Option 1: maintenance branches
A `release/0.Y` branch is created from the tag when the first back-port is needed, protected like `main` (same required checks, no force push), and `scripts/release.py`, its workflow and `tests/architecture/test_release_script.py` learn to validate a tag on a first-parent commit of that branch, with its own previous-release chain.
- Advantages: keeps the 90-day promise exactly; each back-port goes through the same CI, signing and approval as a release on `main`.
- Disadvantages: release tooling and branch-protection changes; every fix is ported and reviewed twice.

### Option 2: fix forward only
Security and critical fixes ship only in the newest minor; consumers of the previous minor receive an upgrade note and, for a high-impact issue, an advisory with mitigations.
- Advantages: no tooling change.
- Disadvantages: does not provide "at least 90 days of security and critical bug-fix support" for the previous minor as written; a consumer must take every change in the newer minor to get a fix.

## Recommendation

Accept the policy with **Option 1**, and build the maintenance-branch support only when the first back-port is actually needed. Until then the newest minor is the only line released.

## Decision

- **Q1 (decided by the owner, 2026-11-01): Option 1, maintenance branches.** ADR-0015 stays authoritative for pre-1.0 release behaviour (rule 2). The release tooling is not changed until Q2 and Q3 are decided (section "Implementation assessment").
- **Q2 (open).** Does the 90-day window start at the newer minor's publication (as proposed) or at its tag?
  - *Publication*: the GitHub Release, created by the release workflow after validation and the owner's approval in the `release` environment. Consequence: the window starts when consumers can actually see the release; it can start days after the tag if approval waits, and its date is the release's `published_at` on GitHub.
  - *Tag*: the annotated, signed tag's date. Consequence: one date fixed in git and visible offline; the window can start before the release is approved and published, so consumers may have fewer than 90 days of a published newer minor.
- **Q3 (open).** Is the support statement in each changelog entry (rule 5) required from the next release on?
  - *Yes, from the next release*: every entry names the release that leaves full support and the end of its 90-day window. Consequence: release pull requests must write it; `scripts/release.py` can check it fail-closed (a new check and tests), or it is reviewed by hand.
  - *No, not yet*: the policy applies without the statement until the first back-port. Consequence: no change to release pull requests now; consumers must work out the window from release dates themselves.

## Implementation assessment (maintenance branches; nothing changed yet)

What `scripts/release.py` and `.github/workflows/release.yml` assume today, and what a back-port release (for example `0.6.1` from `release/0.6` after `0.7.0` exists) needs. Signed tags, the approval environment, least-privilege jobs and SHA-pinned actions need no change.

| Today (file, check) | Blocks a back-port because | Change needed |
|---|---|---|
| `validate()`: "on main", the commit must be in `git rev-list --first-parent origin/main` | `release/0.6` commits are not first-parent commits of `main` | Validate against the branch named by the version line: `release/0.Y` for `0.Y.Z` when `0.Y` is not the newest minor, `main` otherwise; still first-parent only |
| `_check_previous_release()`: "version order" refuses any existing tag newer than the release | `v0.7.0` exists | Compare within the version line: the previous release is the newest `v0.Y.*` tag; newer minors are allowed |
| `_check_previous_release()`: the previous release must be an ancestor and its full SHA must be in the changelog | Holds within the line (`v0.6.0` is an ancestor of `release/0.6`) | None beyond selecting the previous release per line |
| `_changelog_entry()`: the newest changelog entry must be the tag | Holds on the maintenance branch's own `CHANGELOG.md` | A rule (and a check, if wanted) that `main`'s changelog later records the back-port |
| `_check_github()`: the release pull request must have `base.ref == "main"` | The back-port pull request targets `release/0.6` | Accept the line's branch |
| `_check_github()`: "main CI", a successful CI run for a push event on the release commit | CI (`.github/workflows/ci.yml`) runs on pushes to `main` and on pull requests only | Run CI on pushes to `release/**` |
| Repository settings: the `main` ruleset (seven required checks, no force push, no deletion) | `release/*` is unprotected | A ruleset for `release/*` with the same required checks and restrictions (owner setting) |
| `.github/workflows/release.yml`: triggered by `v*` tags, checks out the tag's SHA, `release` environment limited to `v*` tags | Works for any `v*` tag | Pass the version line's branch to validation instead of the fixed `origin/main` |
| `tests/architecture/test_release_script.py` | Pins the current rules | New cases: a back-port on its branch passes; a back-port not first-parent on its branch, a back-port whose previous line release is missing, and a tag on `main` older than the newest release are refused |
| `docs/RELEASING.md`, `docs/CONSUMER-GUIDE.md` section 14 | Describe one line | The back-port procedure and how a consumer pins a patch of an older minor |

## What Would Be Difficult to Change Later

- A published support window is a promise to consumers; shortening it later breaks plans made on it.
- Once maintenance branches exist, their protection and release validation are part of the security boundary of the release process.

## Related

ADR-0015 (distribution, pins and release amendments), ADR-0041 (dependency and packaging modularity; versioning policy not adopted), `docs/RELEASING.md`, `docs/CONSUMER-GUIDE.md` section 14, `docs/architecture/ARCHITECTURE-DECISION-BRIEF-2026-11-01.md` section 4.
