# ADR-0062: Versioning and support policy

Status: Proposed
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

Pending. Questions for the owner:

- Q1. Option 1 or Option 2 for releasing fixes to the previous minor?
- Q2. Does the 90-day window start at the newer minor's publication (as proposed) or at its tag?
- Q3. Is the support statement in each changelog entry (rule 5) required from the next release on?

## What Would Be Difficult to Change Later

- A published support window is a promise to consumers; shortening it later breaks plans made on it.
- Once maintenance branches exist, their protection and release validation are part of the security boundary of the release process.

## Related

ADR-0015 (distribution, pins and release amendments), ADR-0041 (dependency and packaging modularity; versioning policy not adopted), `docs/RELEASING.md`, `docs/CONSUMER-GUIDE.md` section 14, `docs/architecture/ARCHITECTURE-DECISION-BRIEF-2026-11-01.md` section 4.
