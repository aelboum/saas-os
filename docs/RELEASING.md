# Releasing SaaS OS

How a SaaS OS release is made, validated, tagged, published as a GitHub Release and verified. The rules are ADR-0015's amendments "Release labels", "One pull request per release" and "GitHub Releases"; this page is the procedure. `CHANGELOG.md` is the only source of release notes.

A release is three things that must agree: the version in `pyproject.toml`, an annotated tag `vX.Y.Z` on the merge commit of the release pull request, and the newest entry of `CHANGELOG.md`. The GitHub Release is a page that shows that entry with the exact commit and the CI evidence.

**A GitHub Release is not a package publication and not a deployment.** Nothing is uploaded to PyPI or any other index (none is adopted, ADR-0015), and nothing is deployed. Products pin the release commit's full SHA (ADR-0015 rule 8) and deploy themselves (`docs/CONSUMER-GUIDE.md` section 15).

## The tools

- `scripts/release.py`: the checks, the release notes and the one write (creating the release). Standard library only. It never creates, moves or deletes a tag and never edits or deletes a release.
- `.github/workflows/release.yml`: runs the script on GitHub. A pushed `v*` tag validates and then publishes. A manual run (`workflow_dispatch`) with a tag validates only, unless `publish` is ticked.

| Stage | Command | Needs |
|---|---|---|
| Before tagging | `python scripts/release.py validate --tag vX.Y.Z --stage pre-tag` | a clean checkout of the release commit, `gh` logged in |
| Before publishing | `python scripts/release.py validate --tag vX.Y.Z --stage publish --notes-out notes.md` | the tag, `gh` |
| Publish (the workflow does this) | `python scripts/release.py publish --tag vX.Y.Z --expect-commit <sha> --expect-notes-sha256 <digest>` | `contents: write` |
| After publishing | `python scripts/release.py verify --tag vX.Y.Z` | `gh` |

Add `--offline` to `validate` to rehearse without GitHub: it runs the Git checks only, says so in its result, and `publish` refuses it. The script reads GitHub through `gh api`; it never reads, prints or stores a token.

## What is checked

Every stage checks:

- **Tag syntax.** `vMAJOR.MINOR.PATCH`, no leading zeros, no suffix.
- **Commit.** Before tagging, the clean checked-out commit. After, the commit the annotated tag points to. `--expect-commit` must be a full 40-character SHA.
- **On `main`.** The commit is a first-parent commit of `origin/main`, so it is a merge commit on `main` and not a commit of a merged branch.
- **Version.** `pyproject.toml` at that commit says `X.Y.Z`.
- **Changelog.** At that commit, the newest entry is `vX.Y.Z (YYYY-MM-DD)`, its first paragraph names the release pull request, and it lists at least one change and the migration head.
- **Order.** The version is newer than every other release tag. The previous release is the newest older tag. It must be annotated and an ancestor of the commit, and it must not be the commit itself. The changelog entry after this one must be that release, naming its full SHA.
- **Release pull request.** It was merged into `main`, and its merge commit is the release commit.
- **Main CI.** The newest CI run for a push to `main` on that exact commit completed successfully, with every job of `.github/workflows/ci.yml` successful. A pull-request run, or a run on another commit, is not evidence.
- **Tag on GitHub.** Before tagging, it is absent. After, it is annotated and points to the same commit.
- **Existing release.** Before publishing, no release, draft or published, uses the tag. Verification needs exactly one, not a draft, named `SaaS OS vX.Y.Z`, whose notes name the commit.

The publish job runs the same validation again with the commit and the notes digest the validate job produced. It creates the release only if both still match, so the notes and the commit cannot change between the two jobs. Only that job's token can see draft releases, so a draft that uses the tag is caught there even though the read-only `validate` job cannot see it.

## Procedure

1. **Prepare: the release pull request.** On a branch from `main`:
   - Set `version` in `pyproject.toml`. Before 1.0, use `0.Y.0` for a release with a migration, a changed public signature or a new required deployment step, and `0.Y.Z` for fixes and documentation (ADR-0015).
   - Add the changelog entry. The first paragraph names this pull request ("The merge commit of pull request #N"). List the changes since the previous release, by pull request, and give the migration head. Write the previous release's full SHA into its own entry.
   - Add the upgrade steps to `docs/CONSUMER-GUIDE.md` section 14, with the `saas-os-update check` classification.
   - Move both example pins to the previous release's commit, if they are not there already. The pins lag one release (ADR-0015).

   Open the pull request. Merge it only after its CI passes on its exact head.
2. **Validate the candidate.** After `main` CI passes on the merge commit:

   ```
   git checkout main && git pull --ff-only
   python scripts/release.py validate --tag vX.Y.Z --stage pre-tag
   ```

   Every line must say `PASS`.
3. **Tag.** On the same commit, with the convention every release has used:

   ```
   git tag -a vX.Y.Z <full sha> -m "SaaS OS vX.Y.Z" -m "<one paragraph: what it contains, migration head, release PR, main CI run>"
   git push origin vX.Y.Z
   ```

   Push only that tag, never `--tags` or `--force`. CI never creates tags.
4. **Publish.** Pushing the tag starts the Release workflow. Its `validate` job (read-only) runs every check and puts the notes in the job summary. Its `publish` job (`contents: write`) creates the release and verifies it.
5. **Verify.** Run `python scripts/release.py verify --tag vX.Y.Z`. Then open the release page and check that it shows the tag, the full SHA and the changelog entry. Resolve the tag yourself: `git ls-remote https://github.com/aelboum/saas-os refs/tags/vX.Y.Z^{}` must print the release commit.

To rehearse without publishing, run the Release workflow manually with the tag and `publish` unticked, or run the `validate` command above locally. Either one only reads.

## When the workflow fails

Never move, delete or re-push a published tag, and never delete a published release to start over (ADR-0015: a mistake is corrected by a new release).

- **Validation failed before publishing.** Nothing was created. Read the failing line.
  - Main CI had not finished, or failed: wait for it to pass on that commit (rerun a failed job if the failure was not the code), then run the Release workflow manually with the tag and `publish` ticked.
  - A check fails because the release itself is wrong (version, changelog, wrong commit tagged): the tag stays. Make the next patch release with the correction. A pushed tag without a GitHub Release is allowed, but it is a release in every other sense and is never reused.
- **Publishing failed after the release was created** (for example, the verification step failed or the job was cancelled): do not run it again, because validation now refuses with "release(s) already use". Run `verify` and inspect the release on GitHub. Anything wrong in it is corrected by the next release, as above.
- **The workflow did not start** (a tag pushed before this workflow existed, or Actions disabled): run it manually with the tag, from `main` (the branch selector of "Run workflow"). A manual run uses the workflow and script of the branch it runs on, so run it from `main` only. They validate the tag's commit from Git objects, not from the checkout.

## What is not automated

- The version number, the changelog entry, the upgrade steps and the example pins: written by hand in the release pull request.
- Creating and pushing the tag: done by hand, by the owner, after `pre-tag` validation.
- Package publication: there is none. A product installs `saas-os @ git+https://github.com/aelboum/saas-os@<full sha>`.
- Deployment and deployment qualification (Gate C): each product's own.
- Signed tags, an approval environment on the publish job, and GitHub branch protection: not configured (the ledger in `docs/P-ROADMAP.md`).

## Example: v0.1.2, for reference only

v0.1.2 was tagged on 2026-10-20, before this workflow existed. Its GitHub Release was created by hand on GitHub on 2026-10-20, with GitHub's generated notes, not by this workflow; the workflow now refuses the tag because a release already uses it, which is the intended behaviour. A read-only check of it, run on 2026-10-20 against GitHub before that release existed:

```
$ python scripts/release.py validate --tag v0.1.2 --stage publish
release validation: v0.1.2, stage publish
  [PASS] tag syntax: v0.1.2
  [PASS] tag: v0.1.2 is annotated and points to b0809eeb3448956a4dc85a5541514823ec9ceae7
  [PASS] on main: b0809eeb3448956a4dc85a5541514823ec9ceae7 is a first-parent commit of origin/main
  [PASS] package version: pyproject.toml says 0.1.2, the tag says 0.1.2
  [PASS] changelog: v0.1.2 (2026-10-20), release pull request #71
  [PASS] version order: v0.1.2 follows v0.1.1
  [PASS] previous release: v0.1.1 (c7d898782877b945a54d49c87d280c6ad515586f) is an ancestor
  [PASS] release pull request: #71 merged as b0809eeb3448956a4dc85a5541514823ec9ceae7
  [PASS] main CI: run 39392316234: 7 of 7 jobs passed
  [PASS] remote tag: GitHub has a tag pointing to b0809eeb3448956a4dc85a5541514823ec9ceae7
  [PASS] existing release: none
result: PASS
```

The notes it rendered open with "SaaS OS v0.1.2, released 2026-10-20.", followed by the changelog entry. Then come a "Source" section, with the tag, the full SHA, the pin line and the comparison with v0.1.1; a "Verification" section, with CI run 39392316234 and pull request #71; and "What this release is not".
