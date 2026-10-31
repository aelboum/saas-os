"""Release validation and GitHub Release publication (ADR-0015, "Release
labels", "One pull request per release" and "GitHub Releases").

A release is a version in `pyproject.toml`, an annotated tag `vX.Y.Z` on
the merge commit of the release pull request, and an entry in
`CHANGELOG.md`. This script checks that those agree, that `main` CI passed
on that exact commit, and only then creates the GitHub Release whose notes
are rendered from the changelog entry. It never creates, moves or deletes a
tag, never edits or deletes a release, and publishes no package.

Usage (from the repository root):

    python scripts/release.py validate --tag vX.Y.Z --stage pre-tag
    python scripts/release.py validate --tag vX.Y.Z --stage publish [--notes-out FILE]
    python scripts/release.py publish  --tag vX.Y.Z --expect-commit SHA \
        --expect-notes-sha256 DIGEST
    python scripts/release.py verify   --tag vX.Y.Z

Stages:

- `pre-tag`: before the tag exists. The candidate is the checked-out
  commit, which must be clean; the tag must not exist yet.
- `publish`: the tag exists and is annotated; no GitHub Release exists for
  it yet (drafts included).
- `verify`: exactly one published release exists for the tag and matches.

From `SIGNED_TAGS_FROM` on, a release tag must be signed with the owner's
own key: `pre-tag` checks that Git has a signing key configured, and
`publish` and `verify` require GitHub to report the tag's signature as
verified (ADR-0015 amendment of 2026-10-31).

`--offline` skips every GitHub API check (pull request, CI, releases,
remote tag, tag signature) for a local rehearsal; its result says so and `publish` never
accepts it. GitHub calls go through the `gh` CLI, which reads `GH_TOKEN`
in Actions; this script never reads or prints a token.

Exit status: 0 when every check passed, 1 when any failed, 2 on a usage
error. Standard library only, Python 3.11 or later.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol

DEFAULT_REPOSITORY = "aelboum/saas-os"
CI_WORKFLOW_FILE = "ci.yml"

# The jobs of `.github/workflows/ci.yml`, by display name. A release needs
# every one of them to have succeeded on the release commit;
# tests/architecture/test_release_script.py keeps this list equal to ci.yml.
REQUIRED_CI_JOBS = (
    "backend checks",
    "frontend checks",
    "security checks",
    "docker build + runtime validation",
    "packaging gate (wheel contents + isolated install)",
    "migration gate (P1.7)",
    "security integration gate (PRIV-03 RA-11-F1)",
)

TAG_PATTERN = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
FULL_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
ENTRY_HEADING = re.compile(r"^## (v\S+) \((\d{4}-\d{2}-\d{2})\)\s*$", re.MULTILINE)
PULL_REQUEST_REFERENCE = re.compile(r"pull request #([1-9][0-9]*)")
STAGES = ("pre-tag", "publish", "verify")

Version = tuple[int, int, int]

# ADR-0015 amendment of 2026-10-31 (owner decision): every release from this
# version on is a tag signed with the owner's own key, and GitHub must report
# the signature as verified before the release is created. Earlier tags were
# made unsigned and are never re-made (a tag is never moved), so their
# releases are judged without it.
SIGNED_TAGS_FROM: Version = (0, 6, 0)


class ReleaseError(Exception):
    """A usage or environment problem that prevents validation from running."""


@dataclasses.dataclass(frozen=True)
class Requery:
    """How long to keep asking GitHub before an empty answer counts.

    GitHub's list endpoints can lag a moment behind what just happened: a CI
    run that just completed, or the release this script just created, can be
    missing from the list for a few seconds (v0.4.0's Release run failed its
    own verification this way, and its pre-tag validation briefly found no CI
    run). Only an empty answer is asked again, at most `attempts` times with
    `delay_seconds` between them; any answer that is present is judged as
    before, and an API error is never retried.
    """

    attempts: int = 6
    delay_seconds: float = 5.0
    sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        if self.attempts < 1 or self.delay_seconds < 0:
            raise ValueError("Requery needs attempts >= 1 and delay_seconds >= 0")

    @property
    def budget(self) -> str:
        return f"{self.attempts} queries over {(self.attempts - 1) * self.delay_seconds:g} s"


REQUERY = Requery()


def _requery(query: Callable[[], list[dict[str, Any]]], requery: Requery) -> list[dict[str, Any]]:
    """`query()` until it returns something, within `requery`'s budget."""
    found = query()
    for _ in range(requery.attempts - 1):
        if found:
            break
        requery.sleep(requery.delay_seconds)
        found = query()
    return found


def parse_tag(tag: str) -> Version | None:
    match = TAG_PATTERN.match(tag)
    if match is None:
        return None
    return (int(match[1]), int(match[2]), int(match[3]))


# --------------------------------------------------------------------------
# Git and GitHub access. Both are narrow so tests can replace them.


class Git:
    """Read-only access to a local clone."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        if check and result.returncode != 0:
            raise ReleaseError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
        return result

    def resolve_commit(self, ref: str) -> str | None:
        result = self._run("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False)
        return result.stdout.strip() if result.returncode == 0 else None

    def head(self) -> str:
        return self._run("rev-parse", "HEAD").stdout.strip()

    def is_clean(self) -> bool:
        return self._run("status", "--porcelain", "--untracked-files=normal").stdout.strip() == ""

    def object_type(self, ref: str) -> str | None:
        result = self._run("cat-file", "-t", ref, check=False)
        return result.stdout.strip() if result.returncode == 0 else None

    def tag_object(self, tag: str) -> str:
        return self._run("cat-file", "-p", f"refs/tags/{tag}").stdout

    def tags(self) -> list[str]:
        return [line for line in self._run("tag", "--list", "v*").stdout.splitlines() if line]

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        return (
            self._run("merge-base", "--is-ancestor", ancestor, descendant, check=False).returncode
            == 0
        )

    def first_parent_history(self, ref: str) -> set[str]:
        return set(self._run("rev-list", "--first-parent", ref).stdout.split())

    def show(self, commit: str, path: str) -> str | None:
        result = self._run("show", f"{commit}:{path}", check=False)
        return result.stdout if result.returncode == 0 else None

    def has_signing_key(self) -> bool:
        """Whether `user.signingkey` is set; its value is never printed."""
        result = self._run("config", "--get", "user.signingkey", check=False)
        return result.returncode == 0 and result.stdout.strip() != ""


class GitHub(Protocol):
    def pull_request(self, number: int) -> dict[str, Any] | None: ...

    def ci_runs(self, commit: str) -> list[dict[str, Any]]: ...

    def run_jobs(self, run_id: int) -> list[dict[str, Any]]: ...

    def releases_for_tag(self, tag: str) -> list[dict[str, Any]]: ...

    def remote_tag(self, tag: str) -> tuple[str, str] | None:
        """(object type, peeled commit) of the tag on GitHub, or None."""
        ...

    def tag_signature(self, tag: str) -> tuple[bool, str] | None:
        """(verified, reason) of the annotated tag's signature as GitHub
        reports it, or None when GitHub has no annotated tag of that name."""
        ...

    def create_release(self, payload: dict[str, Any]) -> dict[str, Any]: ...


class GhCli:
    """GitHub REST access through `gh api`; `gh` reads its own credentials."""

    def __init__(self, repository: str) -> None:
        self.repository = repository

    def _api(self, path: str, *extra: str, stdin: str | None = None) -> str | None:
        result = subprocess.run(
            ["gh", "api", *extra, f"repos/{self.repository}/{path}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            input=stdin,
            check=False,
        )
        if result.returncode != 0:
            if "HTTP 404" in result.stderr:
                return None
            raise ReleaseError(f"gh api {path} failed: {result.stderr.strip()}")
        return result.stdout

    def pull_request(self, number: int) -> dict[str, Any] | None:
        body = self._api(f"pulls/{number}")
        return None if body is None else json.loads(body)

    def ci_runs(self, commit: str) -> list[dict[str, Any]]:
        body = self._api(
            f"actions/workflows/{CI_WORKFLOW_FILE}/runs"
            f"?head_sha={commit}&event=push&branch=main&per_page=100"
        )
        return [] if body is None else json.loads(body)["workflow_runs"]

    def run_jobs(self, run_id: int) -> list[dict[str, Any]]:
        body = self._api(f"actions/runs/{run_id}/jobs?per_page=100")
        return [] if body is None else json.loads(body)["jobs"]

    def releases_for_tag(self, tag: str) -> list[dict[str, Any]]:
        # The list includes drafts, which `releases/tags/{tag}` does not.
        body = self._api("releases?per_page=100", "--paginate", "--jq", ".[]")
        releases = [json.loads(line) for line in (body or "").splitlines() if line.strip()]
        return [release for release in releases if release.get("tag_name") == tag]

    def remote_tag(self, tag: str) -> tuple[str, str] | None:
        body = self._api(f"git/ref/tags/{tag}")
        if body is None:
            return None
        target = json.loads(body)["object"]
        if target["type"] != "tag":
            return (target["type"], target["sha"])
        tag_body = self._api(f"git/tags/{target['sha']}")
        if tag_body is None:
            raise ReleaseError(f"tag object {target['sha']} of {tag} not found")
        return ("tag", json.loads(tag_body)["object"]["sha"])

    def tag_signature(self, tag: str) -> tuple[bool, str] | None:
        body = self._api(f"git/ref/tags/{tag}")
        if body is None:
            return None
        target = json.loads(body)["object"]
        if target["type"] != "tag":
            return None
        tag_body = self._api(f"git/tags/{target['sha']}")
        if tag_body is None:
            return None
        verification = json.loads(tag_body).get("verification") or {}
        return (verification.get("verified") is True, str(verification.get("reason")))

    def create_release(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = self._api("releases", "--method", "POST", "--input", "-", stdin=json.dumps(payload))
        if body is None:
            raise ReleaseError("creating the release returned 404")
        return json.loads(body)


# --------------------------------------------------------------------------
# Validation


@dataclasses.dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


@dataclasses.dataclass(frozen=True)
class ChangelogEntry:
    version: str
    date: str
    body: str
    pull_request: int | None
    next_version: str | None
    next_body: str


@dataclasses.dataclass
class Report:
    tag: str
    stage: str
    offline: bool
    checks: list[Check] = dataclasses.field(default_factory=list)
    commit: str | None = None
    previous_tag: str | None = None
    previous_commit: str | None = None
    entry: ChangelogEntry | None = None
    ci_run: dict[str, Any] | None = None
    ci_jobs: list[str] = dataclasses.field(default_factory=list)
    signed_tag_required: bool = False
    signature_verified: bool = False

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(check.ok for check in self.checks)

    def add(self, name: str, ok: bool, detail: str) -> bool:
        self.checks.append(Check(name, ok, detail))
        return ok

    def render(self) -> str:
        lines = [f"release validation: {self.tag}, stage {self.stage}"]
        lines += [f"  [{'PASS' if c.ok else 'FAIL'}] {c.name}: {c.detail}" for c in self.checks]
        if self.offline:
            lines.append(
                "  offline: no GitHub check ran (pull request, CI, releases, remote tag, signature)"
            )
        verdict = "PASS" if self.ok else "FAIL"
        if self.ok and self.offline:
            verdict = "PASS (offline rehearsal; not sufficient to publish)"
        lines.append(f"result: {verdict}")
        return "\n".join(lines)


def parse_changelog(text: str) -> list[tuple[str, str, str]]:
    """[(version, date, body)] in file order."""
    headings = list(ENTRY_HEADING.finditer(text))
    entries = []
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        entries.append((heading[1], heading[2], text[heading.end() : end].strip()))
    return entries


def _changelog_entry(report: Report, text: str | None) -> ChangelogEntry | None:
    if text is None:
        report.add("changelog", False, "CHANGELOG.md is missing at the release commit")
        return None
    entries = parse_changelog(text)
    if not entries or entries[0][0] != report.tag:
        top = entries[0][0] if entries else "none"
        report.add("changelog", False, f"the newest entry is {top}, not {report.tag}")
        return None
    version, date, body = entries[0]
    problems = []
    try:
        dt.date.fromisoformat(date)
    except ValueError:
        problems.append(f"invalid date {date}")
    if not re.search(r"^- ", body, re.MULTILINE):
        problems.append("no change listed")
    if "Migration head:" not in body:
        problems.append("no migration head")
    pull_request = PULL_REQUEST_REFERENCE.search(body.split("\n\n", 1)[0])
    if pull_request is None:
        problems.append("the first paragraph names no release pull request")
    if problems:
        report.add("changelog", False, "; ".join(problems))
        return None
    next_version, next_body = (entries[1][0], entries[1][2]) if len(entries) > 1 else (None, "")
    entry = ChangelogEntry(
        version,
        date,
        body,
        int(pull_request[1]) if pull_request else None,
        next_version,
        next_body,
    )
    report.add("changelog", True, f"{version} ({date}), release pull request #{entry.pull_request}")
    return entry


def _check_tag_object(report: Report, git: Git, commit: str | None) -> str | None:
    """The tag must be annotated, name itself, and peel to the commit."""
    ref = f"refs/tags/{report.tag}"
    kind = git.object_type(ref)
    if kind is None:
        report.add("tag", False, f"{report.tag} does not exist locally")
        return None
    if kind != "tag":
        report.add("tag", False, f"{report.tag} is a lightweight tag ({kind}); annotated required")
        return None
    header = git.tag_object(report.tag)
    if f"\ntag {report.tag}\n" not in f"\n{header}":
        report.add("tag", False, f"the tag object does not name {report.tag}")
        return None
    peeled = git.resolve_commit(ref)
    if commit is not None and peeled != commit:
        report.add("tag", False, f"{report.tag} points to {peeled}, expected {commit}")
        return None
    report.add("tag", True, f"{report.tag} is annotated and points to {peeled}")
    return peeled


def _check_previous_release(
    report: Report, git: Git, version: Version, commit: str, entry: ChangelogEntry | None
) -> None:
    releases: dict[Version, str] = {}
    for tag in git.tags():
        parsed = parse_tag(tag)
        if parsed is not None and tag != report.tag:
            releases[parsed] = tag
    newer = sorted(tag for parsed, tag in releases.items() if parsed > version)
    if newer:
        report.add("version order", False, f"{report.tag} is not newer than {', '.join(newer)}")
        return
    earlier = sorted(releases)
    if not earlier:
        report.add("version order", True, f"{report.tag} is the first release")
        return
    previous = releases[earlier[-1]]
    report.add("version order", True, f"{report.tag} follows {previous}")
    previous_commit = git.resolve_commit(f"refs/tags/{previous}")
    problems = []
    if git.object_type(f"refs/tags/{previous}") != "tag":
        problems.append(f"{previous} is not an annotated tag")
    if previous_commit is None or previous_commit == commit:
        problems.append(f"{previous} points to the release commit itself; nothing to release")
    elif not git.is_ancestor(previous_commit, commit):
        problems.append(f"{previous} ({previous_commit}) is not an ancestor of {commit}")
    if entry is not None:
        if entry.next_version != previous:
            problems.append(f"the changelog entry after {report.tag} is {entry.next_version}")
        elif previous_commit is not None and previous_commit not in entry.next_body:
            problems.append(f"the {previous} entry does not name its full SHA {previous_commit}")
    if problems:
        report.add("previous release", False, "; ".join(problems))
        return
    report.previous_tag, report.previous_commit = previous, previous_commit
    report.add("previous release", True, f"{previous} ({previous_commit}) is an ancestor")


def _check_github(report: Report, github: GitHub, commit: str, requery: Requery) -> None:
    entry = report.entry
    if entry is not None and entry.pull_request is not None:
        pull = github.pull_request(entry.pull_request)
        if pull is None:
            report.add("release pull request", False, f"#{entry.pull_request} not found")
        elif not pull.get("merged") or pull.get("merge_commit_sha") != commit:
            report.add(
                "release pull request",
                False,
                f"#{entry.pull_request} merged={pull.get('merged')}, "
                f"merge commit {pull.get('merge_commit_sha')}, expected {commit}",
            )
        elif (pull.get("base") or {}).get("ref") != "main":
            report.add("release pull request", False, f"#{entry.pull_request} did not target main")
        else:
            report.add("release pull request", True, f"#{entry.pull_request} merged as {commit}")

    runs = _requery(
        lambda: [
            run
            for run in github.ci_runs(commit)
            if run.get("head_sha") == commit and run.get("event") == "push"
        ],
        requery,
    )
    if not runs:
        report.add("main CI", False, f"no CI run for a push to main on {commit} ({requery.budget})")
    else:
        latest = max(runs, key=lambda run: (run.get("created_at") or "", run.get("id") or 0))
        jobs = github.run_jobs(int(latest["id"]))
        succeeded = {job["name"] for job in jobs if job.get("conclusion") == "success"}
        failed = sorted(job["name"] for job in jobs if job.get("conclusion") != "success")
        missing = [name for name in REQUIRED_CI_JOBS if name not in succeeded]
        if latest.get("status") != "completed" or latest.get("conclusion") != "success":
            report.add(
                "main CI",
                False,
                f"run {latest['id']} is {latest.get('status')}/{latest.get('conclusion')}",
            )
        elif missing or failed:
            report.add(
                "main CI",
                False,
                f"run {latest['id']}: missing {missing}, not successful {failed}",
            )
        else:
            report.ci_run, report.ci_jobs = latest, sorted(succeeded)
            report.add(
                "main CI", True, f"run {latest['id']}: {len(jobs)} of {len(jobs)} jobs passed"
            )

    remote = github.remote_tag(report.tag)
    if report.signed_tag_required and report.stage != "pre-tag":
        signature = github.tag_signature(report.tag)
        if signature is None:
            report.add("tag signature", False, f"GitHub has no annotated {report.tag} to check")
        elif not signature[0]:
            report.add(
                "tag signature",
                False,
                f"GitHub does not verify the signature of {report.tag} ({signature[1]}); "
                "sign it with the owner's key (git tag -s)",
            )
        else:
            report.signature_verified = True
            report.add("tag signature", True, f"GitHub verified the signature of {report.tag}")
    if report.stage == "pre-tag":
        report.add(
            "remote tag",
            remote is None,
            "absent on GitHub" if remote is None else f"{report.tag} already exists on GitHub",
        )
    elif remote is None:
        report.add("remote tag", False, f"{report.tag} is not on GitHub")
    else:
        kind, peeled = remote
        report.add(
            "remote tag",
            kind == "tag" and peeled == commit,
            f"GitHub has a {kind} pointing to {peeled}",
        )

    if report.stage in ("pre-tag", "publish"):
        # No release is the passing answer here, so it is never asked again.
        releases = github.releases_for_tag(report.tag)
        report.add(
            "existing release",
            not releases,
            "none" if not releases else f"{len(releases)} release(s) already use {report.tag}",
        )
    else:
        releases = _requery(lambda: github.releases_for_tag(report.tag), requery)
        _check_published(report, releases, commit, requery)


def _check_published(
    report: Report, releases: list[dict[str, Any]], commit: str, requery: Requery
) -> None:
    if not releases:
        report.add("published release", False, f"0 releases use {report.tag} ({requery.budget})")
        return
    if len(releases) != 1:
        report.add("published release", False, f"{len(releases)} releases use {report.tag}")
        return
    release = releases[0]
    problems = []
    if release.get("draft"):
        problems.append("it is a draft")
    if release.get("name") != release_name(report.tag):
        problems.append(f"its name is {release.get('name')!r}")
    if commit not in (release.get("body") or ""):
        problems.append("its notes do not name the release commit")
    if problems:
        report.add("published release", False, "; ".join(problems))
    else:
        report.add("published release", True, str(release.get("html_url")))


def validate(
    *,
    tag: str,
    stage: str,
    git: Git,
    github: GitHub | None,
    main_ref: str = "origin/main",
    expect_commit: str | None = None,
    requery: Requery | None = None,
    signed_from: Version | None = None,
) -> Report:
    """Every check for `stage`; GitHub checks are skipped when `github` is None.
    `requery` and `signed_from` default to the module's `REQUERY` and
    `SIGNED_TAGS_FROM`, read at call time."""
    report = Report(tag=tag, stage=stage, offline=github is None)
    version = parse_tag(tag)
    if not report.add("tag syntax", version is not None, tag):
        return report
    assert version is not None
    report.signed_tag_required = version >= (signed_from or SIGNED_TAGS_FROM)
    if expect_commit is not None and not FULL_SHA_PATTERN.match(expect_commit):
        report.add("expected commit", False, f"{expect_commit!r} is not a full 40-character SHA")
        return report

    if stage == "pre-tag":
        if git.object_type(f"refs/tags/{tag}") is not None:
            report.add("tag", False, f"{tag} already exists; a tag is never replaced")
            return report
        report.add("tag", True, f"{tag} does not exist yet")
        clean = git.is_clean()
        detail = "no changes" if clean else "the working tree has uncommitted or untracked changes"
        if not report.add("clean candidate", clean, detail):
            return report
        if report.signed_tag_required:
            has_key = git.has_signing_key()
            report.add(
                "signing key",
                has_key,
                "user.signingkey is set (git tag -s will sign)"
                if has_key
                else f"no user.signingkey configured; {tag} must be a signed tag (git tag -s)",
            )
        commit = git.head()
        if expect_commit is not None and commit != expect_commit:
            report.add("candidate", False, f"HEAD is {commit}, expected {expect_commit}")
            return report
    else:
        peeled = _check_tag_object(report, git, expect_commit)
        if peeled is None:
            return report
        commit = peeled
    report.commit = commit

    main = git.resolve_commit(main_ref)
    if main is None:
        report.add("on main", False, f"{main_ref} not found")
        return report
    on_main = commit in git.first_parent_history(main)
    relation = "is" if on_main else "is not"
    report.add("on main", on_main, f"{commit} {relation} a first-parent commit of {main_ref}")

    pyproject = git.show(commit, "pyproject.toml")
    package_version = None
    if pyproject is not None:
        package_version = tomllib.loads(pyproject).get("project", {}).get("version")
    report.add(
        "package version",
        package_version == tag[1:],
        f"pyproject.toml says {package_version}, the tag says {tag[1:]}",
    )

    report.entry = _changelog_entry(report, git.show(commit, "CHANGELOG.md"))
    _check_previous_release(report, git, version, commit, report.entry)

    if github is not None:
        _check_github(report, github, commit, requery or REQUERY)
    return report


# --------------------------------------------------------------------------
# Release notes and publication


def release_name(tag: str) -> str:
    return f"SaaS OS {tag}"


def render_notes(report: Report, repository: str) -> str:
    """The release notes: the changelog entry plus source and evidence."""
    entry, commit = report.entry, report.commit
    if entry is None or commit is None:
        raise ReleaseError("release notes need a validated changelog entry and commit")
    kind = (
        "annotated, signed; GitHub verified the signature"
        if report.signature_verified
        else ("annotated")
    )
    lines = [
        f"SaaS OS {report.tag}, released {entry.date}.",
        "",
        entry.body,
        "",
        "## Source",
        "",
        f"- Tag `{report.tag}` ({kind}) on commit `{commit}`.",
        f"- Pin: `saas-os @ git+https://github.com/{repository}@{commit}`. "
        "Pin the commit SHA, not the tag (ADR-0015 rule 8).",
    ]
    if report.previous_tag is not None:
        lines.append(
            f"- Previous release: `{report.previous_tag}` (`{report.previous_commit}`). "
            f"Changes: https://github.com/{repository}/compare/"
            f"{report.previous_tag}...{report.tag}"
        )
    lines += ["", "## Verification", ""]
    if report.ci_run is None:
        lines.append("- Not checked: offline rehearsal, no GitHub evidence was read.")
    else:
        lines.append(
            f"- CI run {report.ci_run['id']} ({report.ci_run.get('html_url')}) passed on this "
            f"commit, a push to `main`: {len(report.ci_jobs)} of {len(report.ci_jobs)} jobs "
            "succeeded."
        )
        lines.append(
            f"- Release pull request #{entry.pull_request} was merged; its merge commit is this "
            "commit."
        )
        lines.append(
            "- `scripts/release.py` checked the tag, the package version, the changelog entry "
            "and the previous release before this release was created."
        )
    lines += [
        "",
        "## What this release is not",
        "",
        "A GitHub Release is a label with these notes. No package was published to PyPI or any "
        "other index, and nothing was deployed. Each product pins the commit above and qualifies "
        "its own deployment (`docs/CONSUMER-GUIDE.md` section 15).",
        "",
    ]
    return "\n".join(lines)


def notes_digest(notes: str) -> str:
    return hashlib.sha256(notes.encode("utf-8")).hexdigest()


def publish(
    *,
    tag: str,
    git: Git,
    github: GitHub,
    repository: str,
    expect_commit: str,
    expect_notes_sha256: str | None,
    main_ref: str = "origin/main",
    requery: Requery | None = None,
    signed_from: Version | None = None,
) -> tuple[Report, dict[str, Any] | None]:
    """Validate again, then create the release; nothing is created on any failure."""
    report = validate(
        tag=tag,
        stage="publish",
        git=git,
        github=github,
        main_ref=main_ref,
        expect_commit=expect_commit,
        requery=requery,
        signed_from=signed_from,
    )
    if not report.ok:
        return report, None
    notes = render_notes(report, repository)
    if expect_notes_sha256 is not None and notes_digest(notes) != expect_notes_sha256:
        report.add("release notes", False, "the notes differ from the validated ones")
        return report, None
    created = github.create_release(
        {
            "tag_name": tag,
            # Ignored while the tag exists, which the checks above require;
            # if it vanished meanwhile, GitHub would create a lightweight tag
            # here, on the validated commit and nowhere else, and the
            # verification below would fail on it.
            "target_commitish": report.commit,
            "name": release_name(tag),
            "body": notes,
            "draft": False,
            "prerelease": False,
            "make_latest": "true",
        }
    )
    return report, created


# --------------------------------------------------------------------------
# Command line


def _write_outputs(values: dict[str, str]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    git: Git | None = None,
    github: GitHub | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description="SaaS OS release validation and GitHub Release publication"
    )
    parser.add_argument("command", choices=("validate", "publish", "verify"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--stage", choices=STAGES, default="publish")
    parser.add_argument("--expect-commit")
    parser.add_argument("--expect-notes-sha256")
    parser.add_argument("--notes-out", type=Path)
    parser.add_argument("--main-ref", default="origin/main")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPOSITORY))
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)

    git = git or Git(Path.cwd())
    if args.offline and args.command == "publish":
        print("publish needs the GitHub checks; --offline is refused", file=sys.stderr)
        return 2
    if github is None and not args.offline:
        github = GhCli(args.repo)
    if args.offline:
        github = None

    try:
        if args.command == "publish":
            if not args.expect_commit:
                print("publish needs --expect-commit", file=sys.stderr)
                return 2
            assert github is not None
            report, created = publish(
                tag=args.tag,
                git=git,
                github=github,
                repository=args.repo,
                expect_commit=args.expect_commit,
                expect_notes_sha256=args.expect_notes_sha256,
                main_ref=args.main_ref,
            )
            print(report.render())
            if created is None:
                print("nothing was published")
                return 1
            print(f"created {created.get('html_url')}")
            verification = validate(
                tag=args.tag,
                stage="verify",
                git=git,
                github=github,
                main_ref=args.main_ref,
                expect_commit=args.expect_commit,
            )
            print(verification.render())
            return 0 if verification.ok else 1

        stage = "verify" if args.command == "verify" else args.stage
        report = validate(
            tag=args.tag,
            stage=stage,
            git=git,
            github=github,
            main_ref=args.main_ref,
            expect_commit=args.expect_commit,
        )
        print(report.render())
        if report.ok and stage != "verify":
            notes = render_notes(report, args.repo)
            if args.notes_out is not None:
                args.notes_out.write_text(notes, encoding="utf-8", newline="\n")
            digest = notes_digest(notes)
            print(f"notes sha256: {digest}")
            _write_outputs({"commit": report.commit or "", "notes_sha256": digest})
        return 0 if report.ok else 1
    except ReleaseError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
