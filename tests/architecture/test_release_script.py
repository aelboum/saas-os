"""The release validator and publisher (`scripts/release.py`) and the
release workflow (`.github/workflows/release.yml`), ADR-0015 amendment
"GitHub Releases".

Every case runs against a throwaway Git repository built in `tmp_path` and
a fake GitHub that records what would have been created. Nothing here
contacts GitHub, pushes, tags this repository or needs a credential.

Positive control: a release whose tag, version, changelog, release pull
request, main CI and previous release all agree validates, publishes once
and verifies. Negative controls: each way one of those can disagree fails
validation, and no release is created after any failure.
"""

from __future__ import annotations

import copy
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "release.py"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
REPOSITORY = "example/saas-os"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("release_script", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


release = _load()


# --------------------------------------------------------------------------
# A throwaway repository: v0.1.0, then a release commit for v0.1.1.


def _changelog(*entries: str) -> str:
    return "# Changelog\n\nSaaS OS releases.\n\n" + "\n".join(entries)


def _entry(version: str, pull_request: int, *, sha: str | None = None) -> str:
    first = (
        f"Commit `{sha}`, `main` after pull request #{pull_request}."
        if sha
        else f"The merge commit of pull request #{pull_request}, the release pull request."
    )
    return (
        f"## {version} (2026-10-20)\n\n{first}\n\n- **A change** (#{pull_request}).\n\n"
        "Migration head: `f6a2c8e4b1d9`, unchanged.\n"
    )


def _pyproject(version: str) -> str:
    return f'[project]\nname = "saas-os"\nversion = "{version}"\n'


class Repo:
    first: str
    release: str

    def __init__(self, root: Path) -> None:
        self.root = root

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.root, capture_output=True, text=True, check=True
        ).stdout.strip()

    def commit(self, message: str, files: dict[str, str]) -> str:
        for name, content in files.items():
            (self.root / name).write_text(content, encoding="utf-8", newline="\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def annotated_tag(self, tag: str, commit: str) -> None:
        self.git("tag", "-a", tag, commit, "-m", f"SaaS OS {tag}")

    def set_main(self, commit: str) -> None:
        self.git("update-ref", "refs/remotes/origin/main", commit)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Repo:
    # Isolate from the developer's Git configuration (signing, hooks, identity).
    empty = tmp_path / "gitconfig"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "Release Test")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "release-test@example.invalid")
    root = tmp_path / "repo"
    root.mkdir()
    repo = Repo(root)
    repo.git("init", "-q", "-b", "main")
    repo.first = repo.commit(
        "v0.1.0",
        {"pyproject.toml": _pyproject("0.1.0"), "CHANGELOG.md": _changelog(_entry("v0.1.0", 1))},
    )
    repo.annotated_tag("v0.1.0", repo.first)
    repo.release = repo.commit(
        "release: v0.1.1",
        {
            "pyproject.toml": _pyproject("0.1.1"),
            "CHANGELOG.md": _changelog(_entry("v0.1.1", 2), _entry("v0.1.0", 1, sha=repo.first)),
        },
    )
    repo.set_main(repo.release)
    return repo


class FakeGitHub:
    """What GitHub would answer for a correct v0.1.1; tests break one fact."""

    def __init__(self, repo: Repo, tag: str = "v0.1.1") -> None:
        commit = repo.release
        self.pulls: dict[int, dict[str, Any]] = {
            2: {"merged": True, "merge_commit_sha": commit, "base": {"ref": "main"}}
        }
        self.runs: list[dict[str, Any]] = [
            {
                "id": 100,
                "head_sha": commit,
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "created_at": "2026-10-20T10:00:00Z",
                "html_url": "https://github.invalid/run/100",
            }
        ]
        self.jobs: dict[int, list[dict[str, Any]]] = {
            100: [{"name": name, "conclusion": "success"} for name in release.REQUIRED_CI_JOBS]
        }
        self.tags: dict[str, tuple[str, str]] = {tag: ("tag", commit)}
        self.signatures: dict[str, tuple[bool, str]] = {tag: (True, "valid")}
        self.releases: list[dict[str, Any]] = []
        self.created: list[dict[str, Any]] = []

    def retarget(self, commit: str) -> None:
        """Point every GitHub fact at another release commit."""
        self.pulls[2]["merge_commit_sha"] = commit
        self.runs[0]["head_sha"] = commit
        self.tags = {"v0.1.1": ("tag", commit)}

    def pull_request(self, number: int) -> dict[str, Any] | None:
        return self.pulls.get(number)

    def ci_runs(self, commit: str) -> list[dict[str, Any]]:
        return [run for run in self.runs if run["head_sha"] == commit]

    def run_jobs(self, run_id: int) -> list[dict[str, Any]]:
        return self.jobs.get(run_id, [])

    def releases_for_tag(self, tag: str) -> list[dict[str, Any]]:
        return [r for r in self.releases if r["tag_name"] == tag]

    def remote_tag(self, tag: str) -> tuple[str, str] | None:
        return self.tags.get(tag)

    def tag_signature(self, tag: str) -> tuple[bool, str] | None:
        if self.tags.get(tag, ("", ""))[0] != "tag":
            return None
        return self.signatures.get(tag, (False, "unsigned"))

    def create_release(self, payload: dict[str, Any]) -> dict[str, Any]:
        created = {**copy.deepcopy(payload), "html_url": "https://github.invalid/release/1"}
        self.created.append(payload)
        self.releases.append(created)
        return created


@pytest.fixture(autouse=True)
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Every wait the script would make, recorded instead of slept: no test
    here waits in real time, and each one can assert how often it re-asked."""
    recorded: list[float] = []
    monkeypatch.setattr(release, "REQUERY", release.Requery(sleep=recorded.append))
    return recorded


class LaggingGitHub(FakeGitHub):
    """GitHub whose lists lag: the CI runs and the releases for the tag are
    missing from the first `hide_runs` / `hide_releases` answers. Counts every
    query, so a test can show what was asked again and what was not."""

    def __init__(self, repo: Repo, *, hide_runs: int = 0, hide_releases: int = 0) -> None:
        super().__init__(repo)
        self.hide_runs, self.hide_releases = hide_runs, hide_releases
        self.run_queries = self.release_queries = 0

    def ci_runs(self, commit: str) -> list[dict[str, Any]]:
        self.run_queries += 1
        return [] if self.run_queries <= self.hide_runs else super().ci_runs(commit)

    def releases_for_tag(self, tag: str) -> list[dict[str, Any]]:
        self.release_queries += 1
        if self.release_queries <= self.hide_releases:
            return []
        return super().releases_for_tag(tag)


def _validate(repo: Repo, github: FakeGitHub | None, **kwargs: Any) -> Any:
    kwargs.setdefault("tag", "v0.1.1")
    kwargs.setdefault("stage", "publish")
    return release.validate(git=release.Git(repo.root), github=github, **kwargs)


def _failed(report: Any) -> dict[str, str]:
    return {check.name: check.detail for check in report.checks if not check.ok}


def _publish(repo: Repo, github: FakeGitHub, **kwargs: Any) -> tuple[Any, Any]:
    kwargs.setdefault("expect_commit", repo.release)
    kwargs.setdefault("expect_notes_sha256", None)
    return release.publish(
        tag="v0.1.1",
        git=release.Git(repo.root),
        github=github,
        repository=REPOSITORY,
        **kwargs,
    )


def _tagged(repo: Repo) -> FakeGitHub:
    repo.annotated_tag("v0.1.1", repo.release)
    return FakeGitHub(repo)


# --------------------------------------------------------------------------
# Positive control


def test_a_consistent_release_validates_publishes_once_and_verifies(repo: Repo) -> None:
    github = _tagged(repo)
    report = _validate(repo, github)
    assert report.ok, report.render()
    assert report.commit == repo.release
    assert (report.previous_tag, report.previous_commit) == ("v0.1.0", repo.first)

    notes = release.render_notes(report, REPOSITORY)
    assert repo.release in notes and repo.first in notes
    assert "SaaS OS v0.1.1, released 2026-10-20." in notes
    assert "- **A change** (#2)." in notes
    assert "CI run 100" in notes and "7 of 7 jobs" in notes
    assert "No package was published to PyPI" in notes

    checked, created = _publish(repo, github, expect_notes_sha256=release.notes_digest(notes))
    assert checked.ok and created is not None
    assert github.created == [
        {
            "tag_name": "v0.1.1",
            "target_commitish": repo.release,
            "name": "SaaS OS v0.1.1",
            "body": notes,
            "draft": False,
            "prerelease": False,
            "make_latest": "true",
        }
    ]
    verified = _validate(repo, github, stage="verify")
    assert verified.ok, verified.render()


def test_pre_tag_passes_on_a_clean_candidate_before_the_tag_exists(repo: Repo) -> None:
    github = FakeGitHub(repo)
    github.tags = {}
    report = _validate(repo, github, stage="pre-tag")
    assert report.ok, report.render()
    assert report.commit == repo.release


def test_the_command_line_writes_the_notes_and_their_digest(
    repo: Repo,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    github = _tagged(repo)
    outputs = tmp_path / "outputs"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    notes = tmp_path / "notes.md"
    status = release.main(
        ["validate", "--tag", "v0.1.1", "--notes-out", str(notes), "--repo", REPOSITORY],
        git=release.Git(repo.root),
        github=github,
    )
    assert status == 0, capsys.readouterr().out
    digest = release.notes_digest(notes.read_text(encoding="utf-8"))
    assert outputs.read_text(encoding="utf-8") == (
        f"commit={repo.release}\nnotes_sha256={digest}\n"
    )
    assert github.created == []


def test_the_command_line_publishes_then_verifies(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    github = _tagged(repo)
    arguments = ["publish", "--tag", "v0.1.1", "--expect-commit", repo.release]
    assert release.main(arguments, git=release.Git(repo.root), github=github) == 0
    out = capsys.readouterr().out
    assert "created https://github.invalid/release/1" in out
    assert "stage verify" in out and len(github.created) == 1
    # A second run finds the release and creates nothing.
    assert release.main(arguments, git=release.Git(repo.root), github=github) == 1
    assert len(github.created) == 1


# --------------------------------------------------------------------------
# Version and tag


@pytest.mark.parametrize("tag", ["0.1.1", "v0.1", "v01.1.1", "v0.1.1-rc1", "v0.1.1 ", "V0.1.1"])
def test_an_invalid_tag_is_refused(repo: Repo, tag: str) -> None:
    report = _validate(repo, FakeGitHub(repo), tag=tag)
    assert not report.ok
    assert "tag syntax" in _failed(report)


def test_a_package_version_that_differs_from_the_tag_fails(repo: Repo) -> None:
    head = repo.commit("bump", {"pyproject.toml": _pyproject("0.1.2")})
    repo.set_main(head)
    repo.annotated_tag("v0.1.1", head)
    github = FakeGitHub(repo)
    github.retarget(head)
    failed = _failed(_validate(repo, github))
    assert "pyproject.toml says 0.1.2" in failed["package version"]


def test_an_existing_tag_is_never_replaced_at_pre_tag(repo: Repo) -> None:
    github = _tagged(repo)
    assert "already exists" in _failed(_validate(repo, github, stage="pre-tag"))["tag"]


def test_a_tag_already_on_github_fails_pre_tag(repo: Repo) -> None:
    report = _validate(repo, FakeGitHub(repo), stage="pre-tag")
    assert "already exists on GitHub" in _failed(report)["remote tag"]


def test_a_lightweight_tag_is_refused(repo: Repo) -> None:
    repo.git("tag", "v0.1.1", repo.release)
    assert "lightweight" in _failed(_validate(repo, FakeGitHub(repo)))["tag"]


def test_a_tag_on_another_commit_than_expected_fails(repo: Repo) -> None:
    repo.annotated_tag("v0.1.1", repo.first)
    report = _validate(repo, FakeGitHub(repo), expect_commit=repo.release)
    assert "expected" in _failed(report)["tag"]


def test_an_abbreviated_expected_commit_is_refused(repo: Repo) -> None:
    github = _tagged(repo)
    report = _validate(repo, github, expect_commit=repo.release[:7])
    assert "full 40-character SHA" in _failed(report)["expected commit"]


def test_a_github_tag_that_differs_from_the_local_one_fails(repo: Repo) -> None:
    github = _tagged(repo)
    github.tags["v0.1.1"] = ("commit", repo.release)
    assert "commit pointing" in _failed(_validate(repo, github))["remote tag"]
    github.tags["v0.1.1"] = ("tag", repo.first)
    assert repo.first in _failed(_validate(repo, github))["remote tag"]


def test_a_tag_on_a_commit_that_is_not_a_main_commit_fails(repo: Repo) -> None:
    repo.git("checkout", "-q", "-b", "side")
    side = repo.commit("side", {"notes.txt": "side\n"})
    repo.git("checkout", "-q", "main")
    repo.git("merge", "-q", "--no-ff", "side", "-m", "merge side")
    repo.set_main(repo.git("rev-parse", "HEAD"))
    repo.annotated_tag("v0.1.1", side)
    github = FakeGitHub(repo)
    github.retarget(side)
    assert "is not a first-parent commit" in _failed(_validate(repo, github))["on main"]


def test_a_version_older_than_an_existing_release_fails(repo: Repo) -> None:
    repo.annotated_tag("v0.2.0", repo.first)
    github = _tagged(repo)
    assert "not newer than v0.2.0" in _failed(_validate(repo, github))["version order"]


# --------------------------------------------------------------------------
# Candidate state


def test_a_dirty_candidate_fails_pre_tag(repo: Repo) -> None:
    (repo.root / "stray.txt").write_text("x\n", encoding="utf-8")
    github = FakeGitHub(repo)
    github.tags = {}
    report = _validate(repo, github, stage="pre-tag")
    assert "uncommitted or untracked" in _failed(report)["clean candidate"]


def test_a_candidate_other_than_the_expected_commit_fails_pre_tag(repo: Repo) -> None:
    github = FakeGitHub(repo)
    github.tags = {}
    report = _validate(repo, github, stage="pre-tag", expect_commit=repo.first)
    assert "expected" in _failed(report)["candidate"]


# --------------------------------------------------------------------------
# Previous release


def test_a_previous_release_that_is_not_an_ancestor_fails(repo: Repo) -> None:
    repo.git("tag", "-d", "v0.1.0")
    repo.git("checkout", "-q", "--orphan", "elsewhere")
    stray = repo.commit("elsewhere", {"other.txt": "x\n"})
    repo.git("checkout", "-q", "-f", "main")
    repo.annotated_tag("v0.1.0", stray)
    github = _tagged(repo)
    assert "not an ancestor" in _failed(_validate(repo, github))["previous release"]


def test_a_previous_release_on_the_release_commit_fails(repo: Repo) -> None:
    repo.git("tag", "-d", "v0.1.0")
    repo.annotated_tag("v0.1.0", repo.release)
    github = _tagged(repo)
    assert "nothing to release" in _failed(_validate(repo, github))["previous release"]


def test_a_lightweight_previous_release_fails(repo: Repo) -> None:
    repo.git("tag", "-d", "v0.1.0")
    repo.git("tag", "v0.1.0", repo.first)
    github = _tagged(repo)
    assert "not an annotated tag" in _failed(_validate(repo, github))["previous release"]


@pytest.mark.parametrize(
    ("previous_entry", "expected"),
    [
        (lambda first: _entry("v0.0.9", 1, sha=first), "entry after v0.1.1 is v0.0.9"),
        (lambda first: _entry("v0.1.0", 1, sha=first[:7]), "full SHA"),
    ],
    ids=["skips-the-previous-release", "previous-sha-abbreviated"],
)
def test_the_changelog_must_continue_from_the_previous_release(
    repo: Repo, previous_entry: Any, expected: str
) -> None:
    head = repo.commit(
        "changelog",
        {"CHANGELOG.md": _changelog(_entry("v0.1.1", 2), previous_entry(repo.first))},
    )
    repo.set_main(head)
    repo.annotated_tag("v0.1.1", head)
    github = FakeGitHub(repo)
    github.retarget(head)
    assert expected in _failed(_validate(repo, github))["previous release"]


# --------------------------------------------------------------------------
# Changelog and notes metadata


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (
            "## v0.1.0 (2026-10-20)\n\nOld.\n\n- x\n\nMigration head: `a`.\n",
            "newest entry is v0.1.0",
        ),
        ("## v0.1.1 (2026-10-20)\n\npull request #2.\n\nMigration head: `a`.\n", "no change"),
        ("## v0.1.1 (2026-10-20)\n\npull request #2.\n\n- x\n", "no migration head"),
        ("## v0.1.1 (2026-10-20)\n\nNo number.\n\n- x\n\nMigration head: `a`.\n", "pull request"),
        ("## v0.1.1 (2026-13-40)\n\npull request #2.\n\n- x\n\nMigration head: `a`.\n", "date"),
    ],
    ids=["not-newest", "no-changes", "no-migration-head", "no-pull-request", "bad-date"],
)
def test_an_incomplete_changelog_entry_fails(repo: Repo, entry: str, expected: str) -> None:
    head = repo.commit("changelog", {"CHANGELOG.md": _changelog(entry)})
    repo.set_main(head)
    repo.annotated_tag("v0.1.1", head)
    github = FakeGitHub(repo)
    github.retarget(head)
    assert expected in _failed(_validate(repo, github))["changelog"]


def test_notes_cannot_be_rendered_from_a_failed_validation(repo: Repo) -> None:
    report = _validate(repo, FakeGitHub(repo), tag="v0.1")
    with pytest.raises(release.ReleaseError):
        release.render_notes(report, REPOSITORY)


# --------------------------------------------------------------------------
# GitHub evidence


def test_a_release_pull_request_with_another_merge_commit_fails(repo: Repo) -> None:
    github = _tagged(repo)
    github.pulls[2]["merge_commit_sha"] = repo.first
    assert "expected" in _failed(_validate(repo, github))["release pull request"]


def test_an_unmerged_or_missing_release_pull_request_fails(repo: Repo) -> None:
    github = _tagged(repo)
    github.pulls[2]["merged"] = False
    assert "merged=False" in _failed(_validate(repo, github))["release pull request"]
    github.pulls = {}
    assert "not found" in _failed(_validate(repo, github))["release pull request"]


def test_a_release_pull_request_into_another_branch_fails(repo: Repo) -> None:
    github = _tagged(repo)
    github.pulls[2]["base"] = {"ref": "develop"}
    assert "did not target main" in _failed(_validate(repo, github))["release pull request"]


def test_no_main_ci_run_for_the_commit_fails(repo: Repo) -> None:
    github = _tagged(repo)
    github.runs = []
    assert "no CI run" in _failed(_validate(repo, github))["main CI"]


def test_a_ci_run_from_a_pull_request_is_not_evidence(repo: Repo) -> None:
    github = _tagged(repo)
    github.runs[0]["event"] = "pull_request"
    assert "no CI run" in _failed(_validate(repo, github))["main CI"]


@pytest.mark.parametrize(
    ("status", "conclusion"),
    [("completed", "failure"), ("in_progress", None), ("completed", "cancelled")],
)
def test_a_ci_run_that_did_not_succeed_fails(
    repo: Repo, status: str, conclusion: str | None
) -> None:
    github = _tagged(repo)
    github.runs[0].update(status=status, conclusion=conclusion)
    assert "run 100 is" in _failed(_validate(repo, github))["main CI"]


def test_the_newest_ci_run_decides(repo: Repo) -> None:
    github = _tagged(repo)
    github.runs.append(
        {**github.runs[0], "id": 101, "created_at": "2026-10-20T11:00:00Z", "conclusion": "failure"}
    )
    assert "run 101" in _failed(_validate(repo, github))["main CI"]


def test_a_missing_or_failed_required_job_fails(repo: Repo) -> None:
    github = _tagged(repo)
    github.jobs[100] = github.jobs[100][1:]
    assert "missing ['backend checks']" in _failed(_validate(repo, github))["main CI"]
    github.jobs[100] = [
        {"name": name, "conclusion": "skipped" if index == 0 else "success"}
        for index, name in enumerate(release.REQUIRED_CI_JOBS)
    ]
    assert "not successful ['backend checks']" in _failed(_validate(repo, github))["main CI"]


@pytest.mark.parametrize("draft", [False, True], ids=["published", "draft"])
def test_an_existing_release_for_the_tag_fails(repo: Repo, draft: bool) -> None:
    github = _tagged(repo)
    github.releases = [{"tag_name": "v0.1.1", "draft": draft}]
    assert "already use v0.1.1" in _failed(_validate(repo, github))["existing release"]


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"draft": True}, "draft"),
        ({"name": "v0.1.1"}, "its name"),
        ({"body": "no sha"}, "do not name the release commit"),
    ],
    ids=["draft", "name", "body"],
)
def test_verify_fails_on_a_release_that_does_not_match(
    repo: Repo, change: dict[str, Any], expected: str
) -> None:
    github = _tagged(repo)
    github.releases = [
        {"tag_name": "v0.1.1", "name": "SaaS OS v0.1.1", "body": repo.release, **change}
    ]
    assert expected in _failed(_validate(repo, github, stage="verify"))["published release"]


def test_verify_fails_without_exactly_one_release(repo: Repo) -> None:
    github = _tagged(repo)
    assert "0 releases" in _failed(_validate(repo, github, stage="verify"))["published release"]
    one = {"tag_name": "v0.1.1", "name": "SaaS OS v0.1.1", "body": repo.release}
    github.releases = [one, dict(one)]
    assert "2 releases" in _failed(_validate(repo, github, stage="verify"))["published release"]


# --------------------------------------------------------------------------
# GitHub's lists can lag: an empty answer is asked again, within a bound


def _lagging(repo: Repo, **hide: int) -> LaggingGitHub:
    repo.annotated_tag("v0.1.1", repo.release)
    return LaggingGitHub(repo, **hide)


def _published(repo: Repo) -> dict[str, Any]:
    return {"tag_name": "v0.1.1", "name": "SaaS OS v0.1.1", "body": repo.release}


def test_a_ci_run_that_appears_late_is_found(repo: Repo, sleeps: list[float]) -> None:
    github = _lagging(repo, hide_runs=2)
    report = _validate(repo, github)
    assert report.ok, report.render()
    assert github.run_queries == 3 and sleeps == [5.0, 5.0]


def test_a_ci_run_that_never_appears_fails_after_the_bound(repo: Repo, sleeps: list[float]) -> None:
    github = _lagging(repo, hide_runs=99)
    detail = _failed(_validate(repo, github))["main CI"]
    assert "no CI run" in detail and "6 queries over 25 s" in detail
    assert github.run_queries == 6 and sleeps == [5.0] * 5


def test_a_run_for_another_commit_is_never_accepted(repo: Repo, sleeps: list[float]) -> None:
    github = _lagging(repo)
    github.runs[0]["head_sha"] = repo.first
    # Even an API that ignored the commit filter would not make it evidence.
    github.ci_runs = lambda commit: list(github.runs)  # type: ignore[method-assign]
    assert "no CI run" in _failed(_validate(repo, github))["main CI"]
    assert len(sleeps) == 5


def test_a_failed_ci_run_is_not_asked_again(repo: Repo, sleeps: list[float]) -> None:
    github = _lagging(repo)
    github.runs[0]["conclusion"] = "failure"
    assert "run 100 is completed/failure" in _failed(_validate(repo, github))["main CI"]
    assert github.run_queries == 1 and sleeps == []


def test_a_release_that_appears_late_is_verified(repo: Repo, sleeps: list[float]) -> None:
    github = _lagging(repo, hide_releases=3)
    github.releases = [_published(repo)]
    report = _validate(repo, github, stage="verify")
    assert report.ok, report.render()
    assert github.release_queries == 4 and sleeps == [5.0] * 3


def test_a_release_that_never_appears_fails_after_the_bound(
    repo: Repo, sleeps: list[float]
) -> None:
    github = _lagging(repo)
    detail = _failed(_validate(repo, github, stage="verify"))["published release"]
    assert detail == "0 releases use v0.1.1 (6 queries over 25 s)"
    assert github.release_queries == 6 and len(sleeps) == 5


def test_a_release_for_another_tag_or_commit_is_never_accepted(
    repo: Repo, sleeps: list[float]
) -> None:
    github = _lagging(repo)
    github.releases = [{**_published(repo), "tag_name": "v0.1.0"}]
    assert "0 releases" in _failed(_validate(repo, github, stage="verify"))["published release"]
    sleeps.clear()
    github.releases = [{**_published(repo), "body": repo.first}]
    detail = _failed(_validate(repo, github, stage="verify"))["published release"]
    assert "do not name the release commit" in detail and sleeps == []


@pytest.mark.parametrize("stage", ["pre-tag", "publish"])
def test_no_release_before_publication_is_not_asked_again(
    repo: Repo, stage: str, sleeps: list[float]
) -> None:
    github = _lagging(repo)
    if stage == "pre-tag":
        repo.git("tag", "-d", "v0.1.1")
        github.tags = {}
    report = _validate(repo, github, stage=stage)
    assert report.ok, report.render()
    assert github.release_queries == 1 and sleeps == []


def test_an_api_error_is_never_retried_or_passed(
    repo: Repo, sleeps: list[float], capsys: pytest.CaptureFixture[str]
) -> None:
    github = _lagging(repo)
    calls: list[str] = []

    def _denied(commit: str) -> list[dict[str, Any]]:
        calls.append(commit)
        raise release.ReleaseError("gh api actions/workflows/ci.yml/runs failed: HTTP 403")

    github.ci_runs = _denied  # type: ignore[method-assign]
    with pytest.raises(release.ReleaseError):
        _validate(repo, github)
    assert calls == [repo.release] and sleeps == []
    arguments = ["verify", "--tag", "v0.1.1"]
    assert release.main(arguments, git=release.Git(repo.root), github=github) == 1
    assert "error: gh api" in capsys.readouterr().err and sleeps == []


def test_the_command_line_publishes_once_and_verifies_a_lagging_release(
    repo: Repo, sleeps: list[float], capsys: pytest.CaptureFixture[str]
) -> None:
    # The publish stage sees no release (its single query), then the new
    # release is missing from the next two answers, as in v0.4.0's run.
    github = _lagging(repo, hide_releases=3)
    arguments = ["publish", "--tag", "v0.1.1", "--expect-commit", repo.release]
    assert release.main(arguments, git=release.Git(repo.root), github=github) == 0
    out = capsys.readouterr().out
    assert "created https://github.invalid/release/1" in out and "result: PASS" in out
    assert len(github.created) == 1 and sleeps == [5.0, 5.0]


def test_the_requery_budget_is_bounded() -> None:
    assert release.REQUERY.attempts * release.REQUERY.delay_seconds <= 60
    assert (release.Requery().attempts, release.Requery().delay_seconds) == (6, 5.0)
    for attempts, delay in ((0, 5.0), (-1, 5.0), (3, -1.0)):
        with pytest.raises(ValueError):
            release.Requery(attempts=attempts, delay_seconds=delay)


# --------------------------------------------------------------------------
# Publication is never attempted after a failure


@pytest.mark.parametrize(
    "breakage",
    ["ci-failed", "release-exists", "wrong-commit", "lightweight-remote", "pull-request"],
)
def test_nothing_is_created_after_a_failed_validation(repo: Repo, breakage: str) -> None:
    github = _tagged(repo)
    expect_commit = repo.release
    if breakage == "ci-failed":
        github.runs[0]["conclusion"] = "failure"
    elif breakage == "release-exists":
        github.releases = [{"tag_name": "v0.1.1", "draft": True}]
    elif breakage == "wrong-commit":
        expect_commit = repo.first
    elif breakage == "lightweight-remote":
        github.tags["v0.1.1"] = ("commit", repo.release)
    else:
        github.pulls = {}
    report, created = _publish(repo, github, expect_commit=expect_commit)
    assert not report.ok and created is None
    assert github.created == []


def test_nothing_is_created_when_the_notes_differ_from_the_validated_ones(repo: Repo) -> None:
    github = _tagged(repo)
    report, created = _publish(repo, github, expect_notes_sha256="0" * 64)
    assert created is None and "release notes" in _failed(report)
    assert github.created == []


def test_the_command_line_publishes_nothing_on_failure_or_offline(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    github = _tagged(repo)
    github.runs = []
    arguments = ["publish", "--tag", "v0.1.1", "--expect-commit", repo.release]
    assert release.main(arguments, git=release.Git(repo.root), github=github) == 1
    assert "nothing was published" in capsys.readouterr().out
    assert release.main([*arguments, "--offline"], git=release.Git(repo.root), github=github) == 2
    assert release.main(arguments[:3], git=release.Git(repo.root), github=github) == 2
    assert github.created == []


def test_an_offline_rehearsal_is_labelled_and_reads_no_evidence(repo: Repo) -> None:
    repo.annotated_tag("v0.1.1", repo.release)
    report = _validate(repo, None)
    assert report.ok and report.offline
    assert "not sufficient to publish" in report.render()
    assert "Not checked: offline rehearsal" in release.render_notes(report, REPOSITORY)


# --------------------------------------------------------------------------
# Signed tags (ADR-0015 amendment of 2026-10-31). The throwaway repository's
# v0.1.1 stands in for a release at or after SIGNED_TAGS_FROM.

_SIGNED = {"signed_from": (0, 1, 1)}


def test_signed_tags_are_required_from_v0_6_0_and_not_before() -> None:
    assert release.SIGNED_TAGS_FROM == (0, 6, 0)


def test_a_release_before_the_threshold_is_judged_without_a_signature(repo: Repo) -> None:
    github = _tagged(repo)
    github.signatures = {}
    report = _validate(repo, github)
    assert report.ok, report.render()
    assert "tag signature" not in {check.name for check in report.checks}


def test_a_verified_signed_tag_validates_publishes_and_verifies(repo: Repo) -> None:
    github = _tagged(repo)
    report = _validate(repo, github, **_SIGNED)
    assert report.ok, report.render()
    assert report.signature_verified
    notes = release.render_notes(report, REPOSITORY)
    assert "(annotated, signed; GitHub verified the signature)" in notes
    checked, created = _publish(repo, github, **_SIGNED)
    assert checked.ok and created is not None
    assert _validate(repo, github, stage="verify", **_SIGNED).ok


@pytest.mark.parametrize("reason", ["unsigned", "unknown_key", "bad_email", "invalid"])
def test_a_tag_github_does_not_verify_is_never_published(repo: Repo, reason: str) -> None:
    github = _tagged(repo)
    github.signatures = {"v0.1.1": (False, reason)}
    report, created = _publish(repo, github, **_SIGNED)
    assert created is None and github.created == []
    assert reason in _failed(report)["tag signature"]
    assert not _validate(repo, github, stage="verify", **_SIGNED).ok


def test_a_tag_that_is_not_annotated_on_github_has_no_signature_to_check(repo: Repo) -> None:
    github = _tagged(repo)
    github.tags["v0.1.1"] = ("commit", repo.release)
    report = _validate(repo, github, **_SIGNED)
    assert "no annotated v0.1.1" in _failed(report)["tag signature"]


def test_pre_tag_needs_a_configured_signing_key(repo: Repo) -> None:
    github = FakeGitHub(repo)
    github.tags = {}
    report = _validate(repo, github, stage="pre-tag", **_SIGNED)
    assert "user.signingkey" in _failed(report)["signing key"]
    repo.git("config", "user.signingkey", "not-a-real-key-only-presence-is-checked")
    report = _validate(repo, github, stage="pre-tag", **_SIGNED)
    assert report.ok, report.render()
    assert "not-a-real-key" not in report.render()


def test_an_offline_rehearsal_does_not_judge_the_signature(repo: Repo) -> None:
    repo.annotated_tag("v0.1.1", repo.release)
    report = _validate(repo, None, **_SIGNED)
    assert report.ok and report.offline
    assert "signature" in report.render()  # named among the checks that did not run


# --------------------------------------------------------------------------
# The workflows


def _ci_job_names() -> list[str]:
    jobs = CI_WORKFLOW.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
    return re.findall(r"^  [a-z][a-z0-9_-]*:\n    name: (.+)$", jobs, re.MULTILINE)


def test_the_required_jobs_are_the_jobs_of_ci_yml() -> None:
    assert sorted(_ci_job_names()) == sorted(release.REQUIRED_CI_JOBS)


def _job(text: str, name: str) -> str:
    jobs = text.split("\njobs:\n", 1)[1]
    match = re.search(rf"^  {name}:\n(.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)", jobs, re.M | re.S)
    assert match is not None, name
    return match[1]


def test_the_release_workflow_is_least_privilege_and_never_runs_pull_request_code() -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    trigger = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert "pull_request" not in trigger
    assert re.search(r'^  push:\n    tags: \["v\*"\]$', trigger, re.M)
    assert "\npermissions: {}\n" in text

    validate, publish = _job(text, "validate"), _job(text, "publish")
    assert "write" not in validate and "contents: read" in validate
    assert "contents: write" in publish and "needs: validate" in publish
    # Publication, and only publication, runs in the approval environment.
    assert "\n    environment: release\n" in publish
    assert "environment:" not in validate
    assert len(re.findall(r"^\s+[a-z-]+: write$", text, re.M)) == 1

    # Publication re-checks the validated commit and notes.
    assert '--expect-commit "$EXPECT_COMMIT"' in publish
    assert '--expect-notes-sha256 "$EXPECT_NOTES"' in publish
    # A dispatch only validates unless publication is asked for.
    assert "if: github.event_name == 'push' || inputs.publish" in publish
    assert re.search(r"      publish:\n(?:        .+\n)*?        default: false\n", trigger)


def test_the_release_workflow_pins_actions_and_keeps_no_credential() -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    uses = re.findall(r"uses: (\S+)", text)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref) for ref in uses)
    assert text.count("persist-credentials: false") == len(uses)
    # Checking out the tag ref would turn the annotated tag lightweight
    # locally (actions/checkout issue 290), so every checkout names the SHA.
    assert text.count("ref: ${{ github.sha }}") == len(uses)
    assert set(re.findall(r"\$\{\{ (secrets\.\w+|github\.token) \}\}", text)) == {"github.token"}
    # Inputs reach the shell only through environment variables.
    run_blocks = re.findall(r"run: \|\n((?:          .+\n)+)", text)
    assert run_blocks and not any("${{" in block for block in run_blocks)


def test_the_release_workflow_never_creates_moves_or_deletes_tags_or_releases() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8").lower()
    script = SCRIPT_PATH.read_text(encoding="utf-8")
    for forbidden in ("git tag", "git push", "gh release", "twine", "pypi"):
        assert forbidden not in workflow
    assert script.count('"--method"') == 1 and '"--method", "POST"' in script
    for method in ("PATCH", "DELETE", "PUT"):
        assert f'"{method}"' not in script
    assert '"push"' not in re.sub(r'run\.get\("event"\) == "push"', "", script)
