"""Read-only Git access for the updater (docs/AUTO-UPDATE-CLI.md).

Every call is a local, read-only `git` invocation against a repository on
disk: the updater never fetches, pushes, commits, stashes, resets or checks
anything out, and never talks to a hosting provider. Configuration that
could run an external program from a repository's own config (external
diff and textconv drivers, fsmonitor) is disabled per call, and Git is told
never to prompt.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
# A ref or abbreviated SHA a person may pass to discover a candidate. Never
# starts with "-" (it would be read as an option), no whitespace, no
# revision-range or reflog syntax.
_REF = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/\-]{0,254}$")
_TIMEOUT_SECONDS = 120


class GitError(RuntimeError):
    """A Git invocation failed or Git is unavailable."""


def is_full_sha(value: str) -> bool:
    """An exact, immutable commit id: 40 lowercase hexadecimal characters."""
    return bool(_FULL_SHA.match(value))


def is_valid_ref(value: str) -> bool:
    return bool(_REF.match(value)) and ".." not in value and "@{" not in value


def _environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _git(repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
    command = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-C",
        str(repository),
        *args,
    ]
    try:
        return subprocess.run(  # noqa: S603 -- fixed argv, no shell
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_environment(),
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(f"git could not be run: {type(exc).__name__}") from exc


def _git_ok(repository: Path, *args: str) -> str:
    result = _git(repository, *args)
    if result.returncode != 0:
        raise GitError(f"git {args[0]} failed")
    return result.stdout


def repository_root(path: Path) -> Path | None:
    """The top level of the work tree containing `path`, or `None`."""
    if not path.is_dir():
        return None
    result = _git(path, "rev-parse", "--show-toplevel")
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip()).resolve()


def resolve_commit(repository: Path, ref: str) -> str | None:
    """The full SHA of the commit `ref` names in `repository`, or `None`
    if it does not name a commit there."""
    if not is_valid_ref(ref):
        return None
    result = _git(repository, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    sha = result.stdout.strip()
    if result.returncode != 0 or not is_full_sha(sha):
        return None
    return sha


def is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    result = _git(repository, "merge-base", "--is-ancestor", ancestor, descendant)
    if result.returncode not in (0, 1):
        raise GitError("git merge-base failed")
    return result.returncode == 0


def commit_count(repository: Path, older: str, newer: str) -> int:
    return int(_git_ok(repository, "rev-list", "--count", f"{older}..{newer}").strip())


@dataclass(frozen=True)
class CommitInfo:
    subject: str
    committed_at: str


def commit_info(repository: Path, sha: str) -> CommitInfo:
    """Subject and committer date only -- no author e-mail, no body."""
    output = _git_ok(repository, "show", "-s", "--no-show-signature", "--format=%s%x00%cI", sha)
    subject, _, committed_at = output.rstrip("\n").partition("\x00")
    return CommitInfo(subject=subject, committed_at=committed_at)


@dataclass(frozen=True)
class ChangedPath:
    status: str
    path: str


def changed_paths(repository: Path, older: str, newer: str) -> list[ChangedPath]:
    """Every path that differs between two commits, without rename
    detection (a rename is a deletion plus an addition, both classified)."""
    output = _git_ok(
        repository,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--name-status",
        "-z",
        older,
        newer,
    )
    fields = [field for field in output.split("\x00") if field]
    return [
        ChangedPath(status=fields[index][:1], path=fields[index + 1])
        for index in range(0, len(fields) - 1, 2)
    ]


def head(repository: Path) -> str | None:
    result = _git(repository, "rev-parse", "--verify", "--quiet", "HEAD")
    sha = result.stdout.strip()
    return sha if result.returncode == 0 and is_full_sha(sha) else None


def working_tree_changes(repository: Path) -> list[str]:
    """Every staged, modified, deleted or untracked (non-ignored) path."""
    output = _git_ok(repository, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    return [entry[3:] for entry in output.split("\x00") if len(entry) > 3]


def tracked_changes(repository: Path) -> list[str]:
    """Tracked paths whose content differs from HEAD (staged or not)."""
    unstaged = _git_ok(repository, "diff", "--no-ext-diff", "--name-only", "-z")
    staged = _git_ok(repository, "diff", "--no-ext-diff", "--cached", "--name-only", "-z")
    return sorted({path for path in (unstaged + staged).split("\x00") if path})
