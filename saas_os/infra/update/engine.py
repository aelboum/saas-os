"""Analysis and the transactional update (docs/AUTO-UPDATE-CLI.md).

    detect -> inspect -> classify -> preflight -> update -> validate
           -> accept OR roll back

`analyze()` reads and changes nothing. `update()` analyzes, and only for a
SAFE decision re-verifies that nothing it analyzed has changed, rewrites the
single pin, runs the consumer's configured validation, and -- on any
failure -- restores the pin file byte for byte and verifies the restore.
It never commits, pushes, stashes, resets or touches any other file.

A decision only ever moves towards caution: once any reason makes it
REVIEW_REQUIRED or BLOCKED, nothing later makes it SAFE.
"""

from __future__ import annotations

import enum
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from saas_os.infra.update import git
from saas_os.infra.update.config import ConfigError, UpdateConfig, load_config
from saas_os.infra.update.pins import (
    Pin,
    PinError,
    file_digest,
    find_pin,
    lock_files_mentioning,
    redact,
    restore,
    write_pin,
)
from saas_os.infra.update.policy import (
    POLICY_VERSION,
    Category,
    classify,
    policy_digest,
    requires_review,
)

REPORT_SCHEMA_VERSION = 1


class Decision(enum.StrEnum):
    SAFE = "safe"
    UP_TO_DATE = "up_to_date"
    REVIEW_REQUIRED = "review_required"
    BLOCKED = "blocked"


class Outcome(enum.StrEnum):
    NOT_APPLIED = "not_applied"
    APPLIED = "applied"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


class ExitCode(enum.IntEnum):
    """The stable exit-code contract (docs/AUTO-UPDATE-CLI.md)."""

    SUCCESS = 0  # check: SAFE to apply; update: applied and validated
    USAGE = 2  # invalid command line (argparse)
    UP_TO_DATE = 10
    REVIEW_REQUIRED = 20
    BLOCKED = 30
    VALIDATION_FAILED = 40  # update applied, validation failed, rollback verified
    ROLLBACK_FAILED = 50  # the consumer may be modified: manual intervention


_SEVERITY = {
    Decision.SAFE: 0,
    Decision.UP_TO_DATE: 0,
    Decision.REVIEW_REQUIRED: 1,
    Decision.BLOCKED: 2,
}


@dataclass(frozen=True)
class Reason:
    code: str
    detail: str
    decision: Decision


@dataclass
class CheckResult:
    argv: tuple[str, ...]
    status: str  # passed | failed | timed_out | error | not_run
    exit_code: int | None = None
    duration_seconds: float | None = None


@dataclass
class ChangedFile:
    path: str
    status: str
    category: Category


@dataclass
class Analysis:
    command: str
    candidate_ref: str
    decision: Decision = Decision.SAFE
    reasons: list[Reason] = field(default_factory=list)
    pin: Pin | None = None
    pin_digest: str | None = None
    consumer_head: str | None = None
    current_sha: str | None = None
    candidate_sha: str | None = None
    relationship: str | None = None  # same | ahead | behind | diverged
    commit_count: int | None = None
    candidate_subject: str | None = None
    candidate_committed_at: str | None = None
    changes: list[ChangedFile] = field(default_factory=list)
    config: UpdateConfig | None = None
    outcome: Outcome = Outcome.NOT_APPLIED
    checks: list[CheckResult] = field(default_factory=list)
    rollback_attempted: bool = False
    rollback_verified: bool | None = None

    def add(self, decision: Decision, code: str, detail: str) -> None:
        self.reasons.append(Reason(code=code, detail=detail, decision=decision))
        if _SEVERITY[decision] > _SEVERITY[self.decision] or (
            decision is Decision.UP_TO_DATE and self.decision is Decision.SAFE
        ):
            self.decision = decision

    @property
    def exit_code(self) -> ExitCode:
        if self.outcome is Outcome.ROLLBACK_FAILED:
            return ExitCode.ROLLBACK_FAILED
        if self.outcome is Outcome.ROLLED_BACK:
            return ExitCode.VALIDATION_FAILED
        return {
            Decision.SAFE: ExitCode.SUCCESS,
            Decision.UP_TO_DATE: ExitCode.UP_TO_DATE,
            Decision.REVIEW_REQUIRED: ExitCode.REVIEW_REQUIRED,
            Decision.BLOCKED: ExitCode.BLOCKED,
        }[self.decision]

    def to_dict(self) -> dict[str, object]:
        """The machine-readable report. Stable keys; no environment, no
        command output, no credentials (URLs are redacted)."""
        categories: dict[str, int] = {}
        for change in self.changes:
            categories[change.category.value] = categories.get(change.category.value, 0) + 1
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "command": self.command,
            "policy": {"version": POLICY_VERSION, "digest": policy_digest()},
            "decision": self.decision.value,
            "outcome": self.outcome.value,
            "exit_code": int(self.exit_code),
            "consumer": {
                "pin_file": self.pin.relative_file if self.pin else None,
                "pin_line": self.pin.line_number if self.pin else None,
                "pin_url": redact(self.pin.url) if self.pin else None,
                "current_sha": self.current_sha,
            },
            "candidate": {
                "ref": redact(self.candidate_ref),
                "sha": self.candidate_sha,
                "relationship": self.relationship,
                "commit_count": self.commit_count,
                "subject": redact(self.candidate_subject) if self.candidate_subject else None,
                "committed_at": self.candidate_committed_at,
            },
            "changes": {
                "files": [
                    {"path": c.path, "status": c.status, "category": c.category.value}
                    for c in self.changes
                ],
                "categories": dict(sorted(categories.items())),
                "review_categories": sorted(
                    {c.category.value for c in self.changes if requires_review(c.category)}
                ),
            },
            "reasons": [
                {"code": r.code, "decision": r.decision.value, "detail": redact(r.detail)}
                for r in self.reasons
            ],
            "checks": [
                {
                    "argv": [redact(part) for part in check.argv],
                    "status": check.status,
                    "exit_code": check.exit_code,
                    "duration_seconds": check.duration_seconds,
                }
                for check in self.checks
            ],
            "rollback": {
                "attempted": self.rollback_attempted,
                "verified": self.rollback_verified,
            },
        }


def analyze(
    consumer: Path, source: Path, candidate_ref: str, *, command: str = "check"
) -> Analysis:
    """Everything an update decision rests on. Reads only."""
    analysis = Analysis(command=command, candidate_ref=candidate_ref)
    consumer = consumer.resolve()
    source = source.resolve()

    consumer_root = git.repository_root(consumer)
    if consumer_root is None or consumer_root != consumer:
        analysis.add(
            Decision.BLOCKED,
            "consumer_not_repository",
            "the consumer path is not the root of a Git working tree",
        )
        return analysis
    analysis.consumer_head = git.head(consumer)

    try:
        analysis.config = load_config(consumer)
    except ConfigError as exc:
        analysis.add(Decision.BLOCKED, "config_malformed", str(exc))
        return analysis

    try:
        pin = find_pin(consumer, analysis.config.pin_files)
    except PinError as exc:
        analysis.add(Decision.BLOCKED, exc.code, exc.detail)
        return analysis
    analysis.pin = pin
    analysis.pin_digest = file_digest(pin.file)
    if not git.is_full_sha(pin.ref):
        analysis.add(
            Decision.BLOCKED,
            "pin_not_exact_sha",
            f"{pin.relative_file}:{pin.line_number} pins a mutable reference, not an exact "
            "commit SHA (ADR-0015 rule 8); pin an exact SHA first",
        )
        return analysis
    analysis.current_sha = pin.ref

    if git.repository_root(source) is None:
        analysis.add(
            Decision.BLOCKED, "source_not_repository", "the SaaS-OS source is not a Git repository"
        )
        return analysis
    if not git.is_valid_ref(candidate_ref):
        analysis.add(
            Decision.BLOCKED, "candidate_invalid", "the candidate is not a valid commit reference"
        )
        return analysis
    candidate_sha = git.resolve_commit(source, candidate_ref)
    if candidate_sha is None:
        analysis.add(
            Decision.BLOCKED,
            "candidate_unresolvable",
            "the candidate does not name a commit in the SaaS-OS source",
        )
        return analysis
    analysis.candidate_sha = candidate_sha
    if git.resolve_commit(source, analysis.current_sha) != analysis.current_sha:
        analysis.add(
            Decision.BLOCKED,
            "current_unverifiable",
            "the currently pinned SHA is not a commit in the SaaS-OS source; the change "
            "cannot be inspected",
        )
        return analysis

    info = git.commit_info(source, candidate_sha)
    analysis.candidate_subject = info.subject
    analysis.candidate_committed_at = info.committed_at

    if candidate_sha == analysis.current_sha:
        analysis.relationship = "same"
        analysis.commit_count = 0
        analysis.add(
            Decision.UP_TO_DATE, "already_current", "the consumer already pins the candidate"
        )
        return analysis

    if git.is_ancestor(source, analysis.current_sha, candidate_sha):
        analysis.relationship = "ahead"
        analysis.commit_count = git.commit_count(source, analysis.current_sha, candidate_sha)
    elif git.is_ancestor(source, candidate_sha, analysis.current_sha):
        analysis.relationship = "behind"
        analysis.commit_count = git.commit_count(source, candidate_sha, analysis.current_sha)
        analysis.add(
            Decision.REVIEW_REQUIRED,
            "candidate_older",
            "the candidate is older than the pinned SHA: a downgrade can revert fixes",
        )
    else:
        analysis.relationship = "diverged"
        analysis.add(
            Decision.REVIEW_REQUIRED,
            "candidate_diverged",
            "the candidate is not a descendant of the pinned SHA (diverged history)",
        )

    for changed in git.changed_paths(source, analysis.current_sha, candidate_sha):
        analysis.changes.append(
            ChangedFile(path=changed.path, status=changed.status, category=classify(changed.path))
        )
    for category in sorted({c.category for c in analysis.changes if requires_review(c.category)}):
        count = sum(1 for c in analysis.changes if c.category is category)
        analysis.add(
            Decision.REVIEW_REQUIRED,
            f"category:{category.value}",
            f"{count} changed path(s) classified {category.value} require human review",
        )
    if not analysis.changes:
        analysis.add(
            Decision.REVIEW_REQUIRED,
            "no_file_changes",
            "the candidate differs from the pinned SHA but changes no file; verify it manually",
        )

    locked = lock_files_mentioning(consumer, analysis.current_sha)
    if locked:
        analysis.add(
            Decision.BLOCKED,
            "lock_file_references_pin",
            f"lock file(s) also record the pinned SHA ({', '.join(locked)}); the updater "
            "changes only the pin and would leave them inconsistent",
        )

    dirty = git.working_tree_changes(consumer)
    if dirty:
        analysis.add(
            Decision.REVIEW_REQUIRED,
            "dirty_working_tree",
            f"the consumer has {len(dirty)} uncommitted or untracked path(s); "
            "the updater does not stash, reset or overwrite local work",
        )

    if command == "update":
        _preflight_update(analysis)
    return analysis


def _preflight_update(analysis: Analysis) -> None:
    """The conditions only applying (not inspecting) needs."""
    assert analysis.config is not None and analysis.pin is not None
    if not analysis.config.validation:
        analysis.add(
            Decision.BLOCKED,
            "validation_not_configured",
            "no validation is configured ([tool.saas-os-update] validation); an update "
            "is never accepted unvalidated",
        )
    pin_file = analysis.pin.file
    if pin_file.is_symlink() or not pin_file.is_file():
        analysis.add(
            Decision.BLOCKED,
            "rollback_not_guaranteed",
            f"{analysis.pin.relative_file} is not a regular file; a byte-exact rollback "
            "cannot be guaranteed",
        )


def _stale(analysis: Analysis, consumer: Path, source: Path) -> str | None:
    """Why the state analyzed is no longer the state on disk, if it is not."""
    assert analysis.pin is not None and analysis.config is not None
    if git.resolve_commit(source, analysis.candidate_ref) != analysis.candidate_sha:
        return "the candidate reference now names a different commit"
    if git.head(consumer) != analysis.consumer_head:
        return "the consumer's HEAD moved"
    if file_digest(analysis.pin.file) != analysis.pin_digest:
        return f"{analysis.pin.relative_file} changed"
    try:
        if find_pin(consumer, analysis.config.pin_files).ref != analysis.current_sha:
            return "the pinned SHA changed"
    except PinError as exc:
        return exc.detail
    if git.working_tree_changes(consumer):
        return "the consumer's working tree is no longer clean"
    return None


def _run_check(argv: tuple[str, ...], cwd: Path, timeout: int) -> CheckResult:
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 -- configured argv, never a shell
            list(argv),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CheckResult(argv, "timed_out", None, round(time.monotonic() - started, 3))
    except OSError:
        return CheckResult(argv, "error", None, round(time.monotonic() - started, 3))
    status = "passed" if completed.returncode == 0 else "failed"
    return CheckResult(argv, status, completed.returncode, round(time.monotonic() - started, 3))


def update(consumer: Path, source: Path, candidate_ref: str) -> Analysis:
    consumer = consumer.resolve()
    source = source.resolve()
    analysis = analyze(consumer, source, candidate_ref, command="update")
    if analysis.decision is not Decision.SAFE:
        return analysis
    assert analysis.pin is not None and analysis.config is not None
    assert analysis.candidate_sha is not None and git.is_full_sha(analysis.candidate_sha)

    stale = _stale(analysis, consumer, source)
    if stale is not None:
        analysis.add(Decision.BLOCKED, "stale_state", f"{stale} since it was analyzed; aborted")
        return analysis

    original: bytes | None = None
    failure: str | None = None
    try:
        original = write_pin(analysis.pin, analysis.candidate_sha)
    except PinError as exc:  # raised before anything is written
        analysis.add(Decision.BLOCKED, exc.code, f"{exc.detail}; aborted")
        return analysis
    try:
        if find_pin(consumer, analysis.config.pin_files).ref != analysis.candidate_sha:
            failure = "the rewritten pin does not read back as the candidate SHA"
        elif git.tracked_changes(consumer) != [analysis.pin.relative_file]:
            failure = "the update changed more than the pin file"
        else:
            for argv in analysis.config.validation:
                if failure is not None:
                    analysis.checks.append(CheckResult(argv, "not_run"))
                    continue
                result = _run_check(argv, consumer, analysis.config.timeout_seconds)
                analysis.checks.append(result)
                if result.status != "passed":
                    failure = f"validation check {len(analysis.checks)} {result.status}"
            if failure is None and git.tracked_changes(consumer) != [analysis.pin.relative_file]:
                failure = "validation changed tracked files other than the pin file"
    except Exception as exc:  # noqa: BLE001 -- any failure after writing must roll back
        failure = f"unexpected error during the update: {type(exc).__name__}"

    if failure is None:
        analysis.outcome = Outcome.APPLIED
        return analysis

    analysis.add(Decision.BLOCKED, "update_failed", failure)
    if original is None:
        return analysis  # nothing was written
    analysis.rollback_attempted = True
    try:
        verified = restore(analysis.pin.file, original)
    except OSError:
        verified = False
    analysis.rollback_verified = verified
    analysis.outcome = Outcome.ROLLED_BACK if verified else Outcome.ROLLBACK_FAILED
    return analysis
