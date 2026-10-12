"""`saas-os-update` end to end against throwaway local Git repositories
(docs/AUTO-UPDATE-CLI.md): the decision, the transactional update, the
rollback, and the machine-readable contract. No network."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from saas_os.infra.update import engine
from saas_os.infra.update.cli import main
from saas_os.infra.update.engine import Decision, ExitCode, Outcome, analyze, update

if shutil.which("git") is None:  # pragma: no cover
    pytest.skip("git is not installed", allow_module_level=True)

PIN_URL = "https://github.com/example/saas-os"
PASS = [sys.executable, "-c", "raise SystemExit(0)"]
FAIL = [sys.executable, "-c", "raise SystemExit(3)"]


def git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Update Test",
            "-c",
            "user.email=update-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            "-C",
            str(repository),
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


@dataclass
class Source:
    path: Path

    def commit(self, files: dict[str, str], message: str = "change") -> str:
        for name, content in files.items():
            target = self.path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        git(self.path, "add", "-A")
        git(self.path, "commit", "-q", "-m", message)
        return git(self.path, "rev-parse", "HEAD")


@dataclass
class Consumer:
    path: Path

    @property
    def pyproject(self) -> Path:
        return self.path / "pyproject.toml"

    def pinned(self) -> str:
        text = self.pyproject.read_text(encoding="utf-8")
        return text.split("saas-os @ git+")[1].split('"')[0].rsplit("@", 1)[1]

    def commits(self) -> int:
        return int(git(self.path, "rev-list", "--count", "HEAD"))


def _pyproject(sha: str, validation: list[list[str]] | None) -> str:
    lines = [
        "[project]",
        'name = "consumer"',
        'version = "0.1.0"',
        "dependencies = [",
        '    "httpx>=0.27",',
        f'    "saas-os @ git+{PIN_URL}@{sha}",',
        "]",
        "",
    ]
    if validation is not None:
        # A JSON string is a valid TOML basic string.
        rendered = ", ".join("[" + ", ".join(json.dumps(a) for a in c) + "]" for c in validation)
        lines += ["[tool.saas-os-update]", f"validation = [{rendered}]", ""]
    return "\n".join(lines)


@pytest.fixture
def source(tmp_path: Path) -> Source:
    path = tmp_path / "saas-os"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    repository = Source(path)
    repository.commit(
        {"saas_os/core/notifications/service.py": "VERSION = 1\n", "README.md": "v1\n"}, "base"
    )
    return repository


@pytest.fixture
def make_consumer(tmp_path: Path) -> Callable[..., Consumer]:
    def make(
        sha: str,
        validation: list[list[str]] | None = None,
        *,
        configured: bool = True,
        name: str = "consumer",
    ) -> Consumer:
        path = tmp_path / name
        path.mkdir()
        git(path, "init", "-q", "-b", "main")
        checks = (validation if validation is not None else [PASS]) if configured else None
        (path / "pyproject.toml").write_text(_pyproject(sha, checks), encoding="utf-8")
        (path / "app.py").write_text("print('app')\n", encoding="utf-8")
        git(path, "add", "-A")
        git(path, "commit", "-q", "-m", "consumer")
        return Consumer(path)

    return make


MakeConsumer = Callable[..., Consumer]


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict]:  # type: ignore[type-arg]
    code = main([*argv, "--format", "json"])
    return code, json.loads(capsys.readouterr().out)


def _untouched(consumer: Consumer, sha: str, commits: int = 1) -> None:
    assert consumer.pinned() == sha
    assert git(consumer.path, "status", "--porcelain") == ""
    assert consumer.commits() == commits


# --- SAFE ---------------------------------------------------------------------------


def test_a_safe_candidate_updates_only_the_pin_and_commits_nothing(
    source: Source, make_consumer: MakeConsumer, capsys: pytest.CaptureFixture[str]
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    candidate = source.commit(
        {"saas_os/core/notifications/service.py": "VERSION = 2\n", "docs/notes.md": "x\n"}, "fix"
    )
    consumer = make_consumer(base)
    before = consumer.pyproject.read_text(encoding="utf-8")

    code, report = _run(
        capsys,
        "update",
        "--source",
        str(source.path),
        "--candidate",
        "main",
        "--consumer",
        str(consumer.path),
    )

    assert code == ExitCode.SUCCESS
    assert (report["decision"], report["outcome"]) == ("safe", "applied")
    assert report["candidate"]["sha"] == candidate and consumer.pinned() == candidate
    assert consumer.pyproject.read_text(encoding="utf-8") == before.replace(base, candidate)
    assert git(consumer.path, "status", "--porcelain") == "M pyproject.toml"
    assert consumer.commits() == 1  # no commit was created
    assert [c["status"] for c in report["checks"]] == ["passed"]
    assert report["changes"]["categories"] == {"documentation": 1, "internal": 1}


def test_check_reports_without_changing_anything(
    source: Source, make_consumer: MakeConsumer, capsys: pytest.CaptureFixture[str]
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"})
    consumer = make_consumer(base)
    code, report = _run(
        capsys,
        "check",
        "--source",
        str(source.path),
        "--candidate",
        "main",
        "--consumer",
        str(consumer.path),
    )
    assert (code, report["decision"], report["outcome"]) == (0, "safe", "not_applied")
    assert report["candidate"]["relationship"] == "ahead"
    assert report["candidate"]["commit_count"] == 1
    _untouched(consumer, base)


def test_an_already_current_pin_is_up_to_date(
    source: Source, make_consumer: MakeConsumer, capsys: pytest.CaptureFixture[str]
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    consumer = make_consumer(base)
    code, report = _run(
        capsys,
        "update",
        "--source",
        str(source.path),
        "--candidate",
        base,
        "--consumer",
        str(consumer.path),
    )
    assert (code, report["decision"]) == (ExitCode.UP_TO_DATE, "up_to_date")
    _untouched(consumer, base)


# --- REVIEW_REQUIRED ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "category"),
    [
        ("saas_os/infra/db/migrations/versions/x_drop.py", "migration"),
        ("saas_os/infra/db/rls.py", "tenant_rls"),
        ("saas_os/core/rbac/authorization.py", "authorization"),
        ("saas_os/core/billing/stripe_provider.py", "provider_boundary"),
        ("saas_os/core/billing/commercial.py", "billing"),
        ("docs/ADR/0099-new.md", "architecture"),
        ("pyproject.toml", "dependency_toolchain"),
        ("saas_os/contracts/events.py", "public_api"),
        ("saas_os/infra/update/policy.py", "updater_policy"),
        ("frontend/app.tsx", "unknown"),
        ("saas_os/infra/db/init/01-create-app-role.sh", "security_control"),
        ("saas_os/core/outbox/dispatch.py", "security_control"),
        ("saas_os/control_plane/self_learning/service.py", "autonomous_orchestration"),
    ],
)
def test_a_sensitive_change_requires_review_and_changes_nothing(
    source: Source, make_consumer: MakeConsumer, path: str, category: str
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({path: "changed\n", "README.md": "v2\n"})
    consumer = make_consumer(base)
    analysis = update(consumer.path, source.path, "main")
    assert analysis.decision is Decision.REVIEW_REQUIRED
    assert analysis.exit_code is ExitCode.REVIEW_REQUIRED
    assert f"category:{category}" in {reason.code for reason in analysis.reasons}
    assert analysis.outcome is Outcome.NOT_APPLIED and analysis.checks == []
    _untouched(consumer, base)


def test_a_deleted_sensitive_file_also_requires_review(
    source: Source, make_consumer: MakeConsumer
) -> None:
    source.commit({"saas_os/core/rbac/authorization.py": "guard\n"})
    base = git(source.path, "rev-parse", "HEAD")
    git(source.path, "rm", "-q", "saas_os/core/rbac/authorization.py")
    git(
        source.path, "-c", "user.name=t", "-c", "user.email=t@x.invalid", "commit", "-q", "-m", "rm"
    )
    consumer = make_consumer(base)
    analysis = analyze(consumer.path, source.path, "main")
    assert analysis.decision is Decision.REVIEW_REQUIRED
    assert [(c.status, c.category.value) for c in analysis.changes] == [("D", "authorization")]


def test_an_older_candidate_requires_review(source: Source, make_consumer: MakeConsumer) -> None:
    older = git(source.path, "rev-parse", "HEAD")
    newer = source.commit({"README.md": "v2\n"})
    consumer = make_consumer(newer)
    analysis = update(consumer.path, source.path, older)
    assert analysis.relationship == "behind" and analysis.decision is Decision.REVIEW_REQUIRED
    assert "candidate_older" in {r.code for r in analysis.reasons}
    _untouched(consumer, newer)


def test_a_diverged_candidate_requires_review(source: Source, make_consumer: MakeConsumer) -> None:
    root = git(source.path, "rev-parse", "HEAD")
    pinned = source.commit({"README.md": "mainline\n"})
    git(source.path, "checkout", "-q", "-b", "side", root)
    side = source.commit({"docs/side.md": "side\n"})
    consumer = make_consumer(pinned)
    analysis = update(consumer.path, source.path, side)
    assert analysis.relationship == "diverged" and analysis.decision is Decision.REVIEW_REQUIRED
    _untouched(consumer, pinned)


@pytest.mark.parametrize("dirt", ["modified", "untracked", "staged"])
def test_local_changes_require_review_and_are_never_touched(
    source: Source, make_consumer: MakeConsumer, dirt: str
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"})
    consumer = make_consumer(base)
    if dirt == "modified":
        (consumer.path / "app.py").write_text("print('local work')\n", encoding="utf-8")
    elif dirt == "untracked":
        (consumer.path / "notes.txt").write_text("local\n", encoding="utf-8")
    else:
        (consumer.path / "new.py").write_text("x = 1\n", encoding="utf-8")
        git(consumer.path, "add", "new.py")
    status = git(consumer.path, "status", "--porcelain")
    analysis = update(consumer.path, source.path, "main")
    assert analysis.decision is Decision.REVIEW_REQUIRED
    assert "dirty_working_tree" in {r.code for r in analysis.reasons}
    assert consumer.pinned() == base and git(consumer.path, "status", "--porcelain") == status


# --- BLOCKED --------------------------------------------------------------------------


def test_an_unresolvable_candidate_is_blocked(source: Source, make_consumer: MakeConsumer) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    consumer = make_consumer(base)
    for candidate, code in (
        ("0" * 40, "candidate_unresolvable"),
        ("no-such-branch", "candidate_unresolvable"),
        ("--upload-pack=x", "candidate_invalid"),
    ):
        analysis = update(consumer.path, source.path, candidate)
        assert analysis.decision is Decision.BLOCKED
        assert code in {r.code for r in analysis.reasons}
    _untouched(consumer, base)


def test_a_pinned_sha_the_source_does_not_contain_cannot_be_verified(
    source: Source, make_consumer: MakeConsumer
) -> None:
    consumer = make_consumer("c" * 40)
    analysis = update(consumer.path, source.path, "main")
    assert analysis.decision is Decision.BLOCKED
    assert "current_unverifiable" in {r.code for r in analysis.reasons}
    _untouched(consumer, "c" * 40)


def test_a_mutable_current_pin_is_blocked(source: Source, make_consumer: MakeConsumer) -> None:
    consumer = make_consumer("main")
    analysis = update(consumer.path, source.path, "main")
    assert analysis.decision is Decision.BLOCKED
    assert "pin_not_exact_sha" in {r.code for r in analysis.reasons}


def test_a_mutable_candidate_ref_is_always_recorded_as_an_exact_sha(
    source: Source, make_consumer: MakeConsumer
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    candidate = source.commit({"README.md": "v2\n"})
    git(source.path, "tag", "v2")
    consumer = make_consumer(base)
    analysis = update(consumer.path, source.path, "v2")
    assert analysis.outcome is Outcome.APPLIED
    assert consumer.pinned() == candidate and "v2" not in consumer.pyproject.read_text("utf-8")


def test_missing_ambiguous_and_lock_file_pins_are_blocked(
    source: Source, make_consumer: MakeConsumer
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"})

    missing = make_consumer(base, name="missing")
    missing.pyproject.write_text('[project]\nname = "x"\n', encoding="utf-8")
    git(missing.path, "commit", "-q", "-am", "drop pin")

    ambiguous = make_consumer(base, name="ambiguous")
    (ambiguous.path / "requirements.txt").write_text(
        f"saas-os @ git+https://h/o/saas-os@{base}\n", encoding="utf-8"
    )
    git(ambiguous.path, "add", "-A")
    git(ambiguous.path, "commit", "-q", "-m", "second pin")

    locked = make_consumer(base, name="locked")
    (locked.path / "uv.lock").write_text(f'source = "git+https://h/o/saas-os@{base}"\n', "utf-8")
    git(locked.path, "add", "-A")
    git(locked.path, "commit", "-q", "-m", "lock")

    for consumer, code in (
        (missing, "pin_missing"),
        (ambiguous, "pin_ambiguous"),
        (locked, "lock_file_references_pin"),
    ):
        analysis = update(consumer.path, source.path, "main")
        assert analysis.decision is Decision.BLOCKED, code
        assert code in {r.code for r in analysis.reasons}
        assert git(consumer.path, "status", "--porcelain") == ""


def test_malformed_or_missing_validation_configuration_blocks_an_update(
    source: Source, make_consumer: MakeConsumer
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"})
    unconfigured = make_consumer(base, configured=False, name="unconfigured")
    analysis = update(unconfigured.path, source.path, "main")
    assert "validation_not_configured" in {r.code for r in analysis.reasons}
    assert analysis.decision is Decision.BLOCKED and unconfigured.pinned() == base
    # `check` still analyzes: inspecting needs no validation.
    assert analyze(unconfigured.path, source.path, "main").decision is Decision.SAFE

    malformed = make_consumer(base, name="malformed")
    with malformed.pyproject.open("a", encoding="utf-8") as handle:
        handle.write("unknown_key = 1\n")
    git(malformed.path, "commit", "-q", "-am", "bad config")
    analysis = update(malformed.path, source.path, "main")
    assert analysis.decision is Decision.BLOCKED
    assert "config_malformed" in {r.code for r in analysis.reasons}
    _untouched(malformed, base, commits=2)


def test_a_missing_repository_is_blocked(tmp_path: Path, source: Source) -> None:
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    analysis = update(plain, source.path, "main")
    assert analysis.decision is Decision.BLOCKED
    assert "consumer_not_repository" in {r.code for r in analysis.reasons}
    assert analysis.exit_code is ExitCode.BLOCKED


# --- the transaction -------------------------------------------------------------------


def test_failed_validation_restores_the_original_pin_byte_for_byte(
    source: Source, make_consumer: MakeConsumer, capsys: pytest.CaptureFixture[str]
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"})
    consumer = make_consumer(base, [PASS, FAIL, PASS])
    before = consumer.pyproject.read_bytes()
    code, report = _run(
        capsys,
        "update",
        "--source",
        str(source.path),
        "--candidate",
        "main",
        "--consumer",
        str(consumer.path),
    )
    assert code == ExitCode.VALIDATION_FAILED
    assert report["outcome"] == "rolled_back" and report["rollback"] == {
        "attempted": True,
        "verified": True,
    }
    assert [c["status"] for c in report["checks"]] == ["passed", "failed", "not_run"]
    assert consumer.pyproject.read_bytes() == before
    _untouched(consumer, base)


def test_validation_that_edits_tracked_files_is_a_failure(
    source: Source, make_consumer: MakeConsumer
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"})
    tamper = [sys.executable, "-c", "open('app.py', 'a').write('# tampered\\n')"]
    consumer = make_consumer(base, [tamper])
    analysis = update(consumer.path, source.path, "main")
    assert analysis.outcome is Outcome.ROLLED_BACK and consumer.pinned() == base
    assert "validation changed tracked files" in " ".join(r.detail for r in analysis.reasons)


def test_a_failed_rollback_is_reported_as_such(
    source: Source, make_consumer: MakeConsumer, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"})
    consumer = make_consumer(base, [FAIL])
    monkeypatch.setattr(engine, "restore", lambda path, original: False)
    analysis = update(consumer.path, source.path, "main")
    assert analysis.outcome is Outcome.ROLLBACK_FAILED
    assert analysis.exit_code is ExitCode.ROLLBACK_FAILED
    assert analysis.rollback_attempted and analysis.rollback_verified is False


@pytest.mark.parametrize("change", ["candidate_moved", "pin_edited", "consumer_committed"])
def test_state_that_changes_after_analysis_aborts_the_update(
    source: Source, make_consumer: MakeConsumer, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"})
    consumer = make_consumer(base)
    real_analyze = engine.analyze

    def analyze_then_change(*args, **kwargs):  # type: ignore[no-untyped-def]
        analysis = real_analyze(*args, **kwargs)
        if change == "candidate_moved":
            source.commit({"README.md": "v3\n"})
        elif change == "pin_edited":
            consumer.pyproject.write_text(
                consumer.pyproject.read_text("utf-8") + "# edited\n", encoding="utf-8"
            )
        else:
            (consumer.path / "other.py").write_text("x = 1\n", encoding="utf-8")
            git(consumer.path, "add", "-A")
            git(consumer.path, "commit", "-q", "-m", "concurrent")
        return analysis

    monkeypatch.setattr(engine, "analyze", analyze_then_change)
    analysis = update(consumer.path, source.path, "main")
    assert analysis.decision is Decision.BLOCKED and analysis.outcome is Outcome.NOT_APPLIED
    assert "stale_state" in {r.code for r in analysis.reasons}
    assert consumer.pinned() == base


# --- output hygiene --------------------------------------------------------------------


def test_output_never_carries_credentials_environment_or_command_output(
    source: Source,
    make_consumer: MakeConsumer,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"})
    leak = [sys.executable, "-c", "import os; print(os.environ['UPDATE_TEST_SECRET'])"]
    consumer = make_consumer(base, [leak])
    text = consumer.pyproject.read_text("utf-8").replace(
        "https://github.com",
        "https://deploy:tok3n-value@github.com",  # pragma: allowlist secret
    )
    consumer.pyproject.write_text(text, encoding="utf-8")
    git(consumer.path, "commit", "-q", "-am", "credentialed url")
    monkeypatch.setenv("UPDATE_TEST_SECRET", "env-s3cret-value")
    for output_format in ("json", "text"):
        main(
            [
                "update",
                "--source",
                str(source.path),
                "--candidate",
                "main",
                "--consumer",
                str(consumer.path),
                "--format",
                output_format,
            ]
        )
        out = capsys.readouterr()
        assert "tok3n-value" not in out.out + out.err
        assert "env-s3cret-value" not in out.out + out.err
        git(consumer.path, "checkout", "-q", "--", "pyproject.toml")


def test_the_json_report_is_a_stable_contract(
    source: Source, make_consumer: MakeConsumer, capsys: pytest.CaptureFixture[str]
) -> None:
    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"saas_os/core/rbac/x.py": "y\n"})
    consumer = make_consumer(base)
    code, report = _run(
        capsys,
        "check",
        "--source",
        str(source.path),
        "--candidate",
        "main",
        "--consumer",
        str(consumer.path),
    )
    assert code == report["exit_code"] == ExitCode.REVIEW_REQUIRED
    assert report["consumer"] == {
        "current_sha": base,
        "pin_file": "pyproject.toml",
        "pin_line": 6,
        "pin_url": "https://github.com/example/saas-os",
    }
    assert report["changes"]["review_categories"] == ["authorization"]
    assert report["reasons"] == [
        {
            "code": "category:authorization",
            "decision": "review_required",
            "detail": "1 changed path(s) classified authorization require human review",
        }
    ]
    assert report["policy"]["version"] == "3" and len(report["policy"]["digest"]) == 64


def test_text_output_survives_a_console_that_cannot_encode_the_subject(
    source: Source,
    make_consumer: MakeConsumer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io

    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"}, "ship \U0001f680 rocket")
    consumer = make_consumer(base)
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    code = main(
        [
            "check",
            "--source",
            str(source.path),
            "--candidate",
            "main",
            "--consumer",
            str(consumer.path),
        ]
    )
    stream.flush()
    assert code == ExitCode.SUCCESS
    assert b"ship ? rocket" in stream.buffer.getvalue()  # type: ignore[attr-defined]


def test_a_pin_that_changes_while_writing_is_reported_as_stale(
    source: Source, make_consumer: MakeConsumer, monkeypatch: pytest.MonkeyPatch
) -> None:
    from saas_os.infra.update.pins import PinError

    base = git(source.path, "rev-parse", "HEAD")
    source.commit({"README.md": "v2\n"})
    consumer = make_consumer(base)

    def stale(*args: object) -> bytes:
        raise PinError("stale_state", "pyproject.toml changed since it was analyzed")

    monkeypatch.setattr(engine, "write_pin", stale)
    analysis = update(consumer.path, source.path, "main")
    assert analysis.decision is Decision.BLOCKED and analysis.outcome is Outcome.NOT_APPLIED
    assert "stale_state" in {r.code for r in analysis.reasons}
    assert not analysis.rollback_attempted
    _untouched(consumer, base)


def test_a_candidate_cannot_approve_its_own_weaker_policy(
    source: Source, make_consumer: MakeConsumer
) -> None:
    """A candidate that rewrites the updater policy to make everything
    automatic is judged by the INSTALLED policy: review required, and the
    report records the installed policy's version and digest."""
    from saas_os.infra.update import policy

    base = git(source.path, "rev-parse", "HEAD")
    source.commit(
        {
            "saas_os/infra/update/policy.py": (
                'POLICY_VERSION = "99"\nAUTOMATIC_CATEGORIES = "everything"\n'
            ),
            "saas_os/core/webhooks/service.py": "SIGNING = None\n",
        }
    )
    consumer = make_consumer(base)
    analysis = update(consumer.path, source.path, "main")
    codes = {reason.code for reason in analysis.reasons}
    assert analysis.decision is Decision.REVIEW_REQUIRED
    assert {"category:updater_policy", "category:security_control"} <= codes
    report = analysis.to_dict()
    assert report["policy"] == {"version": "3", "digest": policy.policy_digest()}
    _untouched(consumer, base)
