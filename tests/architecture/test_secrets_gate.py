"""P2.5 -- regression tests for the repository's detect-secrets CI
security gate (`scripts/check-security.sh`, `.github/workflows/ci.yml`'s
`security` job).

The previous production-readiness audit found `detect-secrets vs
baseline: FAIL` -- `.secrets.baseline` had drifted stale relative to the
tracked file set (many files added/modified since it was last
regenerated carried the same, already-reviewed synthetic test-fixture
patterns the baseline already accepted for older files, but were never
re-added). P2.5 regenerated the baseline (every new entry individually
reviewed -- see the P2.5 audit report -- and explicitly marked
`"is_secret": false`), and this file proves the *gate itself* -- not
just today's baseline content -- behaves correctly:

    Test 1: a clean run of the real gate against the real, current
            repository succeeds.
    Test 2: a genuinely new, unbaselined secret-shaped string is
            rejected (non-zero exit) -- proves the gate is fail-closed
            for real findings.
    Test 3: an already-reviewed, baselined false positive is accepted.
    Test 4: weakening the baseline (removing a reviewed entry) makes a
            previously-accepted file fail again -- proves baseline
            tampering that *removes* protection is caught by the gate
            regenerating a real finding, not silently accepted.
    Test 5: the actual CI wrapper (`scripts/check-security.sh`)
            propagates a failing `detect-secrets` exit code rather than
            masking it -- this is the specific defect class the prior
            audit flagged (a pipeline/exit-code integrity problem that
            could hide a failing scan).
    Test 6: failure output never echoes the actual secret value -- only
            a type/location/hash, matching `detect-secrets`'s own design
            and this repository's "never leak a value into a log or
            error message" convention.

Every test uses only synthetic, never-real values, and every synthetic
secret lives in a `tmp_path` fixture or an out-of-tree scratch file --
never inside this repository's own git-tracked file set (no test here
runs `git add`/`git commit`/mutates the real working tree's tracked
files).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = REPO_ROOT / ".secrets.baseline"
CHECK_SECURITY_SCRIPT = REPO_ROOT / "scripts" / "check-security.sh"

# A real-looking, but entirely synthetic, AWS-shaped secret -- detect-secrets'
# own `AWSKeyDetector`/`KeywordDetector` reliably flag this pattern, and it is
# not, and has never been, a real credential.
# pragma: allowlist nextline secret
_SYNTHETIC_SECRET_LINE = 'AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLEQWERTYUIOPASDFGHJKLZ"\n'


def _run_hook(baseline: Path, *files: str | Path) -> subprocess.CompletedProcess[str]:
    """Invokes the exact `detect-secrets-hook` entrypoint
    `scripts/check-security.sh` uses, via `python -m` (portable across
    platforms/venvs -- avoids relying on a `detect-secrets-hook` console
    script being on PATH, which is what actually varies between a local
    shell and a fresh CI runner). Runs with `cwd=REPO_ROOT` and accepts
    relative-path strings for `files`, exactly matching
    `scripts/check-security.sh`'s own `$(git ls-files)` invocation (a
    relative baseline arg, relative file args) -- both because that is
    what the real gate actually does, and because passing hundreds of
    *absolute* paths on Windows can exceed `CreateProcess`'s command-line
    length limit (`tmp_path`-rooted absolute paths are still fine; those
    are few and short)."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "detect_secrets.pre_commit_hook",
            "--baseline",
            str(baseline),
            *[str(f) for f in files],
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_clean_repository_gate_succeeds() -> None:
    """Test 1: the real gate, against the real, current, tracked file
    set and the real (P2.5-regenerated) baseline, exits 0. This is the
    exact command `scripts/check-security.sh` runs."""
    tracked_files = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    result = _run_hook(Path(".secrets.baseline"), *tracked_files)
    assert result.returncode == 0, result.stdout + result.stderr


def test_synthetic_secret_is_rejected(tmp_path: Path) -> None:
    """Test 2: a genuinely new, never-baselined secret-shaped string
    fails the gate. The file lives entirely outside this repository's
    working tree (`tmp_path`) -- never staged, never committed."""
    bad_file = tmp_path / "definitely_not_tracked.py"
    bad_file.write_text(_SYNTHETIC_SECRET_LINE)

    result = _run_hook(BASELINE_PATH, bad_file)
    assert result.returncode != 0
    assert "Potential secrets" in result.stdout


def test_approved_false_positive_remains_accepted() -> None:
    """Test 3: a file already reviewed and baselined in P2.5 (a
    synthetic test-fixture signing secret, `_test_signing_secret`
    -- see `tests/core/webhooks/test_replay_protection_unit.py`)
    continues to pass when scanned individually against the real
    baseline. Uses a *relative* path -- the baseline stores relative
    keys, and `detect-secrets` matches on the exact filename string
    (separator-normalized, but never absolute-vs-relative-normalized)."""
    relative = "tests/core/webhooks/test_replay_protection_unit.py"
    assert (REPO_ROOT / relative).is_file()
    result = _run_hook(Path(".secrets.baseline"), relative)
    assert result.returncode == 0, result.stdout + result.stderr


def test_removing_a_baseline_entry_makes_the_finding_reappear(tmp_path: Path) -> None:
    """Test 4: baseline tampering that *weakens* protection (removing a
    reviewed entry, e.g. reverting someone's legitimate audit, or an
    attacker trying to make a previously-suppressed finding disappear
    from view by deleting its baseline record) is caught -- the gate
    fails closed: the finding simply reappears and blocks CI again,
    exactly as if it had never been reviewed. This is the property that
    matters (removing baseline coverage never silently stays green);
    detect-secrets itself has no separate signature/integrity mechanism
    over the baseline file's *contents* -- see the P2.5 audit report for
    why that is an accepted limitation, not an oversight."""
    relative = "tests/core/webhooks/test_replay_protection_unit.py"
    baseline_data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    # The baseline file itself was generated on Windows and stores this
    # key with `\\` separators (its raw on-disk JSON text is the same on
    # every platform -- only *loading* it through `detect-secrets`
    # normalizes separators to the running OS, which is irrelevant to
    # this raw-JSON edit).
    key = "tests\\core\\webhooks\\test_replay_protection_unit.py"
    assert key in baseline_data["results"], "expected baseline entry not present to tamper with"

    tampered = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    del tampered["results"][key]
    tampered_path = tmp_path / "tampered.secrets.baseline"
    tampered_path.write_text(json.dumps(tampered, indent=2), encoding="utf-8")

    result = _run_hook(tampered_path, relative)
    assert result.returncode != 0, (
        "removing a reviewed baseline entry must make the gate fail again for that file"
    )


def test_check_security_script_propagates_a_failing_detect_secrets_exit_code(
    tmp_path: Path,
) -> None:
    """Test 5: protects against the historical defect the prior audit
    flagged ("a pipeline/exit-code integrity problem where a failing
    security scan could effectively be hidden"). Reproduces
    `scripts/check-security.sh`'s exact shell contract -- `set -euo
    pipefail` followed by a single, unpiped `detect-secrets-hook`
    invocation as the final command -- against a synthetic secret, and
    proves the wrapper's own exit code is non-zero and that execution
    stops at the failing line (a command after it never runs). This is
    a faithful reproduction of the wrapper's shell semantics rather than
    an in-place edit of the real, git-tracked file set (which would
    require staging a real secret-shaped file into this repository's own
    index) -- `test_check_security_script_has_no_exit_code_masking`
    below separately asserts, statically, that the real script actually
    has this exact shape."""
    bad_file = tmp_path / "definitely_not_tracked.py"
    bad_file.write_text(_SYNTHETIC_SECRET_LINE)
    marker = tmp_path / "reached_after_failure.marker"

    wrapper = tmp_path / "wrapper.sh"
    wrapper.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'cd "{REPO_ROOT.as_posix()}"\n'
        f'"{Path(sys.executable).as_posix()}" -m detect_secrets.pre_commit_hook '
        f'--baseline "{BASELINE_PATH.as_posix()}" "{bad_file.as_posix()}"\n'
        f'touch "{marker.as_posix()}"\n'
    )

    result = subprocess.run(["bash", str(wrapper)], capture_output=True, text=True, timeout=60)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not marker.exists(), (
        "set -e must stop the wrapper at the failing detect-secrets-hook line -- "
        "a later command must never run"
    )


def test_check_security_script_has_no_exit_code_masking() -> None:
    """Static companion to Test 5: the real
    `scripts/check-security.sh` must never reintroduce the historical
    masking defect -- no `|| true`, no `continue-on-error` (a GitHub
    Actions construct that would belong in `ci.yml`, not this script,
    but checked here too for defense in depth), and the script must have
    `set -e` (or `-o errexit`) active so a failing command aborts it."""
    source = CHECK_SECURITY_SCRIPT.read_text(encoding="utf-8")
    assert "|| true" not in source
    assert "continue-on-error" not in source
    assert "set -e" in source or "set -o errexit" in source or "-euo" in source or "-eu" in source
    # The detect-secrets invocation itself must be the last thing on its
    # line -- never piped into another command that could swallow its exit
    # status (e.g. `detect-secrets-hook ... | tee log.txt`).
    detect_secrets_lines = [
        line
        for line in source.splitlines()
        if "detect-secrets-hook" in line and not line.strip().startswith("#")
    ]
    assert detect_secrets_lines, "expected to find the detect-secrets-hook invocation"
    for line in detect_secrets_lines:
        assert "|" not in line, f"detect-secrets-hook invocation must not be piped: {line!r}"


def test_ci_workflow_has_no_security_bypass() -> None:
    """The GitHub Actions workflow itself must never mask the security
    job's result: no `continue-on-error: true` on the security job/step,
    no `|| true` in any of its `run:` blocks."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "continue-on-error" not in workflow
    assert "|| true" not in workflow


def test_failure_output_never_leaks_the_actual_secret_value(tmp_path: Path) -> None:
    """Test 6: the synthetic secret's own literal value never appears in
    the gate's stdout/stderr -- only `detect-secrets`'s own
    type/location/hash summary. Proves this repository's "never echo a
    credential value" convention holds for tooling output too, not just
    application log lines."""
    bad_file = tmp_path / "definitely_not_tracked.py"
    bad_file.write_text(_SYNTHETIC_SECRET_LINE)

    result = _run_hook(BASELINE_PATH, bad_file)
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    # pragma: allowlist nextline secret
    assert "AKIAIOSFODNN7EXAMPLEQWERTYUIOPASDFGHJKLZ" not in combined


def test_pinned_detect_secrets_version_matches_the_baseline_format_version() -> None:
    """Requirement F (deterministic local/CI result): `pyproject.toml`
    pins an exact `detect-secrets` version (P2.5 -- previously an
    unbounded `>=1.5`, which could silently change plugin/heuristic
    behavior on a future release and make the same repository content
    scan differently between two otherwise-identical environments). The
    installed version must match `.secrets.baseline`'s own recorded
    `"version"` field -- if they drift, the baseline was generated by a
    different `detect-secrets` release than what CI/local runs actually
    use, and coverage is no longer guaranteed identical."""
    from detect_secrets.__version__ import VERSION

    baseline_data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    assert VERSION == baseline_data["version"]

    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "detect-secrets==" in pyproject, (
        "detect-secrets must be pinned to an exact version for deterministic CI "
        "(pyproject.toml's own dependency-comment convention)"
    )


def test_baseline_is_fully_reviewed_with_no_real_secret_marked() -> None:
    """Every entry in the committed baseline must carry an explicit
    `is_secret` audit decision (never silently unaudited), and none may
    be `true` -- a confirmed real secret must never be committed to the
    baseline at all (it must be removed from the source file instead)."""
    baseline_data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    for filename, entries in baseline_data["results"].items():
        for entry in entries:
            assert "is_secret" in entry, f"unaudited baseline entry in {filename}: {entry}"
            assert entry["is_secret"] is False, (
                f"a baseline entry is marked is_secret=true: {entry}"
            )


@pytest.mark.skipif(not BASELINE_PATH.is_file(), reason="`.secrets.baseline` not present")
def test_baseline_is_valid_json_with_the_expected_top_level_shape() -> None:
    baseline_data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    assert "version" in baseline_data
    assert "plugins_used" in baseline_data
    assert "results" in baseline_data
    assert isinstance(baseline_data["results"], dict)
