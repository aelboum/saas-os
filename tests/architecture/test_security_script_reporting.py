"""`scripts/check-security.sh` runs all three checks and fails if any fails.

Before: the script stopped at the first failing command, so a failing
frontend audit meant the secret scan never ran and its result was unknown.
Now the two dependency audits record their failure and the script goes on
to the secret scan, which still aborts the script at once
(`tests/architecture/test_secrets_gate.py`).

The real script is run here, unmodified, in a temporary directory with
`pip-audit`, the frontend audit gate, `detect-secrets-hook` and `git`
replaced by stubs whose exit codes the test chooses -- so the eight
pass/fail combinations are exercised without a network, and without the
repository's own baseline being read or written. The gate's own logic is
covered by `tests/architecture/test_npm_audit_gate.py`.
"""

from __future__ import annotations

import itertools
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-security.sh"
_CHECKS: tuple[str, ...] = ("pip-audit", "npm audit", "detect-secrets-hook")
_AUDITS: tuple[str, ...] = ("pip-audit", "npm audit")

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")


_BASELINE = '{"version": "1.5.0", "results": {}}\n'


def _run(
    tmp_path: Path,
    exit_codes: dict[str, int],
    *,
    tracked_files: int = 1,
    hook_rewrites_baseline: bool = False,
) -> subprocess.CompletedProcess[str]:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "frontend").mkdir()
    (repo / ".secrets.baseline").write_text(_BASELINE, encoding="utf-8", newline="\n")
    shutil.copyfile(SCRIPT, repo / "scripts" / "check-security.sh")
    (repo / "scripts" / "npm_audit_gate.py").write_text(
        f'import sys\nprint("ran npm audit")\nsys.exit({exit_codes["npm audit"]})\n',
        encoding="utf-8",
    )
    stubs = tmp_path / "bin"
    stubs.mkdir()

    def stub(name: str, body: str) -> None:
        path = stubs / name
        path.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8", newline="\n")
        path.chmod(0o755)

    stub("pip-audit", f'echo "ran pip-audit"\nexit {exit_codes["pip-audit"]}')
    # Reports how many file names each invocation received, and whether it
    # ran in UTF-8 mode.
    # Like the real hook, it may rewrite the baseline it is given ($2).
    rewrite = 'echo rewritten > "$2"\n' if hook_rewrites_baseline else ""
    stub(
        "detect-secrets-hook",
        'echo "ran detect-secrets-hook with $(( $# - 2 )) files"\n'
        'echo "PYTHONUTF8=${PYTHONUTF8-unset}"\n'
        f"{rewrite}"
        f"exit {exit_codes['detect-secrets-hook']}",
    )
    # `git ls-files -z`: NUL-separated names, one of them with a space in it.
    names = ["dir with space/file one.py"] + [
        f"pkg/some/deeply/nested/module_{i:05d}.py" for i in range(tracked_files - 1)
    ]
    (tmp_path / "tracked.bin").write_bytes(b"".join(n.encode() + b"\0" for n in names))
    stub("git", f'cat "{(tmp_path / "tracked.bin").as_posix()}"')
    env = dict(os.environ)
    env.pop("PYTHONUTF8", None)  # the script must set it itself
    env["PATH"] = f"{stubs}{os.pathsep}{env['PATH']}"
    return subprocess.run(
        ["bash", str(repo / "scripts" / "check-security.sh")],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )


@pytest.mark.parametrize("codes", list(itertools.product((0, 1), repeat=3)))
def test_every_check_runs_and_any_failure_fails_the_script(
    tmp_path: Path, codes: tuple[int, int, int]
) -> None:
    exit_codes = dict(zip(_CHECKS, codes, strict=True))
    result = _run(tmp_path, exit_codes)
    output = result.stdout + result.stderr

    for check in _CHECKS:  # nothing is skipped because an earlier check failed
        assert f"ran {check}" in output, output

    if any(codes):
        assert result.returncode != 0, output
        assert "All security checks passed." not in output
    else:
        assert result.returncode == 0, output
        assert "All security checks passed." in output

    for audit in _AUDITS:  # each failed audit is named, the others are not
        assert (f"FAIL: {audit}" in output) == bool(exit_codes[audit]), output


def test_the_secret_scan_receives_every_tracked_file_however_many_there_are(
    tmp_path: Path,
) -> None:
    """4,000 names, about 170,000 characters -- five times what one Windows
    command line holds. The scan must still see each of them exactly once,
    in as many invocations as the platform needs."""
    result = _run(tmp_path, dict.fromkeys(_CHECKS, 0), tracked_files=4000)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-2000:]
    assert "Argument list too long" not in output
    counts = [
        int(line.split(" with ")[1].split(" ")[0])
        for line in output.splitlines()
        if line.startswith("ran detect-secrets-hook with ")
    ]
    assert sum(counts) == 4000, counts


def test_the_secret_scan_runs_in_utf8_mode(tmp_path: Path) -> None:
    """Outside UTF-8 mode, detect-secrets on Windows reads files as cp1252
    and skips any it cannot decode, without a finding or a failure
    (`tests/architecture/test_secrets_gate.py`). Every invocation must run
    with `PYTHONUTF8=1`, even when the caller's environment does not set it."""
    result = _run(tmp_path, dict.fromkeys(_CHECKS, 0), tracked_files=4000)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output[-2000:]
    modes = [line for line in output.splitlines() if line.startswith("PYTHONUTF8=")]
    assert modes, output[-2000:]
    assert set(modes) == {"PYTHONUTF8=1"}, modes


def test_a_failing_scan_of_a_long_file_list_still_fails_the_script(tmp_path: Path) -> None:
    exit_codes = dict.fromkeys(_CHECKS, 0) | {"detect-secrets-hook": 1}
    result = _run(tmp_path, exit_codes, tracked_files=4000)
    assert result.returncode != 0
    assert "All security checks passed." not in result.stdout


@pytest.mark.parametrize("hook_exit", [0, 1])
def test_the_scan_never_modifies_the_committed_baseline(tmp_path: Path, hook_exit: int) -> None:
    """`detect-secrets-hook` rewrites the baseline it is given when its
    findings do not match; the script hands it a copy, so running the check
    never edits `.secrets.baseline` (deferred-issue ledger, "detect-secrets-hook
    rewrites the baseline it is given"). A failing scan still fails."""
    exit_codes = dict.fromkeys(_CHECKS, 0) | {"detect-secrets-hook": hook_exit}
    result = _run(tmp_path, exit_codes, hook_rewrites_baseline=True)
    baseline = (tmp_path / "repo" / ".secrets.baseline").read_text(encoding="utf-8")
    assert baseline == _BASELINE
    assert (result.returncode != 0) == bool(hook_exit), result.stdout + result.stderr


def test_the_script_adds_no_blanket_exemption() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "scripts/npm_audit_gate.py" in source
    for weakening in ("--omit=dev", "--audit-level=critical", "--ignore-vuln", "|| true"):
        assert weakening not in source, weakening
