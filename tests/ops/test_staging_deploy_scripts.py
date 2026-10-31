"""`scripts/deploy-staging.sh` and `deploy/staging-remote.sh` (docs/STAGING.md).

No host is contacted and nothing is deployed. The local script runs in a
throwaway Git repository with `ssh` replaced by a stub that records its
arguments and the script it was sent. The host script runs in a temporary
directory with `docker`, `git`, `systemctl` and `stat` replaced by stubs
that log every call, so the order of the steps and every refusal are
checked without Docker, a database or a network.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LOCAL = REPO_ROOT / "scripts" / "deploy-staging.sh"
REMOTE = REPO_ROOT / "deploy" / "staging-remote.sh"
SHA_A = "a" * 40
SHA_B = "b" * 40

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")


def _stub(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def _bash(script: Path, args: list[str], *, cwd: Path, env: dict[str, str], stdin: str = ""):
    return subprocess.run(
        ["bash", script.as_posix(), *args],
        cwd=cwd,
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


# --------------------------------------------------------------------------
# The local script


@pytest.fixture
def local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    empty = tmp_path / "gitconfig"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "deploy").mkdir()
    shutil.copy(LOCAL, repo / "scripts" / "deploy-staging.sh")
    shutil.copy(REMOTE, repo / "deploy" / "staging-remote.sh")

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()

    git("init", "-q", "-b", "main")
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "one")
    commit = git("rev-parse", "HEAD")
    git("update-ref", "refs/remotes/origin/main", commit)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "ssh.log"
    sent = tmp_path / "ssh.stdin"
    _stub(bin_dir, "ssh", f'printf "%s\\n" "$*" >> "{log.as_posix()}"\ncat > "{sent.as_posix()}"\n')
    env = {**os.environ, "PATH": f"{bin_dir.as_posix()}{os.pathsep}{os.environ['PATH']}"}
    return {"repo": repo, "commit": commit, "env": env, "log": log, "sent": sent}


def _local(local: dict[str, object], *args: str):
    repo = local["repo"]
    assert isinstance(repo, Path)
    env = local["env"]
    assert isinstance(env, dict)
    return _bash(repo / "scripts" / "deploy-staging.sh", list(args), cwd=repo, env=env)


def test_plan_contacts_nothing_and_names_every_step(local: dict[str, object]) -> None:
    commit = str(local["commit"])
    result = _local(
        local, "plan", "--host", "staging.example", "--dir", "/srv/s", "--commit", commit
    )
    assert result.returncode == 0, result.stderr
    assert "nothing was contacted or changed" in result.stdout
    assert "carries no release tag" in result.stdout
    assert "saas-os-backup.service" in result.stdout
    assert not Path(str(local["log"])).exists()


@pytest.mark.parametrize("command", ["deploy", "rollback", "verify"])
def test_a_host_command_needs_the_host_confirmed(local: dict[str, object], command: str) -> None:
    commit = str(local["commit"])
    base = [command, "--host", "staging.example", "--dir", "/srv/s", "--commit", commit]
    missing = _local(local, *base)
    assert missing.returncode == 2 and "--confirm-host staging.example" in missing.stderr
    other = _local(local, *base, "--confirm-host", "prod.example")
    assert other.returncode == 2 and "does not match" in other.stderr
    assert not Path(str(local["log"])).exists()


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--host", "h", "--dir", "/srv/s", "--commit", "abc123"], "full 40-character SHA"),
        (["--host", "h", "--dir", "/srv/s", "--commit", SHA_A], "not in this clone"),
        (["--host", "h", "--dir", "srv/s", "--commit", SHA_A], "absolute path"),
        (["--host", "h", "--dir", "/srv/s;rm", "--commit", SHA_A], "characters other than"),
        (["--host", "-oProxyCommand=x", "--dir", "/srv/s", "--commit", SHA_A], "plain"),
        (["--dir", "/srv/s", "--commit", SHA_A], "--host is required"),
    ],
)
def test_bad_arguments_are_refused_before_anything_runs(
    local: dict[str, object], args: list[str], message: str
) -> None:
    result = _local(local, "plan", *args)
    assert result.returncode == 2 and message in result.stderr
    assert not Path(str(local["log"])).exists()


def test_deploy_sends_the_host_script_over_batch_mode_ssh(local: dict[str, object]) -> None:
    commit = str(local["commit"])
    result = _local(
        local,
        "deploy",
        "--host",
        "staging.example",
        "--dir",
        "/srv/s",
        "--commit",
        commit,
        "--confirm-host",
        "staging.example",
        "--first-deploy",
    )
    assert result.returncode == 0, result.stderr
    log = Path(str(local["log"])).read_text(encoding="utf-8").strip()
    assert log == f"-o BatchMode=yes -- staging.example bash -s -- deploy /srv/s {commit} first"
    assert Path(str(local["sent"])).read_text(encoding="utf-8") == REMOTE.read_text(
        encoding="utf-8"
    )


# --------------------------------------------------------------------------
# The host script


@pytest.fixture
def host(tmp_path: Path) -> dict[str, object]:
    site = tmp_path / "site"
    site.mkdir()
    (site / "STAGING").write_text("", encoding="utf-8")
    for name in (".env", ".env.app"):
        (site / name).write_text("NOT_READ=1\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.log"
    head = tmp_path / "head"
    head.write_text(SHA_A + "\n", encoding="utf-8")
    log = f'printf "%s %s\\n" "$(basename "$0")" "$*" >> "{calls.as_posix()}"\n'
    _stub(bin_dir, "docker", log)
    _stub(bin_dir, "systemctl", log)
    _stub(bin_dir, "stat", log + 'echo "${STUB_MODE:-600}"\n')
    _stub(
        bin_dir,
        "git",
        log
        + 'case "$1 $2" in\n'
        + f'  "rev-list --first-parent") printf "%s\\n" ${{STUB_MAIN:-{SHA_A} {SHA_B}}} ;;\n'
        + f'  "-c advice.detachedHead=false") echo "$6" > "{head.as_posix()}" ;;\n'
        + f'  "rev-parse HEAD") cat "{head.as_posix()}" ;;\n'
        + "esac\n",
    )
    env = {**os.environ, "PATH": f"{bin_dir.as_posix()}{os.pathsep}{os.environ['PATH']}"}
    return {"site": site, "calls": calls, "env": env}


def _remote(host: dict[str, object], *args: str, **env: str):
    site = host["site"]
    assert isinstance(site, Path)
    base = host["env"]
    assert isinstance(base, dict)
    return _bash(REMOTE, [args[0], site.as_posix(), *args[1:]], cwd=site, env={**base, **env})


def _calls(host: dict[str, object]) -> list[str]:
    path = Path(str(host["calls"]))
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def _state(host: dict[str, object]) -> str:
    return (Path(str(host["site"])) / ".deploy-state").read_text(encoding="utf-8")


def _index(calls: list[str], fragment: str) -> int:
    return next(i for i, call in enumerate(calls) if fragment in call)


def test_a_first_deployment_runs_every_step_in_order_without_a_backup(
    host: dict[str, object],
) -> None:
    result = _remote(host, "deploy", SHA_A, "first")
    assert result.returncode == 0, result.stderr
    calls = _calls(host)
    order = [
        "git fetch --quiet --tags origin",
        "git rev-list --first-parent origin/main",
        f"checkout --quiet --detach {SHA_A}",
        "docker compose -f docker-compose.prod.yml config --quiet",
        "docker compose -f docker-compose.prod.yml build",
        "run --rm --no-deps --entrypoint saas-os-migrate backend upgrade head",
        "up -d --wait --wait-timeout 300",
    ]
    assert [_index(calls, step) for step in order] == sorted(_index(calls, s) for s in order)
    assert not any(call.startswith("systemctl") for call in calls)
    assert _state(host) == f"current={SHA_A}\nprevious=\n"


def test_a_later_deployment_backs_up_before_it_migrates(host: dict[str, object]) -> None:
    assert _remote(host, "deploy", SHA_A, "first").returncode == 0
    result = _remote(host, "deploy", SHA_B)
    assert result.returncode == 0, result.stderr
    calls = _calls(host)
    backup = _index(calls, "systemctl start --wait saas-os-backup.service")
    migrate = [i for i, c in enumerate(calls) if "saas-os-migrate" in c][-1]
    assert backup < migrate
    assert _state(host) == f"current={SHA_B}\nprevious={SHA_A}\n"


def test_rollback_restarts_the_previous_commit_and_never_touches_the_schema(
    host: dict[str, object],
) -> None:
    assert _remote(host, "deploy", SHA_A, "first").returncode == 0
    assert _remote(host, "deploy", SHA_B).returncode == 0
    before = len(_calls(host))
    result = _remote(host, "rollback")
    assert result.returncode == 0, result.stderr
    calls = _calls(host)[before:]
    assert any(f"checkout --quiet --detach {SHA_A}" in call for call in calls)
    assert any("up -d --wait" in call for call in calls)
    assert not any("saas-os-migrate" in call or "downgrade" in call for call in calls)
    assert _state(host) == f"current={SHA_A}\nprevious={SHA_B}\n"


def test_verify_waits_for_the_healthchecks_of_the_deployed_commit(
    host: dict[str, object],
) -> None:
    assert _remote(host, "deploy", SHA_A, "first").returncode == 0
    result = _remote(host, "verify")
    assert result.returncode == 0, result.stderr
    assert f"deployed {SHA_A}" in result.stdout
    assert any("up -d --wait --wait-timeout 300 --no-recreate" in c for c in _calls(host))


def _refused_before_any_change(host: dict[str, object], result, message: str) -> None:
    assert result.returncode == 1
    assert message in result.stderr
    changing = ("checkout", "build", "saas-os-migrate", "up -d", "systemctl")
    assert not any(word in call for call in _calls(host) for word in changing)


def test_a_host_without_the_staging_marker_is_refused(host: dict[str, object]) -> None:
    (Path(str(host["site"])) / "STAGING").unlink()
    result = _remote(host, "deploy", SHA_A, "first")
    _refused_before_any_change(host, result, "not marked as staging")


@pytest.mark.parametrize("mode", ["644", "640", "660", "755"])
def test_an_env_file_readable_by_others_is_refused(host: dict[str, object], mode: str) -> None:
    result = _remote(host, "deploy", SHA_A, "first", STUB_MODE=mode)
    _refused_before_any_change(host, result, f"has mode {mode}")


def test_a_missing_env_file_is_refused(host: dict[str, object]) -> None:
    (Path(str(host["site"])) / ".env.app").unlink()
    result = _remote(host, "deploy", SHA_A, "first")
    _refused_before_any_change(host, result, ".env.app is missing")


def test_a_commit_that_is_not_on_main_is_refused(host: dict[str, object]) -> None:
    result = _remote(host, "deploy", SHA_A, "first", STUB_MAIN=SHA_B)
    _refused_before_any_change(host, result, "not a first-parent commit of origin/main")


@pytest.mark.parametrize("commit", ["abc", "A" * 40, "g" * 40, ""])
def test_a_commit_that_is_not_a_full_sha_is_refused(host: dict[str, object], commit: str) -> None:
    result = _remote(host, "deploy", commit, "first")
    _refused_before_any_change(host, result, "full 40-character SHA")


def test_first_and_later_deployments_cannot_be_confused(host: dict[str, object]) -> None:
    result = _remote(host, "deploy", SHA_A)
    _refused_before_any_change(host, result, "run the first deployment with --first-deploy")
    assert _remote(host, "deploy", SHA_A, "first").returncode == 0
    again = _remote(host, "deploy", SHA_B, "first")
    assert again.returncode == 1 and "first deployment asked" in again.stderr


def test_rollback_without_a_previous_deployment_is_refused(host: dict[str, object]) -> None:
    assert _remote(host, "deploy", SHA_A, "first").returncode == 0
    before = len(_calls(host))
    result = _remote(host, "rollback")
    assert result.returncode == 1 and "no previous deployment" in result.stderr
    assert not any("checkout" in call for call in _calls(host)[before:])


def test_the_env_files_are_never_read(host: dict[str, object]) -> None:
    """The only code lines that name `.env` loop over the two files for the
    mode check; nothing opens, sources or greps them."""
    assert _remote(host, "deploy", SHA_A, "first").returncode == 0
    code = [
        line.strip()
        for line in REMOTE.read_text(encoding="utf-8").splitlines()
        if ".env" in line and not line.lstrip().startswith("#")
    ]
    assert code == ["for file in .env .env.app; do"]
