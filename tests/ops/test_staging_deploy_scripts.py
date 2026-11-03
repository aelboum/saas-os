"""`scripts/deploy-staging.sh` and `deploy/staging-remote.sh` (docs/STAGING.md).

No host is contacted and nothing is deployed. The local script runs in a
throwaway Git repository with `ssh` replaced by a stub that records its
arguments and the script it was sent. The host script runs in a temporary
directory with `docker`, `git`, `systemctl` and `stat` replaced by stubs
that log every call, so the order of the steps and every refusal are
checked without Docker, a database or a network. The first-parent check of
both scripts also runs with the real `git` on a throwaway history (last
section).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
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


# --------------------------------------------------------------------------
# The first-parent check, with the real `git`
#
# Both scripts used to run `git rev-list --first-parent origin/main | grep -qx
# "$commit"` under `set -o pipefail`. grep -q exits at the first match, git's
# next write then dies of SIGPIPE (status 141), and pipefail turned a found
# commit into "not a first-parent commit". Here main has MAIN_COMMITS + 1
# first-parent commits (410,041 bytes of rev-list output, far more than a
# pipe holds), so on Linux the old check refused a commit near the top every
# time. A Git error must stay an error and never read as "not on main".

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

MAIN_COMMITS = 10_000
RELEASE_TAGS = 20_000
NOT_ON_MAIN = "is not a first-parent commit of origin/main"
CANNOT_LIST = "could not list the first-parent commits of origin/main"
GIT_ERRORS = ["missing", "dangling", "unreadable"]


def _git(cwd: Path, env: dict[str, str], *args: str, stdin: bytes | None = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, env=env, input=stdin, capture_output=True, check=True
    )
    return result.stdout.decode("utf-8").strip()


@dataclass(frozen=True)
class _History:
    upstream: Path
    env: dict[str, str]
    commits: dict[str, str]


@dataclass(frozen=True)
class _Clone:
    site: Path
    env: dict[str, str]
    calls: Path
    commits: dict[str, str]


@pytest.fixture(scope="module")
def history(tmp_path_factory: pytest.TempPathFactory) -> _History:
    """An upstream whose main is MAIN_COMMITS linear commits and then the
    merge of one side-branch commit. First parents: merge, tip, ..., root;
    `side` is reachable from main but is not a first-parent commit."""
    root = tmp_path_factory.mktemp("history")
    config = root / "gitconfig"
    config.write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": str(config),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CEILING_DIRECTORIES": str(tmp_path_factory.getbasetemp()),
    }
    upstream = root / "upstream"
    _git(root, env, "init", "-q", "-b", "main", upstream.as_posix())

    def commit(ref: str, n: int, extra: str = "") -> str:
        when = 1_700_000_000 + n
        return f"commit {ref}\ncommitter t <t@example.invalid> {when} +0000\ndata 0\n{extra}\n"

    stream = "".join(commit("refs/heads/main", n) for n in range(MAIN_COMMITS))
    stream += commit("refs/heads/side", MAIN_COMMITS, "from refs/heads/main\n")
    stream += commit("refs/heads/main", MAIN_COMMITS + 1, "merge refs/heads/side\n")
    _git(upstream, env, "fast-import", "--quiet", stdin=stream.encode("ascii"))
    commits = {
        "merge": _git(upstream, env, "rev-parse", "main"),
        "tip": _git(upstream, env, "rev-parse", "main^1"),
        "root": _git(upstream, env, "rev-list", "--max-parents=0", "main"),
        "side": _git(upstream, env, "rev-parse", "main^2"),
        "absent": "c" * 40,
    }
    first_parents = _git(upstream, env, "rev-list", "--first-parent", "main").split()
    assert len(first_parents) == MAIN_COMMITS + 1
    assert first_parents[:2] == [commits["merge"], commits["tip"]]
    assert first_parents[-1] == commits["root"]
    assert commits["side"] not in first_parents and commits["absent"] not in first_parents
    return _History(upstream=upstream, env=env, commits=commits)


@pytest.fixture
def clone(history: _History, tmp_path: Path) -> _Clone:
    """A staging checkout cloned from the upstream, so `git fetch origin`
    works offline, with the local script copied in and `docker`,
    `systemctl` and `stat` stubbed. `git` is the real one."""
    site = tmp_path / "site"
    _git(tmp_path, history.env, "clone", "-q", history.upstream.as_posix(), site.as_posix())
    (site / "STAGING").write_text("", encoding="utf-8")
    for name in (".env", ".env.app"):
        (site / name).write_text("NOT_READ=1\n", encoding="utf-8")
    (site / "scripts").mkdir()
    shutil.copy(LOCAL, site / "scripts" / "deploy-staging.sh")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.log"
    log = f'printf "%s %s\\n" "$(basename "$0")" "$*" >> "{calls.as_posix()}"\n'
    _stub(bin_dir, "docker", log)
    _stub(bin_dir, "systemctl", log)
    _stub(bin_dir, "stat", log + "echo 600\n")
    env = {**history.env, "PATH": f"{bin_dir.as_posix()}{os.pathsep}{history.env['PATH']}"}
    return _Clone(site=site, env=env, calls=calls, commits=history.commits)


def _host_deploy(clone: _Clone, commit: str, site: Path | None = None):
    target = clone.site if site is None else site
    return _bash(REMOTE, ["deploy", target.as_posix(), commit, "first"], cwd=target, env=clone.env)


def _local_plan(clone: _Clone, commit: str, script: Path | None = None):
    path = clone.site / "scripts" / "deploy-staging.sh" if script is None else script
    args = ["plan", "--host", "staging.example", "--dir", "/srv/s", "--commit", commit]
    return _bash(path, args, cwd=path.parent, env=clone.env)


def _nothing_changed(clone: _Clone) -> None:
    assert _git(clone.site, clone.env, "symbolic-ref", "HEAD") == "refs/heads/main"
    assert not (clone.site / ".deploy-state").exists()
    calls = clone.calls.read_text(encoding="utf-8") if clone.calls.exists() else ""
    assert not any(call.startswith(("docker", "systemctl")) for call in calls.splitlines())


def _break_origin_main(clone: _Clone, how: str) -> str:
    """Make origin/main unusable in the way `how` names, keep `git fetch`
    working (it now fetches `side` only) and return a commit to ask for."""
    site, env = clone.site, clone.env
    _git(site, env, "config", "remote.origin.fetch", "+refs/heads/side:refs/remotes/origin/side")
    if how == "missing":
        _git(site, env, "update-ref", "-d", "refs/remotes/origin/main")
        return clone.commits["merge"]
    if how == "dangling":
        _git(site, env, "symbolic-ref", "refs/remotes/origin/main", "refs/heads/gone")
        return clone.commits["merge"]
    # "unreadable": git prints the requested commit first, then fails on a
    # parent whose object is gone.
    ident = ("-c", "user.name=t", "-c", "user.email=t@example.invalid")
    tree = _git(site, env, "mktree", stdin=b"")
    first = _git(site, env, *ident, "commit-tree", "-m", "1", tree)
    second = _git(site, env, *ident, "commit-tree", "-m", "2", "-p", first, tree)
    third = _git(site, env, *ident, "commit-tree", "-m", "3", "-p", second, tree)
    _git(site, env, "update-ref", "refs/remotes/origin/main", third)
    loose = site / ".git" / "objects" / first[:2] / first[2:]
    loose.chmod(0o644)
    loose.unlink()
    return third


@needs_git
@pytest.mark.parametrize("which", ["merge", "tip", "root"])
def test_the_host_script_finds_every_first_parent_commit_of_a_long_main(
    clone: _Clone, which: str
) -> None:
    """The regression: `merge` and `tip` head a 410 kB first-parent list."""
    commit = clone.commits[which]
    result = _host_deploy(clone, commit)
    assert result.returncode == 0, result.stderr
    assert _git(clone.site, clone.env, "rev-parse", "HEAD") == commit
    state = (clone.site / ".deploy-state").read_text(encoding="utf-8")
    assert state == f"current={commit}\nprevious=\n"


@needs_git
@pytest.mark.parametrize("which", ["merge", "tip", "root"])
def test_the_local_script_finds_every_first_parent_commit_of_a_long_main(
    clone: _Clone, which: str
) -> None:
    commit = clone.commits[which]
    result = _local_plan(clone, commit)
    assert result.returncode == 0, result.stderr
    assert f"plan: deploy {commit} to staging.example:/srv/s" in result.stdout


@needs_git
@pytest.mark.parametrize("which", ["side", "absent"])
def test_the_host_script_refuses_a_commit_that_is_not_a_first_parent_of_main(
    clone: _Clone, which: str
) -> None:
    commit = clone.commits[which]
    result = _host_deploy(clone, commit)
    assert result.returncode == 1
    assert f"staging: refused: {commit} {NOT_ON_MAIN}" in result.stderr
    _nothing_changed(clone)


@needs_git
def test_the_local_script_refuses_a_commit_that_is_not_a_first_parent_of_main(
    clone: _Clone,
) -> None:
    commit = clone.commits["side"]
    result = _local_plan(clone, commit)
    assert result.returncode == 2
    assert f"deploy-staging: {commit} {NOT_ON_MAIN}" in result.stderr


@needs_git
@pytest.mark.parametrize("how", GIT_ERRORS)
def test_the_host_script_reports_a_git_error_and_not_a_commit_off_main(
    clone: _Clone, how: str
) -> None:
    commit = _break_origin_main(clone, how)
    result = _host_deploy(clone, commit)
    assert result.returncode == 1
    assert f"staging: refused: {CANNOT_LIST}" in result.stderr
    assert "fatal:" in result.stderr  # git's own message is kept
    assert NOT_ON_MAIN not in result.stderr
    _nothing_changed(clone)


@needs_git
@pytest.mark.parametrize("how", GIT_ERRORS)
def test_the_local_script_reports_a_git_error_and_not_a_commit_off_main(
    clone: _Clone, how: str
) -> None:
    commit = _break_origin_main(clone, how)
    result = _local_plan(clone, commit)
    assert result.returncode == 2
    assert f"deploy-staging: {CANNOT_LIST}" in result.stderr
    assert "fatal:" in result.stderr
    assert NOT_ON_MAIN not in result.stderr


@needs_git
def test_outside_a_repository_neither_script_blames_main(clone: _Clone, tmp_path: Path) -> None:
    """Not a regression test for the pipe fix: both scripts fail before the
    first-parent check here (the host at `git fetch`, the local script at its
    `rev-parse` check), with the old code as with the new. Kept to pin that
    outside a repository neither says "not a first-parent commit"."""
    plain = tmp_path / "plain"
    (plain / "scripts").mkdir(parents=True)
    for name in ("STAGING", ".env", ".env.app"):
        (plain / name).write_text("", encoding="utf-8")
    shutil.copy(LOCAL, plain / "scripts" / "deploy-staging.sh")
    commit = clone.commits["merge"]
    host = _host_deploy(clone, commit, site=plain)
    local = _local_plan(clone, commit, script=plain / "scripts" / "deploy-staging.sh")
    for result in (host, local):
        assert result.returncode != 0
        assert "not a git repository" in result.stderr
        assert NOT_ON_MAIN not in result.stderr


@needs_git
def test_the_local_script_names_the_first_release_tag_among_thousands(clone: _Clone) -> None:
    """`git tag --points-at ... | head -n 1` under pipefail: head exits after
    the first line, git's next write dies of SIGPIPE (141) and `set -e` ended
    `plan` silently. RELEASE_TAGS tags list 180,000 bytes, more than a pipe
    holds, so on Linux the old line failed every time."""
    commit = clone.commits["merge"]
    refs = "".join(f"create refs/tags/v0.{n:05d} {commit}\n" for n in range(RELEASE_TAGS))
    _git(clone.site, clone.env, "update-ref", "--stdin", stdin=refs.encode("ascii"))
    result = _local_plan(clone, commit)
    assert result.returncode == 0, result.stderr
    assert f"plan: deploy {commit} (v0.00000) to staging.example:/srv/s" in result.stdout
    assert "carries no release tag" not in result.stdout
