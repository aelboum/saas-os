"""`saas-os-update` safety policy, pin parsing and configuration, without
Git (docs/AUTO-UPDATE-CLI.md)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from infra.update.config import ConfigError, load_config
from infra.update.engine import Analysis, Decision, ExitCode, Outcome
from infra.update.git import is_full_sha, is_valid_ref
from infra.update.pins import PinError, find_pin, redact, restore, write_pin
from infra.update.policy import Category, classify

from infra.update import policy

SHA_A = "a" * 40
SHA_B = "b" * 40
# A fake credentialed URL, as a consumer might pin one.
_CREDENTIALED = "https://user:tok@host/o/saas-os"  # pragma: allowlist secret

# --- classification -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "category"),
    [
        ("infra/update/policy.py", Category.UPDATER_POLICY),
        ("infra/db/migrations/versions/abc_add_x.py", Category.MIGRATION),
        ("infra/db/rls.py", Category.TENANT_RLS),
        ("core/tenancy/service.py", Category.TENANT_RLS),
        ("core/billing/stripe_provider.py", Category.PROVIDER_BOUNDARY),
        ("infra/secrets/providers/vault.py", Category.PROVIDER_BOUNDARY),
        ("core/billing/commercial.py", Category.BILLING),
        ("core/billing/__init__.py", Category.BILLING),
        ("core/usage/reporting.py", Category.BILLING),
        ("core/rbac/authorization.py", Category.AUTHORIZATION),
        ("core/authority/caller.py", Category.AUTHORIZATION),
        ("api/auth/session.py", Category.AUTHORIZATION),
        ("docs/ADR/0015-saas-os-distribution-and-consumer-boundary.md", Category.ARCHITECTURE),
        ("pyproject.toml", Category.DEPENDENCY_TOOLCHAIN),
        ("scripts/check-all.sh", Category.DEPENDENCY_TOOLCHAIN),
        ("contracts/events.py", Category.PUBLIC_API),
        ("api/v1/routes.py", Category.PUBLIC_API),
        ("core/notifications/__init__.py", Category.PUBLIC_API),
        ("tests/core/test_x.py", Category.TESTS),
        ("docs/ROADMAP.md", Category.DOCUMENTATION),
        ("README.md", Category.DOCUMENTATION),
        ("core/notifications/service.py", Category.INTERNAL),
        ("infra/jobs/queue.py", Category.INTERNAL),
        ("infra/db/backup/destination.py", Category.INTERNAL),
        ("control-plane/control_plane/__init__.py", Category.PUBLIC_API),
        ("frontend/src/app.tsx", Category.UNKNOWN),
        ("products/demo/x.py", Category.UNKNOWN),
        ("deploy/prod.yml", Category.UNKNOWN),
    ],
)
def test_paths_are_classified_by_the_first_matching_rule(path: str, category: Category) -> None:
    assert classify(path) is category


def test_only_documentation_tests_and_internal_changes_are_automatic() -> None:
    assert policy.AUTOMATIC_CATEGORIES == {
        Category.DOCUMENTATION,
        Category.TESTS,
        Category.INTERNAL,
    }
    for category in Category:
        assert policy.requires_review(category) is (category not in policy.AUTOMATIC_CATEGORIES)
    assert policy.requires_review(Category.UNKNOWN)
    assert policy.requires_review(Category.UPDATER_POLICY)


def test_the_policy_digest_is_stable_and_covers_the_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    digest = policy.policy_digest()
    assert digest == policy.policy_digest() and len(digest) == 64
    monkeypatch.setattr(
        policy, "AUTOMATIC_CATEGORIES", policy.AUTOMATIC_CATEGORIES | {Category.MIGRATION}
    )
    assert policy.policy_digest() != digest


# --- references -----------------------------------------------------------------------


def test_only_forty_lowercase_hex_characters_are_an_exact_sha() -> None:
    assert is_full_sha(SHA_A)
    for value in ("a" * 39, "A" * 40, "g" * 40, "main", "v1.0.0", "", SHA_A + "0"):
        assert not is_full_sha(value)


@pytest.mark.parametrize("ref", ["main", "v1.2.3", "release/2026-10", SHA_A, "abc1234"])
def test_plain_refs_are_accepted_for_discovery(ref: str) -> None:
    assert is_valid_ref(ref)


@pytest.mark.parametrize(
    "ref", ["-x", "--upload-pack=evil", "main..dev", "HEAD@{1}", "a b", "", "main;rm"]
)
def test_option_like_and_range_refs_are_refused(ref: str) -> None:
    assert not is_valid_ref(ref)


# --- pins -----------------------------------------------------------------------------


def _write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return path


@pytest.mark.parametrize(
    ("line", "url"),
    [
        (
            f'  "saas-os @ git+https://github.com/o/saas-os@{SHA_A}",',
            "https://github.com/o/saas-os",
        ),
        (
            f'"saas_os[billing] @ git+ssh://git@github.com/o/saas-os.git@{SHA_A}#egg=saas-os",',
            "ssh://git@github.com/o/saas-os.git",
        ),
        (
            f'"SaaS-OS@git+{_CREDENTIALED}@{SHA_A} ; python_version>=\\"3.13\\""',
            _CREDENTIALED,
        ),
    ],
)
def test_a_pin_is_found_in_its_common_forms(tmp_path: Path, line: str, url: str) -> None:
    _write(tmp_path, "pyproject.toml", f"[project]\ndependencies = [\n{line}\n]\n")
    pin = find_pin(tmp_path)
    assert (pin.ref, pin.url, pin.relative_file, pin.line_number) == (
        SHA_A,
        url,
        "pyproject.toml",
        3,
    )


def test_a_missing_pin_is_refused(tmp_path: Path) -> None:
    _write(tmp_path, "pyproject.toml", '[project]\ndependencies = ["httpx"]\n')
    with pytest.raises(PinError) as excinfo:
        find_pin(tmp_path)
    assert excinfo.value.code == "pin_missing"


def test_pins_in_several_places_are_ambiguous(tmp_path: Path) -> None:
    line = f'"saas-os @ git+https://h/o/saas-os@{SHA_A}"'
    _write(tmp_path, "pyproject.toml", f"[project]\ndependencies = [{line}]\n")
    _write(tmp_path, "requirements.txt", f"saas-os @ git+https://h/o/saas-os@{SHA_A}\n")
    with pytest.raises(PinError) as excinfo:
        find_pin(tmp_path)
    assert excinfo.value.code == "pin_ambiguous"


def test_a_pin_without_a_ref_is_not_an_exact_pin(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "saas-os @ git+ssh://git@github.com/o/saas-os.git\n")
    with pytest.raises(PinError) as excinfo:
        find_pin(tmp_path)
    assert excinfo.value.code == "pin_not_exact_sha"


def test_commented_pins_are_ignored(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "requirements.txt",
        f"# saas-os @ git+https://h/o/saas-os@{SHA_B}\nsaas-os @ git+https://h/o/saas-os@{SHA_A}\n",
    )
    assert find_pin(tmp_path).ref == SHA_A


def test_writing_a_pin_changes_only_its_ref_and_restore_is_byte_exact(tmp_path: Path) -> None:
    text = f'[project]\r\ndependencies = [\r\n  "saas-os @ git+https://h/o/saas-os@{SHA_A}#egg=x",\r\n]\r\n'
    path = _write(tmp_path, "pyproject.toml", text)
    original = write_pin(find_pin(tmp_path), SHA_B)
    assert path.read_bytes() == text.replace(SHA_A, SHA_B).encode("utf-8")
    assert original == text.encode("utf-8")
    assert restore(path, original) and path.read_bytes() == original


def test_writing_a_pin_that_changed_since_analysis_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, "requirements.txt", f"saas-os @ git+https://h/o/saas-os@{SHA_A}\n")
    pin = find_pin(tmp_path)
    path.write_text(f"saas-os @ git+https://h/o/saas-os@{SHA_B}\n", encoding="utf-8")
    with pytest.raises(PinError) as excinfo:
        write_pin(pin, SHA_A)
    assert excinfo.value.code == "stale_state"


def test_credentials_in_urls_are_redacted() -> None:
    fake = "git+https://user:s3cret@host/o/r@x"  # pragma: allowlist secret
    assert redact(fake) == "git+https://***@host/o/r@x"
    assert redact("ssh://git@github.com/o/r") == "ssh://***@github.com/o/r"
    assert "s3cret" not in redact("see https://ghp_s3cret@github.com/o/r for details")


# --- configuration -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "table",
    [
        'validation = "pytest"',
        "validation = [[]]",
        'validation = [["pytest", 1]]',
        'validation = [["pytest"]]\nunknown = 1',
        'validation = [["pytest"]]\ntimeout_seconds = 0',
        'validation = [["pytest"]]\ntimeout_seconds = true',
        'validation = [["pytest"]]\npin_files = ["../outside.txt"]',
        'validation = [["pytest"]]\npin_files = []',
    ],
)
def test_malformed_configuration_is_refused(tmp_path: Path, table: str) -> None:
    _write(tmp_path, "pyproject.toml", f"[tool.saas-os-update]\n{table}\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_invalid_toml_is_malformed_configuration(tmp_path: Path) -> None:
    _write(tmp_path, "pyproject.toml", "[tool.saas-os-update\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_a_valid_configuration_is_read(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pyproject.toml",
        '[tool.saas-os-update]\nvalidation = [["pytest", "-q"]]\ntimeout_seconds = 60\n',
    )
    config = load_config(tmp_path)
    assert config.validation == (("pytest", "-q"),)
    assert config.timeout_seconds == 60 and config.configured


# --- decisions, exit codes and the report ---------------------------------------------------


def test_a_decision_only_ever_becomes_more_cautious() -> None:
    analysis = Analysis(command="check", candidate_ref="main")
    analysis.add(Decision.BLOCKED, "x", "blocked")
    analysis.add(Decision.REVIEW_REQUIRED, "y", "review")
    analysis.add(Decision.SAFE, "z", "safe")
    analysis.add(Decision.UP_TO_DATE, "w", "current")
    assert analysis.decision is Decision.BLOCKED and analysis.exit_code is ExitCode.BLOCKED


@pytest.mark.parametrize(
    ("decision", "outcome", "code"),
    [
        (Decision.SAFE, Outcome.NOT_APPLIED, 0),
        (Decision.SAFE, Outcome.APPLIED, 0),
        (Decision.UP_TO_DATE, Outcome.NOT_APPLIED, 10),
        (Decision.REVIEW_REQUIRED, Outcome.NOT_APPLIED, 20),
        (Decision.BLOCKED, Outcome.NOT_APPLIED, 30),
        (Decision.BLOCKED, Outcome.ROLLED_BACK, 40),
        (Decision.BLOCKED, Outcome.ROLLBACK_FAILED, 50),
    ],
)
def test_the_exit_code_contract(decision: Decision, outcome: Outcome, code: int) -> None:
    analysis = Analysis(command="update", candidate_ref="main")
    analysis.decision, analysis.outcome = decision, outcome
    assert int(analysis.exit_code) == code


def test_the_report_has_a_stable_shape() -> None:
    report = Analysis(command="check", candidate_ref="main").to_dict()
    assert set(report) == {
        "schema_version",
        "command",
        "policy",
        "decision",
        "outcome",
        "exit_code",
        "consumer",
        "candidate",
        "changes",
        "reasons",
        "checks",
        "rollback",
    }
    assert report["schema_version"] == 1
    json.dumps(report)


# --- final closure audit regressions ---------------------------------------------------


def test_a_pin_reached_through_a_symlink_outside_the_consumer_is_ignored(tmp_path: Path) -> None:
    root, outside = tmp_path / "consumer", tmp_path / "outside"
    root.mkdir()
    _write(outside, "requirements.txt", f"saas-os @ git+https://h/o/saas-os@{SHA_A}\n")
    link = root / "requirements"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        # Unprivileged Windows: a directory junction redirects the path the
        # same way and needs no privilege.
        try:
            import _winapi

            _winapi.CreateJunction(str(outside), str(link))
        except (ImportError, OSError):
            pytest.skip("neither symlinks nor junctions are available here")
    assert (link / "requirements.txt").is_file()  # the redirect really works
    with pytest.raises(PinError) as excinfo:
        find_pin(root)
    assert excinfo.value.code == "pin_missing"


def test_drive_qualified_pin_patterns_are_malformed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pyproject.toml",
        '[tool.saas-os-update]\nvalidation = [["pytest"]]\npin_files = ["C:requirements.txt"]\n',
    )
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_an_invalid_candidate_is_reported_redacted() -> None:
    supplied = "https://user:s3cret@host/o/r"  # pragma: allowlist secret
    report = Analysis(command="check", candidate_ref=supplied).to_dict()
    assert "s3cret" not in json.dumps(report)


# --- policy v2: security controls and autonomous orchestration (closure audit M1) -----


@pytest.mark.parametrize(
    ("path", "category"),
    [
        ("infra/db/init/01-create-app-role.sh", Category.SECURITY_CONTROL),
        ("core/webhooks/service.py", Category.SECURITY_CONTROL),
        ("core/webhooks/__init__.py", Category.SECURITY_CONTROL),
        ("infra/db/backup/encryption.py", Category.SECURITY_CONTROL),
        ("core/idempotency/service.py", Category.SECURITY_CONTROL),
        ("core/outbox/dispatch.py", Category.SECURITY_CONTROL),
        ("core/outbox/consumption.py", Category.SECURITY_CONTROL),
        ("infra/ratelimit/limiter.py", Category.SECURITY_CONTROL),
        ("control-plane/control_plane/orchestration/service.py", Category.AUTONOMOUS_ORCHESTRATION),
        (
            "control-plane/control_plane/development/github_provider.py",
            Category.AUTONOMOUS_ORCHESTRATION,
        ),
        (
            "control-plane/control_plane/self_learning/policy_gate/service.py",
            Category.AUTONOMOUS_ORCHESTRATION,
        ),
    ],
)
def test_security_controls_and_autonomous_orchestration_require_review(
    path: str, category: Category
) -> None:
    assert classify(path) is category
    assert classify(path) is not Category.INTERNAL
    assert policy.requires_review(classify(path))


@pytest.mark.parametrize(
    "path",
    [
        "core/notifications/service.py",
        "infra/jobs/queue.py",
        "infra/db/backup/destination.py",
        "docs/OBSERVABILITY.md",
        "tests/core/webhooks/test_webhooks_unit.py",
        "tests/core/outbox/test_outbox_unit.py",
    ],
)
def test_the_policy_did_not_become_globally_restrictive(path: str) -> None:
    """Tests and documentation about the protected areas -- in `tests/` and
    `docs/` -- stay automatic, as does ordinary internal code."""
    assert not policy.requires_review(classify(path))


def test_the_policy_version_is_2() -> None:
    assert policy.POLICY_VERSION == "2"
