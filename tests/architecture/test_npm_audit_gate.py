"""The frontend dependency-audit gate (`scripts/npm_audit_gate.py`) and its
one checked-in exception (`scripts/security-exceptions.json`).

Positive control: the accepted advisory, under its conditions, passes.
Negative controls: every way the exception must stop applying fails the
gate -- another advisory, another package, expiry, reaching production
dependencies, a non-breaking fix, a stale entry, a malformed file.

The reports are `npm audit --json` documents built here; no network.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = REPO_ROOT / "scripts" / "npm_audit_gate.py"
EXCEPTIONS_PATH = REPO_ROOT / "scripts" / "security-exceptions.json"

BRACES = "GHSA-vfj7-8cjw-p6xm"
TODAY = dt.date(2026, 10, 11)


def _load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("npm_audit_gate", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _report(*entries: tuple[str, str, str, Any]) -> dict[str, Any]:
    """`(package, advisory id, severity, fixAvailable)` -> an audit report.
    Each package also drags in a dependent that is affected only *via* it,
    the way `npm audit` reports `micromatch` for `braces`."""
    vulnerabilities: dict[str, Any] = {}
    for package, identifier, severity, fix in entries:
        vulnerabilities[package] = {
            "name": package,
            "severity": severity,
            "via": [
                {
                    "source": 1,
                    "name": package,
                    "title": f"{package} advisory",
                    "url": f"https://github.com/advisories/{identifier}",
                    "severity": severity,
                }
            ],
            "fixAvailable": fix,
        }
        vulnerabilities[f"uses-{package}"] = {
            "name": f"uses-{package}",
            "severity": severity,
            "via": [package],
            "fixAvailable": fix,
        }
    return {"auditReportVersion": 2, "vulnerabilities": vulnerabilities}


_BREAKING_FIX = {"name": "eslint-config-next", "version": "14.2.35", "isSemVerMajor": True}
_BRACES_TODAY = ("braces", BRACES, "high", _BREAKING_FIX)
_CLEAN = _report()


def _exceptions() -> list[Any]:
    return gate.load_exceptions(EXCEPTIONS_PATH)


# --- The checked-in exception ---------------------------------------------------------------


def test_the_exceptions_file_holds_exactly_the_one_approved_advisory() -> None:
    document = json.loads(EXCEPTIONS_PATH.read_text(encoding="utf-8"))
    assert [(e["id"], e["package"], e["expires"]) for e in document["npm"]] == [
        (BRACES, "braces", "2027-01-11")
    ]
    entry = document["npm"][0]
    for field in ("reason", "approved_by", "approved_on", "review_when", "remediation"):
        assert entry[field].strip(), field


def test_the_accepted_advisory_passes_and_is_reported_as_not_fixed() -> None:
    verdict = gate.evaluate(_report(_BRACES_TODAY), _CLEAN, _exceptions(), TODAY)
    assert verdict.passed
    assert len(verdict.accepted) == 1
    assert "NOT FIXED" in verdict.accepted[0] and "2027-01-11" in verdict.accepted[0]


def test_it_holds_through_its_last_day_and_fails_the_day_after() -> None:
    report = _report(_BRACES_TODAY)
    assert gate.evaluate(report, _CLEAN, _exceptions(), dt.date(2027, 1, 11)).passed
    expired = gate.evaluate(report, _CLEAN, _exceptions(), dt.date(2027, 1, 12))
    assert not expired.passed
    assert "EXPIRED" in expired.blocking[0]


# --- Everything else still fails ------------------------------------------------------------


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_any_other_advisory_fails_the_gate(severity: str) -> None:
    report = _report(_BRACES_TODAY, ("lodash", "GHSA-aaaa-bbbb-cccc", severity, True))
    verdict = gate.evaluate(report, _CLEAN, _exceptions(), TODAY)
    assert not verdict.passed
    assert len(verdict.blocking) == 1 and "GHSA-aaaa-bbbb-cccc" in verdict.blocking[0]


def test_another_advisory_in_the_same_package_fails_the_gate() -> None:
    report = _report(("braces", "GHSA-zzzz-yyyy-xxxx", "high", _BREAKING_FIX))
    verdict = gate.evaluate(report, _CLEAN, _exceptions(), TODAY)
    assert any("GHSA-zzzz-yyyy-xxxx" in line for line in verdict.blocking)


def test_the_same_advisory_id_in_another_package_fails_the_gate() -> None:
    report = _report(_BRACES_TODAY, ("other-package", BRACES, "high", _BREAKING_FIX))
    verdict = gate.evaluate(report, _CLEAN, _exceptions(), TODAY)
    assert [line for line in verdict.blocking if "other-package" in line]


def test_the_exception_is_void_once_the_advisory_reaches_production_dependencies() -> None:
    report = _report(_BRACES_TODAY)
    verdict = gate.evaluate(report, report, _exceptions(), TODAY)
    assert not verdict.passed and "production" in verdict.blocking[0]


def test_the_exception_is_void_once_a_non_breaking_fix_exists() -> None:
    report = _report(("braces", BRACES, "high", True))
    verdict = gate.evaluate(report, _CLEAN, _exceptions(), TODAY)
    assert not verdict.passed and "non-breaking fix" in verdict.blocking[0]


def test_a_stale_exception_fails_the_gate_until_it_is_removed() -> None:
    verdict = gate.evaluate(_CLEAN, _CLEAN, _exceptions(), TODAY)
    assert not verdict.passed and "stale" in verdict.blocking[0]


def test_with_no_exceptions_the_advisory_fails_as_it_did_before() -> None:
    verdict = gate.evaluate(_report(_BRACES_TODAY), _CLEAN, [], TODAY)
    assert not verdict.passed and BRACES in verdict.blocking[0]


def test_low_and_moderate_advisories_do_not_block_as_before() -> None:
    """Unchanged threshold: `--audit-level=high` never failed on these."""
    report = _report(
        _BRACES_TODAY,
        ("a", "GHSA-low0-low0-low0", "low", True),
        ("b", "GHSA-mod0-mod0-mod0", "moderate", True),
    )
    assert gate.evaluate(report, _CLEAN, _exceptions(), TODAY).passed


def test_a_clean_tree_with_no_exceptions_passes() -> None:
    assert gate.evaluate(_CLEAN, _CLEAN, [], TODAY).passed


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "{}",
        '{"npm": [{"id": "GHSA-vfj7-8cjw-p6xm", "package": "braces"}]}',
        '{"npm": [{"id": "X", "package": "p", "reason": "r", "approved_by": "o", '
        '"approved_on": "2026-10-11", "expires": "never"}]}',
        '{"npm": [{"id": "X", "package": "p", "reason": " ", "approved_by": "o", '
        '"approved_on": "2026-10-11", "expires": "2027-01-11"}]}',
    ],
)
def test_a_malformed_exceptions_file_is_an_error_not_an_empty_list(
    tmp_path: Path, content: str
) -> None:
    path = tmp_path / "security-exceptions.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(gate.ExceptionsFileError):
        gate.load_exceptions(path)


def test_the_gate_exits_non_zero_when_it_cannot_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(gate.shutil, "which", lambda name: None)
    assert gate.main(["npm_audit_gate.py", str(tmp_path)]) == 1
    assert "could not run" in capsys.readouterr().out
