"""The frontend dependency-audit gate used by `scripts/check-security.sh`.

It fails on every `npm audit` advisory of severity high or critical --
the same threshold as `npm audit --audit-level=high` -- except an advisory
that is listed in `scripts/security-exceptions.json` AND still meets every
condition of its exception. An exception is not a fix and is never
reported as one: an accepted advisory is printed on every run, with its
expiry.

An exception stops applying, and the gate fails again, as soon as any of
these is true:

- its expiry date has passed;
- the advisory is reachable from production dependencies
  (`npm audit --omit=dev` reports it);
- `npm` offers a fix that is not a breaking change
  (`fixAvailable` is `true` for the affected package);
- the advisory is no longer reported at all -- the entry is stale and
  must be removed.

Nothing else is exempted: no severity, no package, no dependency class.
A malformed exceptions file fails the gate.

Usage: `python scripts/npm_audit_gate.py [frontend-directory]`.
Exit status 0 only when no unaccepted finding exists.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BLOCKING_SEVERITIES = frozenset({"high", "critical"})
EXCEPTIONS_FILE = Path(__file__).resolve().parent / "security-exceptions.json"
_REQUIRED_FIELDS = ("id", "package", "reason", "approved_by", "approved_on", "expires")


class ExceptionsFileError(ValueError):
    """`security-exceptions.json` is missing a field or is not valid."""


@dataclass(frozen=True)
class Advisory:
    id: str
    package: str
    severity: str
    title: str
    fix_available: Any


@dataclass(frozen=True)
class AllowedException:
    id: str
    package: str
    expires: dt.date
    reason: str


@dataclass(frozen=True)
class Verdict:
    blocking: tuple[str, ...]
    accepted: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.blocking


def advisory_id(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[-1]


def advisories(report: dict[str, Any]) -> list[Advisory]:
    """Every distinct advisory in an `npm audit --json` report. A package
    that is only affected *through* another one (`via` holds a package
    name) carries no advisory of its own and adds nothing here."""
    found: dict[tuple[str, str], Advisory] = {}
    for package, entry in sorted(report.get("vulnerabilities", {}).items()):
        for via in entry.get("via", []):
            if not isinstance(via, dict):
                continue
            identifier = advisory_id(str(via.get("url", ""))) or str(via.get("source", ""))
            found[(identifier, package)] = Advisory(
                id=identifier,
                package=package,
                severity=str(via.get("severity", entry.get("severity", "unknown"))).lower(),
                title=str(via.get("title", "")),
                fix_available=entry.get("fixAvailable"),
            )
    return list(found.values())


def load_exceptions(path: Path = EXCEPTIONS_FILE) -> list[AllowedException]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        entries = document["npm"]
        loaded = []
        for entry in entries:
            missing = [name for name in _REQUIRED_FIELDS if not str(entry.get(name, "")).strip()]
            if missing:
                raise ExceptionsFileError(f"exception entry is missing {missing}: {entry!r}")
            dt.date.fromisoformat(entry["approved_on"])
            loaded.append(
                AllowedException(
                    id=entry["id"],
                    package=entry["package"],
                    expires=dt.date.fromisoformat(entry["expires"]),
                    reason=entry["reason"],
                )
            )
    except ExceptionsFileError:
        raise
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ExceptionsFileError(f"{path.name} is not a valid exceptions file: {exc}") from exc
    return loaded


def evaluate(
    full_report: dict[str, Any],
    production_report: dict[str, Any],
    exceptions: list[AllowedException],
    today: dt.date,
) -> Verdict:
    full = advisories(full_report)
    in_production = {(a.id, a.package) for a in advisories(production_report)}
    allowed = {(e.id, e.package): e for e in exceptions}
    blocking: list[str] = []
    accepted: list[str] = []
    seen: set[tuple[str, str]] = set()

    for advisory in full:
        key = (advisory.id, advisory.package)
        seen.add(key)
        label = f"{advisory.id} ({advisory.package}, {advisory.severity}): {advisory.title}"
        if advisory.severity not in BLOCKING_SEVERITIES:
            continue
        exception = allowed.get(key)
        if exception is None:
            blocking.append(label)
        elif today > exception.expires:
            blocking.append(f"{label} -- exception EXPIRED on {exception.expires.isoformat()}")
        elif key in in_production:
            blocking.append(f"{label} -- exception void: reachable from production dependencies")
        elif advisory.fix_available is True:
            blocking.append(f"{label} -- exception void: a non-breaking fix is available")
        else:
            accepted.append(
                f"{label} -- NOT FIXED; accepted until {exception.expires.isoformat()}: "
                f"{exception.reason}"
            )

    for key, exception in allowed.items():
        if key not in seen:
            blocking.append(
                f"{exception.id} ({exception.package}) -- exception is stale: the advisory is no "
                "longer reported; remove it from security-exceptions.json"
            )
    return Verdict(tuple(blocking), tuple(accepted))


def _npm_audit(directory: Path, *extra: str) -> dict[str, Any]:
    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError("npm was not found on PATH")
    completed = subprocess.run(  # noqa: S603 -- fixed arguments, no shell
        [npm, "audit", "--json", *extra],
        cwd=directory,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    # `npm audit` exits non-zero when it finds something; the report on
    # stdout is what is judged. No report at all is a failure of the gate.
    report = json.loads(completed.stdout)
    if "vulnerabilities" not in report:
        raise RuntimeError(f"npm audit returned no report: {completed.stdout[:300]!r}")
    return report


def main(argv: list[str]) -> int:
    directory = Path(argv[1]) if len(argv) > 1 else Path("frontend")
    try:
        verdict = evaluate(
            _npm_audit(directory),
            _npm_audit(directory, "--omit=dev"),
            load_exceptions(),
            dt.date.today(),
        )
    except (ExceptionsFileError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"FAIL: the npm audit gate could not run: {exc}")
        return 1
    for line in verdict.accepted:
        print(f"ACCEPTED EXCEPTION: {line}")
    for line in verdict.blocking:
        print(f"UNACCEPTED: {line}")
    if verdict.passed:
        print("npm audit gate: no unaccepted advisory at high or critical severity.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
