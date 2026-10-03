"""`saas-os-update` -- inspect and apply a newer SaaS-OS revision to a
consuming project's exact-SHA pin (docs/AUTO-UPDATE-CLI.md; ADR-0015).

    saas-os-update check  --source ../saas-os --candidate <sha|ref> [--consumer .] [--format json]
    saas-os-update update --source ../saas-os --candidate <sha|ref> [--consumer .] [--format json]

`check` analyzes and changes nothing. `update` applies only a SAFE
candidate, validates it, and rolls back on failure. Neither commits, pushes,
fetches, nor talks to a hosting provider: `--source` is a local clone the
caller has already fetched. The exit code is the contract for automation
(`infra.update.engine.ExitCode`); `--format json` is the machine-readable
report. Neither prints environment variables, command output or URL
credentials.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from infra.update.engine import Analysis, Decision, Outcome, analyze, update


def _render_text(analysis: Analysis) -> str:
    report = analysis.to_dict()
    consumer = report["consumer"]
    candidate = report["candidate"]
    changes = report["changes"]
    assert isinstance(consumer, dict) and isinstance(candidate, dict)
    assert isinstance(changes, dict)
    lines = [
        f"decision:   {report['decision'].upper()}",  # type: ignore[union-attr]
        f"outcome:    {report['outcome']}",
        f"exit code:  {report['exit_code']}",
        f"policy:     v{report['policy']['version']}",  # type: ignore[index]
        f"pin:        {consumer['pin_file']}:{consumer['pin_line']}",
        f"current:    {consumer['current_sha']}",
        f"candidate:  {candidate['sha']} (from {candidate['ref']!s}, {candidate['relationship']})",
    ]
    if candidate["subject"]:
        lines.append(f"            {candidate['subject']}")
    categories = changes["categories"]
    if categories:
        assert isinstance(categories, dict)
        summary = ", ".join(f"{name}={count}" for name, count in categories.items())
        lines.append(f"changes:    {summary}")
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    if reasons:
        lines.append("reasons:")
        lines.extend(f"  - [{r['decision']}] {r['code']}: {r['detail']}" for r in reasons)
    checks = report["checks"]
    assert isinstance(checks, list)
    if checks:
        lines.append("checks:")
        lines.extend(f"  - {c['status']}: {' '.join(c['argv'])}" for c in checks)
    if analysis.rollback_attempted:
        lines.append(f"rollback:   verified={analysis.rollback_verified}")
    if analysis.outcome is Outcome.ROLLBACK_FAILED:
        lines.append("WARNING: the pin file could not be restored; fix it manually.")
    elif analysis.decision is Decision.REVIEW_REQUIRED:
        lines.append("Human review is required; nothing was changed.")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="saas-os-update",
        description="Inspect and apply a newer SaaS-OS revision to this project's exact-SHA "
        "pin. Never commits or pushes. See docs/AUTO-UPDATE-CLI.md.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("check", "analyze a candidate and explain the decision; changes nothing"),
        ("update", "apply a SAFE candidate, validate it, and roll back on failure"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument(
            "--source",
            required=True,
            help="a local, already-fetched clone of the SaaS-OS repository",
        )
        command.add_argument(
            "--candidate",
            required=True,
            help="the candidate commit: an exact SHA, or a ref resolved to one in --source",
        )
        command.add_argument(
            "--consumer",
            default=".",
            help="the consuming project's repository root (default: the current directory)",
        )
        command.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    consumer, source = Path(args.consumer), Path(args.source)
    if args.command == "check":
        analysis = analyze(consumer, source, args.candidate, command="check")
    else:
        analysis = update(consumer, source, args.candidate)

    if args.format == "json":
        # ASCII-only JSON (`ensure_ascii`): safe on any console encoding.
        sys.stdout.write(json.dumps(analysis.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        # Commit subjects are arbitrary Unicode; a console that cannot encode
        # a character must not turn a decision into a crash.
        encoding = sys.stdout.encoding or "utf-8"
        text = _render_text(analysis).encode(encoding, "replace").decode(encoding)
        sys.stdout.write(text)
    return int(analysis.exit_code)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
