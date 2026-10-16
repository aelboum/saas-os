"""`python -m saas_os.ops.audit_digest` -- check the audit tables against the
digests kept in the deployment's external log store
(docs/ADR/0053-audit-digests-in-external-logs.md; docs/RUNBOOKS.md,
"Audit digests").

    python -m saas_os.ops.audit_digest verify <exported-log-file | ->

The input must come **from the external store**, not from the database or
from a log the database administrators can edit: it is the only copy they
cannot rewrite. Export the worker's `audit_digest` lines (one JSON object
per line, as the worker logs them) for the period to check, and pass the
file, or `-` for standard input. Other log lines in the file are ignored.

By default the export must reach the newest settled window: audit rows
in settled windows after the last record are a finding
(`rows_after_coverage`), as are rows before the first record. Pass
`--partial` to check an export that deliberately ends earlier.

The command recomputes every recorded window from the database as the
application role (`DATABASE_URL`) -- the same read access the worker had
-- and prints one JSON object: the windows checked, the range covered, and
each finding. Exit status: 0 when every window matches and the chain is
whole, 1 when anything differs, 2 for unusable input or configuration.
Read-only: it writes nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict

from saas_os.core.audit_digest import records_from_log_lines, settled_until, verify_records
from saas_os.infra.db import get_engine, validate_application_role

_EXIT_OK = 0
_EXIT_MISMATCH = 1
_EXIT_USAGE = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m saas_os.ops.audit_digest",
        description="Check the audit tables against digests exported from the external log store.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify exported audit_digest log lines")
    verify.add_argument("source", help="exported log file, or - for standard input")
    verify.add_argument(
        "--partial",
        action="store_true",
        help="the export ends before the present: do not require coverage up to now",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    except SystemExit as exc:  # argparse already printed usage
        return int(exc.code) if isinstance(exc.code, int) else _EXIT_USAGE

    try:
        if args.source == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(args.source, encoding="utf-8") as handle:
                lines = handle.read().splitlines()
    except OSError as exc:
        print(f"cannot read {args.source}: {type(exc).__name__}", file=sys.stderr)
        return _EXIT_USAGE

    records = records_from_log_lines(lines)
    if not records:
        print("no audit_digest records in the input", file=sys.stderr)
        return _EXIT_USAGE

    try:
        validate_application_role(get_engine())
        until = None if args.partial else settled_until()
        result = verify_records(records, settled_until=until)
    except Exception as exc:  # noqa: BLE001 -- any failure is a non-zero exit, never a pass
        print(f"failed: {type(exc).__name__}", file=sys.stderr)
        return _EXIT_USAGE
    print(
        json.dumps(
            {
                "ok": result.ok,
                "windows": result.windows,
                "covered_from": result.covered_from,
                "covered_until": result.covered_until,
                "findings": [asdict(finding) for finding in result.findings],
            },
            sort_keys=True,
        )
    )
    return _EXIT_OK if result.ok else _EXIT_MISMATCH


if __name__ == "__main__":
    sys.exit(main())
