"""Report, and once enabled apply, the expiry of platform audit subject links
and erasure markers: audit identity phase P2 (owner decision D7,
"migrations-role expiry command with dry run and explicit confirmation";
`docs/RUNBOOKS.md`, "Audit identity holds and expiry").

    python -m saas_os.ops.audit_identity_expiry --operator <user id> \\
        --reason "TICKET-9: audit identity expiry"
    python -m saas_os.ops.audit_identity_expiry --operator <user id> \\
        --reason "TICKET-9: audit identity expiry" --apply \\
        --confirm-rows N --confirm-digest <hex> --confirm-holds <hex> \\
        --confirm-unlinks N --confirm-markers N

It is `saas_os.core.audit_identity.expire_audit_identity_links` with
`UserCaller(<operator>)`. Without `--apply` (the default) it reports the
platform scope's plan: the links eligible for deletion and their digest,
the links of erased subjects to unlink, the markers to delete, and the
active holds and their digest. It writes nothing.

**`--apply` is disabled** (owner decision O9 of 2026-11-03): it is refused
before any database connection (exit 1) and changes nothing, until an
authenticated, register-eligible approval mechanism is implemented,
independently reviewed and tested and a separate, owner-approved change
enables it. No flag or setting enables it.

`--operator` is a declaration, not an authenticated identity: the command
checks that the named user is an active platform operator holding
`platform.security_retention:report`, but whoever runs it with the
migrations credential can name any such operator.

**Connection.** Only `MIGRATIONS_DATABASE_URL`, the migrations role, which
owns the link tables; the application role has no `DELETE` on them. With
`ENVIRONMENT=production` it requires `--confirm-production`. Exit codes: 0
success, 1 a refused or failed run, 2 usage, invalid input or configuration.
Standard output carries exactly one JSON object on success; a failure prints
only the error's type to standard error. The output holds counts, digests, a
day and times: never a user id and never a reference.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Sequence

# Imported for its table definitions, as `saas_os.ops.operator_cli` does.
import saas_os.core.rbac  # noqa: F401
from saas_os.core.audit_identity import AuditIdentityExpiryReport
from saas_os.core.audit_identity.expiry import ExpiryConfirmation, expire_audit_identity_links
from saas_os.core.authority import UserCaller
from saas_os.core.config import ConfigurationError, get_settings

_EXIT_OK = 0
_EXIT_FAILURE = 1
_EXIT_USAGE = 2

_CONFIRMATIONS = (
    "confirm_rows",
    "confirm_digest",
    "confirm_holds",
    "confirm_unlinks",
    "confirm_markers",
)


class ExpiryInputError(ValueError):
    """A command-line argument is missing, malformed or inconsistent."""


def _uuid(raw: str, *, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except (TypeError, ValueError):
        raise ExpiryInputError(f"{field} must be a UUID.") from None


def _output(report: AuditIdentityExpiryReport) -> dict[str, object]:
    return {
        "as_of": report.as_of.isoformat(),
        "scope": report.scope,
        "applied": report.applied,
        "run_id": str(report.run_id) if report.run_id is not None else None,
        "eligible_links": report.eligible_links,
        "eligible_links_digest": report.eligible_links_digest,
        "links_to_unlink": report.links_to_unlink,
        "markers": report.markers,
        "active_holds": report.active_holds,
        "active_holds_digest": report.active_holds_digest,
        "oldest_eligible_day": (
            report.oldest_eligible_day.isoformat()
            if report.oldest_eligible_day is not None
            else None
        ),
    }


def run(args: argparse.Namespace) -> dict[str, object]:
    reason = args.reason.strip() if isinstance(args.reason, str) else ""
    if not reason:
        raise ExpiryInputError("--reason is required and must not be empty.")
    given = [name for name in _CONFIRMATIONS if getattr(args, name) is not None]
    if not args.apply and given:
        raise ExpiryInputError("the --confirm-* values go with --apply.")
    confirmation = None
    if args.apply:
        if len(given) != len(_CONFIRMATIONS):
            raise ExpiryInputError(
                "--apply needs --confirm-rows, --confirm-digest, --confirm-holds, "
                "--confirm-unlinks and --confirm-markers from a dry run."
            )
        confirmation = ExpiryConfirmation(
            rows=args.confirm_rows,
            digest=args.confirm_digest,
            holds=args.confirm_holds,
            unlinks=args.confirm_unlinks,
            markers=args.confirm_markers,
        )
    report = expire_audit_identity_links(
        caller=UserCaller(_uuid(args.operator, field="--operator")),
        reason=reason,
        apply=args.apply,
        confirmation=confirmation,
    )
    return _output(report)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m saas_os.ops.audit_identity_expiry",
        description=(
            "Report the expiry of platform audit subject links and erasure markers "
            "(migrations role only; owner decision D7). --apply is disabled (owner "
            "decision O9)."
        ),
    )
    parser.add_argument(
        "--operator",
        required=True,
        help="the platform operator's user id (declared, not authenticated)",
    )
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--apply", action="store_true", help="delete and unlink (disabled: refused)"
    )
    parser.add_argument("--confirm-rows", type=int, help="eligible link count of the dry run")
    parser.add_argument("--confirm-digest", help="eligible link digest of the dry run")
    parser.add_argument("--confirm-holds", help="active hold digest of the dry run")
    parser.add_argument("--confirm-unlinks", type=int, help="unlink count of the dry run")
    parser.add_argument("--confirm-markers", type=int, help="marker count of the dry run")
    parser.add_argument("--confirm-production", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    except SystemExit as exc:  # argparse already printed usage
        return int(exc.code) if isinstance(exc.code, int) else _EXIT_USAGE
    try:
        production = get_settings().environment == "production"
    except ConfigurationError as exc:
        print(f"invalid configuration: {exc}", file=sys.stderr)
        return _EXIT_USAGE
    if production and not args.confirm_production:
        print("ENVIRONMENT=production: add --confirm-production.", file=sys.stderr)
        return _EXIT_USAGE
    try:
        result = run(args)
    except ExpiryInputError as exc:
        print(f"invalid input: {exc}", file=sys.stderr)
        return _EXIT_USAGE
    except Exception as exc:  # noqa: BLE001 -- every refusal or failure is a non-zero exit
        print(f"failed: {type(exc).__name__}", file=sys.stderr)
        return _EXIT_FAILURE
    print(json.dumps({"command": "expire-audit-identity", "result": result}))
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
