"""Delete expired permission grant ledger rows: the controlled manual
procedure of owner decision B of 2026-11-02 (`docs/RUNBOOKS.md`,
"Deleting expired permission grant ledger rows").

    python -m saas_os.ops.permission_grant_ledger_expiry \\
        --operator <user id> (--tenant <id> [--tenant <id> ...] | --all-purged \\
        [--after <tenant id>]) --reason "TICKET-9: retention expiry"
    python -m saas_os.ops.permission_grant_ledger_expiry \\
        --execution-authorization <id> --reason "TICKET-9: retention expiry" [--apply]

**The authorised form** (owner decisions of 2026-11-03): with
`--execution-authorization` (the id of an execution authorisation made
through the authenticated platform-admin API) it is
`execute_authorized_permission_grant_ledger_deletion`. Scope, count and
digest come only from the records, and the run's caller is the
authorisation's authenticated author; `--operator`, `--tenant`,
`--all-purged`, `--after`, `--confirm-rows` and `--confirm-digest` are
refused with it. Without `--apply` it verifies the whole chain under the
locks and writes one `verify` platform audit row; it deletes nothing.
`--apply` is refused (`deletion_disabled`, exit 1).

It is `saas_os.core.permission_grants.expiry.expire_permission_grant_ledger_rows`
with `UserCaller(<operator>)`. Without `--apply` it reports, under the same
checks the deletion would use, which tenants' rows are eligible, their
count and digest, and writes nothing.

**`--apply` is disabled** (owner decision of 2026-11-02, separation of
duties): it is refused with `LedgerDeletionDisabledError` (exit 1, one
`denied` platform audit row) and deletes nothing, until a verifiable
approval control exists. When enabled it needs `--confirm-rows` and
`--confirm-digest` copied from a prior report, re-checks eligibility and
legal holds under lock, and deletes exactly those rows with platform audit
rows in the same transaction, or nothing.

`--operator` is a declaration, not an authenticated identity: the command
checks that the named user is an active platform operator holding
`platform.security_retention:report` and records the id, but whoever runs
it with the migrations credential can name any such operator.

**Connection.** Only `MIGRATIONS_DATABASE_URL`, the migrations role. It
refuses a connection whose role does not own the ledger, or that is the
application role (`DATABASE_URL`'s user); it never connects with
`DATABASE_URL`. That is deliberate: the application role has no `DELETE`
on the ledger, and no permission or database role grants one.

Not a step of any purge, job or route. With `ENVIRONMENT=production` it
requires `--confirm-production`. Exit codes: 0 success, 1 a refused or
failed run, 2 usage, invalid input or configuration. Standard output
carries exactly one JSON object on success; a failure prints only the
error's type to standard error.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Sequence

# Imported for its table definitions, as `saas_os.ops.operator_cli` does.
import saas_os.core.rbac  # noqa: F401
from saas_os.core.authority import UserCaller
from saas_os.core.config import ConfigurationError, get_settings
from saas_os.core.permission_grants.expiry import (
    AuthorizedLedgerDeletionResult,
    LedgerExpiryResult,
    execute_authorized_permission_grant_ledger_deletion,
    expire_permission_grant_ledger_rows,
)

_EXIT_OK = 0
_EXIT_FAILURE = 1
_EXIT_USAGE = 2
_MAX_TENANTS = 1000


class ExpiryInputError(ValueError):
    """An argument is missing, malformed or inconsistent."""


def _uuid(raw: str, *, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError, TypeError):
        raise ExpiryInputError(f"{field} must be a UUID.") from None


def _output(result: LedgerExpiryResult) -> dict[str, object]:
    return {
        "applied": result.applied,
        "as_of": result.as_of.isoformat(),
        "run_id": str(result.run_id) if result.run_id is not None else None,
        "eligible_ledger_rows": result.eligible_ledger_rows,
        "eligible_digest": result.eligible_digest,
        "not_eligible": result.not_eligible,
        "more": result.more,
        "eligible": [
            {
                "tenant_id": str(t.tenant_id),
                "ledger_rows": t.ledger_rows,
                "purged_at": t.purged_at.isoformat(),
                "expires_at": t.expires_at.isoformat(),
            }
            for t in result.eligible
        ],
    }


def _authorized_output(result: AuthorizedLedgerDeletionResult) -> dict[str, object]:
    return {
        "applied": result.applied,
        "as_of": result.as_of.isoformat(),
        "execution_authorization_id": str(result.execution_authorization_id),
        "approval_id": str(result.approval_id),
        "request_id": str(result.request_id),
        "authorized_by_user_id": str(result.authorized_by_user_id),
        "audit_id": str(result.audit_id),
        "run_id": str(result.run_id) if result.run_id is not None else None,
        "eligible_ledger_rows": result.eligible_ledger_rows,
        "eligible_digest": result.eligible_digest,
        "scope_digest": result.scope_digest,
        "tenants": [
            {
                "tenant_id": str(t.tenant_id),
                "ledger_rows": t.ledger_rows,
                "purged_at": t.purged_at.isoformat(),
                "expires_at": t.expires_at.isoformat(),
            }
            for t in result.tenants
        ],
    }


def run(args: argparse.Namespace) -> dict[str, object]:
    reason = args.reason.strip() if isinstance(args.reason, str) else ""
    if not reason:
        raise ExpiryInputError("--reason is required and must not be empty.")
    if args.execution_authorization is not None:
        # Scope and binding come only from the records (owner decisions of
        # 2026-11-03): nothing that names a person or a scope goes with it.
        if (
            args.operator is not None
            or args.tenant
            or args.all_purged
            or args.after is not None
            or args.confirm_rows is not None
            or args.confirm_digest is not None
        ):
            raise ExpiryInputError(
                "--execution-authorization takes no --operator, --tenant, --all-purged, "
                "--after, --confirm-rows or --confirm-digest."
            )
        return _authorized_output(
            execute_authorized_permission_grant_ledger_deletion(
                _uuid(args.execution_authorization, field="--execution-authorization"),
                reason=reason,
                apply=args.apply,
            )
        )
    if args.operator is None:
        raise ExpiryInputError("give --operator (a report) or --execution-authorization.")
    tenants = args.tenant or []
    if args.all_purged == bool(tenants):
        raise ExpiryInputError("give --tenant (repeatable) or --all-purged, not both.")
    if len(tenants) > _MAX_TENANTS:
        raise ExpiryInputError(f"at most {_MAX_TENANTS} --tenant values; use --all-purged.")
    if args.after is not None and not args.all_purged:
        raise ExpiryInputError("--after goes with --all-purged.")
    if args.apply and (args.confirm_rows is None or args.confirm_digest is None):
        raise ExpiryInputError("--apply needs --confirm-rows and --confirm-digest.")
    if not args.apply and (args.confirm_rows is not None or args.confirm_digest is not None):
        raise ExpiryInputError("--confirm-rows and --confirm-digest go with --apply.")
    result = expire_permission_grant_ledger_rows(
        caller=UserCaller(_uuid(args.operator, field="--operator")),
        reason=reason,
        tenant_ids=[_uuid(t, field="--tenant") for t in tenants],
        all_purged=args.all_purged,
        after=_uuid(args.after, field="--after") if args.after is not None else None,
        apply=args.apply,
        confirm_rows=args.confirm_rows,
        confirm_digest=args.confirm_digest,
    )
    return _output(result)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m saas_os.ops.permission_grant_ledger_expiry",
        description=(
            "Report expired permission grant ledger rows (migrations role only; owner "
            "decision B of 2026-11-02). --apply (deletion) is disabled pending a "
            "verifiable approval control."
        ),
    )
    parser.add_argument(
        "--operator",
        help="the platform operator's user id for a report (declared, not authenticated)",
    )
    parser.add_argument(
        "--execution-authorization",
        help="the id of an execution authorisation made through the authenticated API",
    )
    parser.add_argument("--tenant", action="append", help="a tenant id (repeatable)")
    parser.add_argument("--all-purged", action="store_true", help="every PURGED tenant")
    parser.add_argument("--after", help="with --all-purged: continue after this tenant id")
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--apply", action="store_true", help="delete (disabled: refused); default reports only"
    )
    parser.add_argument("--confirm-rows", type=int, help="eligible row count of the report")
    parser.add_argument("--confirm-digest", help="eligible digest of the report")
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
    print(json.dumps({"command": "expire-permission-grant-ledger", "result": result}))
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
