"""`saas-os-operator` -- packaged commands for the destructive platform
operations that never become routes (ADR-0050; ADR-0045, "Operator tooling
for purge, erasure, move and delete").

    saas-os-operator delete-tenant --tenant <id> --operator <user id> \\
        --reason "TICKET-1: contract ended" --confirm <id>
    saas-os-operator purge-tenant --tenant <id> --actor <user id> \\
        --setup my_product.purge:register_purge_participants --confirm <id>
    saas-os-operator erase-user --user <id> --tenant <id> [--tenant <id> ...] \\
        --actor <user id> --confirm <id>
    saas-os-operator move-tenant --tenant <id> (--new-parent <id> | --root) \\
        --operator <user id> --reason "TICKET-2: reorganization"
    saas-os-operator ai-show --operator <user id>     (and the other ai-* commands)
    saas-os-operator redact-webhook-errors [--apply]
    saas-os-operator replay-outbox-events --tenant <id> --operator <user id> \\
        (--event-id <id> [--event-id <id> ...] | --dead-lettered-since <ISO time>) \\
        --reason "TICKET-3: quota raised" [--apply]
    saas-os-operator reencrypt-webhook-secrets --tenant <id> --operator <user id> \\
        --reason "TICKET-4: F7 migration" [--apply]
    saas-os-operator apply-permission-grants --operator <user id> --namespace <ns> \\
        --module my_product.grants[:ATTRIBUTE] (--tenant <id> | --all-tenants) \\
        --reason "TICKET-4: reports module" [--apply]
    saas-os-operator permission-grant-ledger-retention --operator <user id> \\
        (--tenant <id> | --all-purged [--after <tenant id>]) --reason "TICKET-6: yearly review"
    saas-os-operator hold-permission-grant-ledger --operator <user id> --tenant <id> \\
        --reference LEGAL-2026-014 --reason "TICKET-7: litigation hold"

**Each command is one Core call, with the caller Core requires.** Nothing is
decided here:

- `delete-tenant` marks a tenant `DELETED` with
  `transition_tenant_status(..., caller=UserCaller(<operator>))`; Core
  requires `platform.tenant:delete` and writes the platform audit row.
- `move-tenant` is `move_tenant(..., caller=UserCaller(<operator>))`; Core
  requires `platform.tenant:move` and refuses a move into the operator's
  own hierarchy.
- `purge-tenant` is `purge_tenant(..., caller=SystemCaller(TENANT_PURGE),
  actor_user_id=<actor>)`, the one caller purge accepts; `--actor` names
  the person, for attribution only. A tenant must already be `DELETED`.
- `erase-user` is `erase_user_identity(<user>, <tenants>,
  actor_user_id=<actor>)`; Core refuses an enrolled platform operator.
- `redact-webhook-errors` is `redact_stored_webhook_url_errors(apply=...)`
  (`saas_os.core.webhooks.stored_errors`, ledger row 900): it counts the
  stored webhook errors that still carry a destination URL, in every
  tenant's outbox `last_error` and in the Redis dead-letter list, and with
  `--apply` replaces their text, keeping the error type. It needs
  `REDIS_URL` as well as `DATABASE_URL`, and no operator id: it changes no
  authority and no tenant state, only removes text that should not have
  been stored.
- `replay-outbox-events` is `replay_dead_lettered_events(<tenant>,
  caller=UserCaller(<operator>), ...)` (outbox decision brief Q2, 2A); Core
  requires `platform.outbox:replay`. Without `--apply` it only counts the
  tenant's matching dead-lettered events; with it, each becomes pending
  again (attempts reset, `last_error` kept), with a platform and a tenant
  audit row. One tenant per run, at most 1000 events.
- `reencrypt-webhook-secrets` is `reencrypt_legacy_signing_secrets(<tenant>,
  caller=UserCaller(<operator>), ...)` (finding F7); Core requires
  `platform.webhook_secret:reencrypt`, checked before anything else. Without
  `--apply` it only counts the tenant's plaintext signing secrets and locks
  no row; with it, the key is checked next, before any row is read, then
  each secret is encrypted in place and verified before it is written, with
  one tenant audit row per subscription and one platform audit row. The
  output is counts only; no secret is ever printed.
- `apply-permission-grants` is `apply_permission_grant_migrations(<the
  list>, namespace=<ns>, caller=UserCaller(<operator>), ...)` (ADR 0060,
  option C); Core requires `platform.permission_grant:apply`. `--module`
  names the product module whose `PERMISSION_GRANT_MIGRATIONS` (or the
  attribute after a colon) is the declared list. Without `--apply` it
  only counts, per tenant; with it, each tenant's missing grants are added
  in a transaction of its own, with tenant audit rows, a ledger row per
  migration and one platform audit row for the run. The output is counts
  per tenant, never a role or permission name.
- `permission-grant-ledger-retention` is
  `permission_grant_ledger_retention_report(caller=UserCaller(<operator>),
  ...)` (owner policy of 2026-11-02); Core requires
  `platform.security_retention:report`. Read only: per tenant, whether its
  ledger rows are eligible for expiry (`PURGED` for two years, no active
  legal hold) and why not, with counts and times, and the eligible rows'
  count and digest; one platform audit row. It deletes nothing: no
  `saas-os-operator` command deletes ledger rows. The deletion is the manual
  migrations-role procedure `python -m
  saas_os.ops.permission_grant_ledger_expiry` (owner decision B of
  2026-11-02), confirmed with that count and digest, and it is disabled
  until a verifiable approval control exists (separation of duties).
- `hold-permission-grant-ledger` is `place_permission_grant_ledger_hold`;
  Core requires `platform.security_retention_hold:manage`: an emergency
  legal hold on one tenant's ledger rows, with an opaque `--reference` to
  the matter (letters, digits and `._:-`; never a name). One platform audit
  row. Hold management is not granted at bootstrap: an independently
  authorised operator receives it out of band (`docs/RUNBOOKS.md`,
  "Granting legal-hold management"). **No command releases a hold or
  approves a deletion** (owner decision of 2026-11-03): the release, the
  deletion request, its approval and its execution authorisation are made
  only through the authenticated platform-admin routes, whose caller is the
  OIDC session's user, never a declared `--operator`. The former
  `release-permission-grant-ledger-hold` is removed.
- `ai-*` configure AI providers, models, aliases, private-endpoint trust and
  destination policy (ADR-0054 D4; `saas_os.ops.ai_commands`), each a
  platform operation run with `UserCaller(<operator>)`.

**Product data.** A purge deletes product rows only through the purge
participants the product registered in *this* process. `purge-tenant`
therefore requires `--setup module:function` (called with no arguments
before the purge, for instance the product's own registration function or
its `create_app`) or an explicit `--no-product-participants`; without
either it refuses, and it refuses when `--setup` ran but no participant is
registered, before the tenant is touched. A non-empty registry proves only
that at least one participant is registered, not that every participant
the product needs is: that is the product's own `--setup` function to
guarantee. `--no-product-participants` is recorded in the purge's
`tenant.purge_completed` metadata as `product_participants_skipped: true`.
`--actor` must name an existing user.

**Guards.** The destructive commands (`delete-tenant`, `purge-tenant`,
`erase-user`) require `--confirm` repeating the target's id. With
`ENVIRONMENT=production` every command requires `--confirm-production`;
run it inside the backend container, which sets `ENVIRONMENT`. The
database connection is `DATABASE_URL`, the application role's; the
command refuses a superuser or `BYPASSRLS` role
(`validate_application_role`), but cannot tell the migrations role from
the application role -- do not point it at the migrations URL.

**Tier-0 trust.** Like the platform bootstrap command, this is not a
security boundary against the person running it: whoever can run it holds
the application role's credentials. It makes the legitimate path the
convenient one, with Core's authorization and audit evidence. `--operator`
and `--actor` are declarations, recorded in the audit rows, not
authenticated identities: Core checks that the named user may perform the
operation, not that the person at the keyboard is that user.

Exit codes: 0 success, 1 a refused or failed operation, 2 usage, invalid
input or configuration. Standard output carries exactly one JSON object
on success and nothing else; every diagnostic goes to standard error, and a
failure prints only the error's type, never its message. An `erase-user`
that failed part way is finished by running it again.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import importlib
import json
import logging
import sys
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any

# Imported for its table definitions: `core.audit_log` has foreign keys onto
# `core.delegation_grants` and `core.support_access_requests`. Without it, every
# audit write in a fresh operator process fails with `NoReferencedTableError`
# unless `--setup` happens to import RBAC (building the application does).
import saas_os.core.rbac  # noqa: F401
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.config import ConfigurationError, get_settings
from saas_os.core.identity import get_user
from saas_os.core.identity.erasure import erase_user_identity
from saas_os.core.tenancy import (
    TenantStatus,
    move_tenant,
    purge_tenant,
    registered_purge_participant_names,
    transition_tenant_status,
)
from saas_os.infra.db import get_engine, validate_application_role
from saas_os.ops.ai_commands import AI_COMMANDS, AICommandInputError, add_ai_parsers

# No `configure_logging()`: it writes JSON log lines to standard output,
# which carries only the result here. Core's warnings reach standard error
# through Python's default handler.
logger = logging.getLogger(__name__)

_EXIT_OK = 0
_EXIT_FAILURE = 1
_EXIT_USAGE = 2
_MAX_REASON = 500
_MAX_ERASE_TENANTS = 1000


class OperatorInputError(ValueError):
    """An argument is missing, malformed or inconsistent."""


def _uuid(raw: str, *, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError, TypeError):
        raise OperatorInputError(f"{field} must be a UUID.") from None


def _reason(raw: str | None) -> str:
    reason = raw.strip() if isinstance(raw, str) else ""
    if not reason:
        raise OperatorInputError("--reason is required and must not be empty.")
    if len(reason) > _MAX_REASON:
        raise OperatorInputError(f"--reason exceeds {_MAX_REASON} characters.")
    return reason


def _confirmed(target: uuid.UUID, confirm: str | None) -> None:
    if confirm is None or _uuid(confirm, field="--confirm") != target:
        raise OperatorInputError("--confirm must repeat the target's id exactly.")


def _setup(spec: str) -> Callable[[], Any]:
    module_name, _, attribute = spec.partition(":")
    if not module_name or not attribute:
        raise OperatorInputError("--setup must be 'module:function'.")
    try:
        target = getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError):
        raise OperatorInputError(f"--setup {spec!r} cannot be imported.") from None
    if not callable(target):
        raise OperatorInputError(f"--setup {spec!r} is not callable.")
    return target


_DEFAULT_MIGRATIONS_ATTRIBUTE = "PERMISSION_GRANT_MIGRATIONS"


def _declared_migrations(spec: str) -> object:
    module_name, _, attribute = spec.partition(":")
    if not module_name:
        raise OperatorInputError("--module must be 'module' or 'module:ATTRIBUTE'.")
    try:
        return getattr(
            importlib.import_module(module_name), attribute or _DEFAULT_MIGRATIONS_ATTRIBUTE
        )
    except (ImportError, AttributeError):
        raise OperatorInputError(f"--module {spec!r} cannot be imported.") from None


def _jsonable(value: object) -> object:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, set | frozenset):
        return sorted((_jsonable(v) for v in value), key=str)
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


# --- the commands ---------------------------------------------------------------------


def delete_tenant(args: argparse.Namespace) -> object:
    tenant = _uuid(args.tenant, field="--tenant")
    _confirmed(tenant, args.confirm)
    result = transition_tenant_status(
        tenant,
        TenantStatus.DELETED,
        caller=UserCaller(_uuid(args.operator, field="--operator")),
        reason=_reason(args.reason),
    )
    return {"tenant_id": result.id, "status": result.status}


def move(args: argparse.Namespace) -> object:
    tenant = _uuid(args.tenant, field="--tenant")
    if args.root == (args.new_parent is not None):
        raise OperatorInputError("give exactly one of --new-parent and --root.")
    new_parent = None if args.root else _uuid(args.new_parent, field="--new-parent")
    result = move_tenant(
        tenant,
        new_parent,
        caller=UserCaller(_uuid(args.operator, field="--operator")),
        reason=_reason(args.reason),
    )
    return {"tenant_id": result.id, "parent_id": result.parent_id}


def purge(args: argparse.Namespace) -> object:
    tenant = _uuid(args.tenant, field="--tenant")
    _confirmed(tenant, args.confirm)
    actor = _uuid(args.actor, field="--actor")
    if not args.setup and not args.no_product_participants:
        raise OperatorInputError(
            "purge-tenant needs --setup module:function to register the product's purge "
            "participants, or --no-product-participants if there is no product data."
        )
    if args.setup and args.no_product_participants:
        raise OperatorInputError("--setup and --no-product-participants exclude each other.")
    if get_user(actor) is None:
        raise OperatorInputError("--actor does not name an existing user.")
    for spec in args.setup or ():
        _setup(spec)()
    if args.setup and not registered_purge_participant_names():
        raise OperatorInputError(
            "--setup registered no purge participant; product rows would stay behind."
        )
    return purge_tenant(
        tenant,
        caller=SystemCaller(SystemAuthority.TENANT_PURGE),
        actor_user_id=actor,
        product_participants_skipped=args.no_product_participants,
    )


def erase(args: argparse.Namespace) -> object:
    user = _uuid(args.user, field="--user")
    _confirmed(user, args.confirm)
    tenants = [_uuid(t, field="--tenant") for t in args.tenant or ()]
    if not tenants:
        raise OperatorInputError("erase-user needs at least one --tenant.")
    if len(tenants) > _MAX_ERASE_TENANTS:
        raise OperatorInputError(f"at most {_MAX_ERASE_TENANTS} --tenant values.")
    return erase_user_identity(user, tenants, actor_user_id=_uuid(args.actor, field="--actor"))


def redact_webhook_errors(args: argparse.Namespace) -> object:
    # Imported here: importing `saas_os.core.webhooks` registers its jobs, which
    # reads `REDIS_URL`; the other commands need no Redis.
    from saas_os.core.webhooks.stored_errors import redact_stored_webhook_url_errors

    return asyncio.run(redact_stored_webhook_url_errors(apply=args.apply))


def replay_outbox_events(args: argparse.Namespace) -> object:
    from saas_os.core.outbox.replay import replay_dead_lettered_events

    tenant = _uuid(args.tenant, field="--tenant")
    if bool(args.event_id) == (args.dead_lettered_since is not None):
        raise OperatorInputError("give --event-id (repeatable) or --dead-lettered-since, not both.")
    since = None
    if args.dead_lettered_since is not None:
        try:
            since = datetime.fromisoformat(args.dead_lettered_since)
        except ValueError:
            raise OperatorInputError("--dead-lettered-since must be an ISO 8601 time.") from None
        if since.tzinfo is None:
            raise OperatorInputError("--dead-lettered-since must carry a UTC offset.")
    return replay_dead_lettered_events(
        tenant,
        caller=UserCaller(_uuid(args.operator, field="--operator")),
        reason=_reason(args.reason),
        event_ids=[_uuid(e, field="--event-id") for e in args.event_id] if args.event_id else None,
        dead_lettered_since=since,
        apply=args.apply,
    )


def reencrypt_webhook_secrets(args: argparse.Namespace) -> object:
    from saas_os.core.webhooks.reencryption import reencrypt_legacy_signing_secrets

    return reencrypt_legacy_signing_secrets(
        _uuid(args.tenant, field="--tenant"),
        caller=UserCaller(_uuid(args.operator, field="--operator")),
        reason=_reason(args.reason),
        apply=args.apply,
    )


def apply_permission_grants(args: argparse.Namespace) -> object:
    from saas_os.core.permission_grants import apply_permission_grant_migrations

    if args.all_tenants == (args.tenant is not None):
        raise OperatorInputError("give --tenant or --all-tenants, not both.")
    tenant_ids = [_uuid(args.tenant, field="--tenant")] if args.tenant is not None else []
    caller = UserCaller(_uuid(args.operator, field="--operator"))
    reason = _reason(args.reason)
    migrations = _declared_migrations(args.module)
    result = apply_permission_grant_migrations(
        migrations,  # type: ignore[arg-type]  # validated by Core
        namespace=args.namespace,
        caller=caller,
        reason=reason,
        tenant_ids=tenant_ids,
        all_tenants=args.all_tenants,
        apply=args.apply,
    )
    return {
        "namespace": result.namespace,
        "applied": result.applied,
        "run_id": result.run_id,
        "tenant_outcomes": result.tenant_counts(),
        "failed_tenant_ids": result.failed_tenant_ids,
        "tenants": result.tenants,
    }


def permission_grant_ledger_retention(args: argparse.Namespace) -> object:
    from saas_os.core.permission_grants import permission_grant_ledger_retention_report

    if args.all_purged == (args.tenant is not None):
        raise OperatorInputError("give --tenant or --all-purged, not both.")
    if args.after is not None and not args.all_purged:
        raise OperatorInputError("--after goes with --all-purged.")
    tenant_ids = [_uuid(args.tenant, field="--tenant")] if args.tenant is not None else []
    after = _uuid(args.after, field="--after") if args.after is not None else None
    caller = UserCaller(_uuid(args.operator, field="--operator"))
    report = permission_grant_ledger_retention_report(
        caller=caller,
        reason=_reason(args.reason),
        tenant_ids=tenant_ids,
        all_purged=args.all_purged,
        after=after,
    )
    return {
        "as_of": report.as_of.isoformat(),
        "status_counts": report.status_counts(),
        "eligible_ledger_rows": report.eligible_ledger_rows,
        "eligible_digest": report.eligible_digest,
        "more": report.more,
        "tenants": [
            {
                "tenant_id": t.tenant_id,
                "status": t.status.value,
                "ledger_rows": t.ledger_rows,
                "active_holds": t.active_holds,
                "purged_at": t.purged_at.isoformat() if t.purged_at else None,
                "expires_at": t.expires_at.isoformat() if t.expires_at else None,
            }
            for t in report.tenants
        ],
    }


def _hold_output(result: Any) -> dict[str, object]:
    return {
        "hold_id": result.hold_id,
        "tenant_id": result.tenant_id,
        "reference": result.reference,
        "placed_at": result.placed_at.isoformat(),
        "released_at": result.released_at.isoformat() if result.released_at else None,
        "platform_audit_id": result.platform_audit_id,
    }


def hold_permission_grant_ledger(args: argparse.Namespace) -> object:
    from saas_os.core.permission_grants import place_permission_grant_ledger_hold

    tenant = _uuid(args.tenant, field="--tenant")
    caller = UserCaller(_uuid(args.operator, field="--operator"))
    return _hold_output(
        place_permission_grant_ledger_hold(
            tenant, reference=args.reference, caller=caller, reason=_reason(args.reason)
        )
    )


_COMMANDS: dict[str, Callable[[argparse.Namespace], object]] = {
    "delete-tenant": delete_tenant,
    "move-tenant": move,
    "purge-tenant": purge,
    "erase-user": erase,
    "redact-webhook-errors": redact_webhook_errors,
    "replay-outbox-events": replay_outbox_events,
    "reencrypt-webhook-secrets": reencrypt_webhook_secrets,
    "apply-permission-grants": apply_permission_grants,
    "permission-grant-ledger-retention": permission_grant_ledger_retention,
    "hold-permission-grant-ledger": hold_permission_grant_ledger,
    **AI_COMMANDS,
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="saas-os-operator",
        description=(
            "Destructive platform operations and AI configuration that are not HTTP routes "
            "(ADR-0050, ADR-0054)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--confirm-production", action="store_true")

    p = sub.add_parser("delete-tenant", help="mark a tenant DELETED")
    p.add_argument("--tenant", required=True)
    p.add_argument("--operator", required=True, help="the platform operator's user id")
    p.add_argument("--reason", required=True)
    p.add_argument("--confirm", required=True, help="the tenant id again")
    common(p)

    p = sub.add_parser("move-tenant", help="move a tenant and its subtree")
    p.add_argument("--tenant", required=True)
    p.add_argument("--new-parent")
    p.add_argument("--root", action="store_true")
    p.add_argument("--operator", required=True, help="the platform operator's user id")
    p.add_argument("--reason", required=True)
    common(p)

    p = sub.add_parser("purge-tenant", help="purge a DELETED tenant into its tombstone")
    p.add_argument("--tenant", required=True)
    p.add_argument("--actor", required=True, help="the user id of the person running it")
    p.add_argument("--setup", action="append", help="module:function registering participants")
    p.add_argument("--no-product-participants", action="store_true")
    p.add_argument("--confirm", required=True, help="the tenant id again")
    common(p)

    p = sub.add_parser("erase-user", help="erase a user's identity data")
    p.add_argument("--user", required=True)
    p.add_argument("--tenant", action="append", help="a tenant to remove the user from")
    p.add_argument("--actor", required=True, help="the user id of the person running it")
    p.add_argument("--confirm", required=True, help="the user id again")
    common(p)

    p = sub.add_parser(
        "redact-webhook-errors",
        help="count (or, with --apply, redact) stored webhook errors that carry a URL",
    )
    p.add_argument("--apply", action="store_true", help="rewrite the matches; default counts only")
    common(p)

    p = sub.add_parser(
        "replay-outbox-events",
        help="count (or, with --apply, replay) a tenant's dead-lettered outbox events",
    )
    p.add_argument("--tenant", required=True)
    p.add_argument("--operator", required=True, help="the platform operator's user id")
    p.add_argument("--event-id", action="append", help="a dead-lettered event id (repeatable)")
    p.add_argument("--dead-lettered-since", help="ISO 8601 time with a UTC offset")
    p.add_argument("--reason", required=True)
    p.add_argument("--apply", action="store_true", help="replay the matches; default counts only")
    common(p)

    p = sub.add_parser(
        "reencrypt-webhook-secrets",
        help="count (or, with --apply, encrypt) a tenant's legacy plaintext webhook secrets",
    )
    p.add_argument("--tenant", required=True)
    p.add_argument("--operator", required=True, help="the platform operator's user id")
    p.add_argument("--reason", required=True)
    p.add_argument(
        "--apply", action="store_true", help="re-encrypt the matches; default counts only"
    )
    common(p)

    p = sub.add_parser(
        "apply-permission-grants",
        help="count (or, with --apply, apply) a product's permission grant migrations",
    )
    p.add_argument("--operator", required=True, help="the platform operator's user id")
    p.add_argument("--namespace", required=True, help="the product's migration namespace")
    p.add_argument(
        "--module", required=True, help="module[:ATTRIBUTE] holding the declared migrations"
    )
    p.add_argument("--tenant", help="one tenant id")
    p.add_argument("--all-tenants", action="store_true", help="every open tenant")
    p.add_argument("--reason", required=True)
    p.add_argument("--apply", action="store_true", help="add the grants; default counts only")
    common(p)

    p = sub.add_parser(
        "permission-grant-ledger-retention",
        help="report which tenants' permission grant ledger rows are eligible for expiry",
    )
    p.add_argument("--operator", required=True, help="the platform operator's user id")
    p.add_argument("--tenant", help="one tenant id")
    p.add_argument("--all-purged", action="store_true", help="every PURGED tenant, in id order")
    p.add_argument("--after", help="with --all-purged: continue after this tenant id")
    p.add_argument("--reason", required=True)
    common(p)

    p = sub.add_parser(
        "hold-permission-grant-ledger",
        help="place a legal hold on a tenant's permission grant ledger rows",
    )
    p.add_argument("--operator", required=True, help="the platform operator's user id")
    p.add_argument("--tenant", required=True)
    p.add_argument("--reference", required=True, help="opaque legal matter reference")
    p.add_argument("--reason", required=True)
    common(p)

    add_ai_parsers(sub.add_parser, common)
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
        validate_application_role(get_engine())
        result = _COMMANDS[args.command](args)
    except (OperatorInputError, AICommandInputError) as exc:
        print(f"invalid input: {exc}", file=sys.stderr)
        return _EXIT_USAGE
    except Exception as exc:  # noqa: BLE001 -- every refusal or failure is a non-zero exit
        print(f"failed: {type(exc).__name__}", file=sys.stderr)
        return _EXIT_FAILURE
    print(json.dumps({"command": args.command, "result": _jsonable(result)}, sort_keys=True))
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
