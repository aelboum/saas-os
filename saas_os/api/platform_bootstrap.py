"""Platform owner bootstrap and recovery -- the operator command
(docs/ADR/0045-installation-scoped-platform-authority.md section 6).

    python -m saas_os.api.platform_bootstrap bootstrap \\
        --owner-issuer https://<your-identity-provider> \\
        --owner-subject <the owner's OIDC subject at that issuer> \\
        --reason "initial platform owner"

    python -m saas_os.api.platform_bootstrap recover \\
        --enroll-issuer https://<your-identity-provider> \\
        --enroll-subject <the replacement's OIDC subject> \\
        --grant platform.authority:manage \\
        --suspend-operator <operator id> \\
        --reason "INC-1234: owner account compromised"

**This is not an HTTP capability and never becomes one.** It is a command,
run by whoever operates the deployment, with the deployment's own database
credentials. No router imports this module, and no Core function reachable
from a route accepts the purpose it acts with
(`SystemAuthority.PLATFORM_BOOTSTRAP`).

**What it may do.** `bootstrap` enrolls the first platform owner and grants
the explicit permission list below; it runs once per deployment and
refuses if any platform operator exists. `recover` is break-glass: it may
enroll an operator, grant named permissions and suspend an operator. It
never revokes, never deletes and never reactivates. It is not
provisioning: it creates no tenant, membership or role, and the
provisioning purpose is accepted by none of what it calls.

**Tier-0 trust, stated plainly.** This command is not a security boundary
and adds no protection against the person running it. Whoever can run it
holds the application role's database credentials and could write the same
rows directly, without the lock and without the audit row. What the
command adds is that the legitimate path is the convenient one, takes the
platform-owners lock, cannot leave the deployment without an owner, and
leaves evidence: every change is recorded in `core.platform_audit_log`
with actor type `system`, in the same transaction, and a recovery is
logged at warning level. The audit rows cannot name the person at the
keyboard -- SaaS OS has no way to know who that is -- so `--reason`
should carry the ticket or incident reference that does.

**Atomic.** The command writes nothing itself. It hands the identity to
Core, which resolves it -- and, for an identity the deployment has never
seen, creates the user -- inside the same transaction as the enrollment,
the grants and the audit rows. A refused or failed run therefore leaves
nothing behind: no user, no identity link, no operator, no grant. The only
external dependency is the database; no identity-provider call is made.

**Identity.** A user is keyed on the OIDC `(issuer, subject)` pair. The
issuer given must equal the deployment's configured `OIDC_ISSUER_URL`: an
operator enrolled under any other issuer could never log in, and a typo
must not create a second, unreachable identity. Neither value is a secret,
and neither is ever written to the audit table.

**Runtime role.** Runs as the restricted application role
(`validate_application_role`), never the migrations role.

**Production.** `ENVIRONMENT=production` requires `--confirm-production`.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import uuid
from collections.abc import Sequence
from urllib.parse import urlsplit

from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.config import get_settings
from saas_os.core.platform_authority import (
    OperatorIdentity,
    PlatformBootstrapResult,
    PlatformPermission,
    PlatformRecoveryResult,
    bootstrap_platform_owner,
    recover_platform_authority,
)
from saas_os.infra.db import get_engine, validate_application_role
from saas_os.infra.observability import configure_logging
from saas_os.infra.secrets import get_secrets_provider

logger = logging.getLogger(__name__)

# The explicit, literal, reviewed list the first platform owner receives.
# It is NOT computed from the vocabulary: adding a permission to
# `PlatformPermission` changes nothing about what bootstrap grants, and
# grants nothing to any existing operator.
#
# It holds all eighteen permissions because, at bootstrap, nobody exists who
# could grant a missing one, and anti-amplification would leave it
# ungrantable from inside. A permission added later must be placed, by a
# reviewer, in exactly one of the two tuples below;
# `tests/api/test_platform_bootstrap_unit.py` fails until it is.
BOOTSTRAP_PERMISSIONS: tuple[PlatformPermission, ...] = (
    PlatformPermission.TENANT_READ,
    PlatformPermission.USER_READ,
    PlatformPermission.OPERATOR_READ,
    PlatformPermission.AUDIT_READ,
    PlatformPermission.BILLING_READ,
    PlatformPermission.FEATURE_FLAG_READ,
    PlatformPermission.TENANT_CREATE,
    PlatformPermission.TENANT_SUSPEND,
    PlatformPermission.TENANT_REACTIVATE,
    PlatformPermission.TENANT_MOVE,
    PlatformPermission.TENANT_DELETE,
    PlatformPermission.USER_DEACTIVATE,
    PlatformPermission.USER_REACTIVATE,
    PlatformPermission.SESSION_REVOKE,
    PlatformPermission.API_KEY_REVOKE,
    PlatformPermission.FEATURE_FLAG_DEFINE,
    PlatformPermission.FEATURE_FLAG_OVERRIDE,
    PlatformPermission.AUTHORITY_MANAGE,
)
NOT_GRANTED_AT_BOOTSTRAP: tuple[PlatformPermission, ...] = ()

_PLATFORM_BOOTSTRAP = SystemCaller(SystemAuthority.PLATFORM_BOOTSTRAP)

_ISSUER_VAR = "OIDC_ISSUER_URL"
_MAX_ISSUER_LENGTH = 2048  # core.external_identities.issuer String(2048)
_MAX_SUBJECT_LENGTH = 255  # core.external_identities.subject String(255)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s")

_EXIT_OK = 0
_EXIT_FAILURE = 1
_EXIT_USAGE = 2


class PlatformBootstrapError(RuntimeError):
    """Every failure this module raises deliberately. Messages name inputs
    by *field*, never by value, and never wrap a database driver message."""


class PlatformBootstrapInputError(PlatformBootstrapError):
    """An operator input failed validation. Nothing was read or written."""


class PlatformBootstrapListError(PlatformBootstrapError):
    """The bootstrap permission literals do not fit the declared
    vocabulary. A defect in this module, caught before any write."""


# --- Validation (pure) --------------------------------------------------------


def validate_bootstrap_list() -> tuple[PlatformPermission, ...]:
    """Check the two literals against the vocabulary, before anything is
    opened: every entry a `PlatformPermission`, no duplicates, the two
    tuples disjoint, their union exactly the vocabulary, and the list
    includes `platform.authority:manage`. Returns the bootstrap list."""
    for name, values in (
        ("BOOTSTRAP_PERMISSIONS", BOOTSTRAP_PERMISSIONS),
        ("NOT_GRANTED_AT_BOOTSTRAP", NOT_GRANTED_AT_BOOTSTRAP),
    ):
        for value in values:
            if not isinstance(value, PlatformPermission):
                raise PlatformBootstrapListError(
                    f"{name} contains an entry that is not a platform permission."
                )
        if len(set(values)) != len(values):
            raise PlatformBootstrapListError(f"{name} contains a duplicate.")
    granted, withheld = set(BOOTSTRAP_PERMISSIONS), set(NOT_GRANTED_AT_BOOTSTRAP)
    if granted & withheld:
        raise PlatformBootstrapListError(
            "a permission is listed both as granted and as not granted at bootstrap."
        )
    if granted | withheld != set(PlatformPermission):
        raise PlatformBootstrapListError(
            "the bootstrap lists do not cover the platform-permission vocabulary exactly: "
            "every permission must be placed in exactly one of them."
        )
    if PlatformPermission.AUTHORITY_MANAGE not in granted:
        raise PlatformBootstrapListError("the bootstrap list must grant platform.authority:manage.")
    return BOOTSTRAP_PERMISSIONS


def _validate_text(raw: object, *, field: str, max_length: int) -> str:
    if not isinstance(raw, str):
        raise PlatformBootstrapInputError(f"{field} must be a string.")
    value = raw.strip()
    if not value:
        raise PlatformBootstrapInputError(f"{field} must not be empty.")
    if len(value) > max_length:
        raise PlatformBootstrapInputError(f"{field} exceeds {max_length} characters.")
    if _CONTROL_CHARACTERS.search(value):
        raise PlatformBootstrapInputError(f"{field} must not contain control characters.")
    return value


def validate_identity(issuer: object, subject: object) -> tuple[str, str]:
    """A plausible OIDC `(issuer, subject)` pair. Pure -- no I/O. The issuer
    is normalized exactly as `saas_os.core.identity.provider` normalizes it."""
    issuer_value = _validate_text(issuer, field="issuer", max_length=_MAX_ISSUER_LENGTH)
    if _WHITESPACE.search(issuer_value):
        raise PlatformBootstrapInputError("issuer must not contain whitespace.")
    parts = urlsplit(issuer_value)
    if parts.scheme not in ("https", "http") or not parts.netloc or parts.query or parts.fragment:
        raise PlatformBootstrapInputError(
            "issuer must be the identity provider's issuer URL "
            "(https://host[/path], no query/fragment)."
        )
    subject_value = _validate_text(subject, field="subject", max_length=_MAX_SUBJECT_LENGTH)
    if _WHITESPACE.search(subject_value):
        raise PlatformBootstrapInputError("subject must not contain whitespace.")
    return issuer_value.rstrip("/"), subject_value


def parse_permissions(values: Sequence[str]) -> tuple[PlatformPermission, ...]:
    """`--grant` values: each must be exactly one member of the closed
    vocabulary. No wildcard, no bundle, no "all"."""
    parsed: list[PlatformPermission] = []
    for value in values:
        try:
            permission = PlatformPermission(value)
        except ValueError:
            raise PlatformBootstrapInputError(
                "--grant must name exactly one platform permission from the vocabulary "
                "(for example platform.authority:manage); there is no wildcard."
            ) from None
        if permission in parsed:
            raise PlatformBootstrapInputError("--grant names the same permission twice.")
        parsed.append(permission)
    return tuple(parsed)


def _parse_operator_id(raw: object) -> uuid.UUID:
    try:
        return uuid.UUID(str(raw))
    except ValueError:
        raise PlatformBootstrapInputError("--suspend-operator must be an operator id.") from None


def _require_configured_issuer(issuer: str) -> None:
    """The issuer must be the deployment's own. Read directly from the
    configuration: this command must not need the identity provider to be
    reachable (the provider configuration's own accessor fetches its
    discovery document)."""
    configured = get_secrets_provider().get(_ISSUER_VAR)
    if not configured or not configured.strip():
        raise PlatformBootstrapError(
            f"{_ISSUER_VAR} is not configured; refusing to enroll an operator for an issuer "
            "this deployment could not authenticate."
        )
    if configured.strip().rstrip("/") != issuer:
        raise PlatformBootstrapInputError(
            f"issuer does not match this deployment's configured {_ISSUER_VAR}."
        )


# --- Operations ---------------------------------------------------------------


def bootstrap_owner(issuer: str, subject: str, *, reason: str) -> PlatformBootstrapResult:
    """Enroll the first platform owner. Fails closed at each step, in this
    order, before the next: the bootstrap lists; the runtime role; the
    issuer. Nothing is written here: Core resolves or creates the user in
    the same transaction as the enrollment, so a refused or failed
    bootstrap leaves no user and no identity link."""
    permissions = validate_bootstrap_list()
    validate_application_role(get_engine())
    _require_configured_issuer(issuer)
    logger.info("platform_bootstrap_started")
    result = bootstrap_platform_owner(
        OperatorIdentity(issuer, subject),
        permissions,
        caller=_PLATFORM_BOOTSTRAP,
        reason=reason,
    )
    logger.info(
        "platform_bootstrap_completed",
        extra={
            "operator_id": str(result.operator_id),
            "user_id": str(result.user_id),
            "newly_enrolled": result.created,
        },
    )
    return result


def recover(
    *,
    reason: str,
    enroll_identity: tuple[str, str] | None = None,
    grant_permissions: Sequence[PlatformPermission] = (),
    suspend_operator_id: uuid.UUID | None = None,
) -> PlatformRecoveryResult:
    """Break-glass recovery: one transaction in Core, under the
    platform-owners lock, refused if it would leave no platform owner."""
    validate_application_role(get_engine())
    identity: OperatorIdentity | None = None
    if enroll_identity is not None:
        issuer, subject = enroll_identity
        _require_configured_issuer(issuer)
        identity = OperatorIdentity(issuer, subject)
    logger.warning(
        "platform_recovery_started",
        extra={
            "enroll": identity is not None,
            "grant_count": len(grant_permissions),
            "suspend": suspend_operator_id is not None,
        },
    )
    result = recover_platform_authority(
        caller=_PLATFORM_BOOTSTRAP,
        reason=reason,
        enroll_identity=identity,
        grant_permissions=tuple(grant_permissions),
        suspend_operator_id=suspend_operator_id,
    )
    logger.warning(
        "platform_recovery_completed",
        extra={
            "enrolled_operator_id": str(result.enrolled_operator_id)
            if result.enrolled_operator_id is not None
            else None,
            "enrolled": result.enrolled,
            "granted": list(result.granted),
            "suspended_operator_id": str(result.suspended_operator_id)
            if result.suspended_operator_id is not None
            else None,
        },
    )
    return result


# --- CLI ----------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m saas_os.api.platform_bootstrap",
        description=(
            "Bootstrap the first platform owner, or recover platform authority "
            "(docs/ADR/0045). An operator command; never an HTTP capability."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--reason",
            required=True,
            help="Why this is being done; recorded in the platform audit log. Use the ticket "
            "or incident reference: the audit row cannot name the person running the command.",
        )
        sub.add_argument(
            "--confirm-production",
            action="store_true",
            help="Required when ENVIRONMENT=production.",
        )

    bootstrap = commands.add_parser(
        "bootstrap", help="Enroll the first platform owner. Runs once per deployment."
    )
    bootstrap.add_argument("--owner-issuer", required=True, help="The exact OIDC issuer URL.")
    bootstrap.add_argument(
        "--owner-subject", required=True, help="The owner's OIDC subject (`sub`); not a secret."
    )
    common(bootstrap)

    recovery = commands.add_parser(
        "recover",
        help="Break-glass: enroll an operator, grant named permissions, suspend an operator. "
        "Never revokes, deletes or reactivates.",
    )
    recovery.add_argument("--enroll-issuer", help="Issuer of the identity to enroll.")
    recovery.add_argument("--enroll-subject", help="Subject of the identity to enroll.")
    recovery.add_argument(
        "--grant",
        action="append",
        default=[],
        metavar="PERMISSION",
        help="One platform permission to grant to the enrolled operator. Repeatable. No wildcard.",
    )
    recovery.add_argument("--suspend-operator", metavar="OPERATOR_ID", help="Operator to suspend.")
    common(recovery)
    return parser


def _print_bootstrap(result: PlatformBootstrapResult) -> None:
    status = "OK" if result.created else "no-op (already bootstrapped identically)"
    print("platform owner bootstrap: " + status)
    print(f"operator id:  {result.operator_id}")
    print(f"user id:      {result.user_id}")
    print(f"permissions:  {len(result.permissions)}")
    for permission in result.permissions:
        print(f"  - {permission}")


def _print_recovery(result: PlatformRecoveryResult) -> None:
    print("platform recovery: " + ("OK" if result.changed else "no-op (nothing to change)"))
    if result.enrolled_operator_id is not None:
        kind = "enrolled" if result.enrolled else "existing operator"
        print(f"operator id:  {result.enrolled_operator_id} ({kind})")
    print("granted:      " + (", ".join(result.granted) if result.granted else "nothing"))
    if result.suspended_operator_id is not None:
        print(f"suspended:    {result.suspended_operator_id}")


def main(argv: list[str] | None = None) -> int:
    """Process entrypoint. Exit codes: 0 success (including an idempotent
    no-op), 1 a refused or failed operation, 2 usage, invalid input or a
    missing production confirmation. Neither a database URL, a secret nor
    an identity's issuer or subject is printed or logged."""
    configure_logging()
    parser = _build_parser()
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:  # argparse already printed usage/help
        return int(exc.code) if isinstance(exc.code, int) else _EXIT_USAGE

    try:
        if args.command == "bootstrap":
            identity = validate_identity(args.owner_issuer, args.owner_subject)
            grants: tuple[PlatformPermission, ...] = ()
            suspend_id = None
        else:
            if bool(args.enroll_issuer) != bool(args.enroll_subject):
                raise PlatformBootstrapInputError(
                    "--enroll-issuer and --enroll-subject must be given together."
                )
            identity = (
                validate_identity(args.enroll_issuer, args.enroll_subject)
                if args.enroll_issuer
                else None
            )
            grants = parse_permissions(args.grant)
            suspend_id = (
                _parse_operator_id(args.suspend_operator)
                if args.suspend_operator is not None
                else None
            )
            if identity is None and suspend_id is None:
                raise PlatformBootstrapInputError(
                    "recover must enroll an operator, suspend an operator, or both."
                )
            if grants and identity is None:
                raise PlatformBootstrapInputError("--grant requires an identity to enroll.")
        reason = _validate_text(args.reason, field="reason", max_length=500)
    except PlatformBootstrapInputError as exc:
        print(f"invalid input: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    if get_settings().environment == "production" and not args.confirm_production:
        print(
            "ENVIRONMENT=production: refusing to change platform authority without "
            "--confirm-production.",
            file=sys.stderr,
        )
        logger.error("platform_bootstrap_refused", extra={"reason": "production_confirmation"})
        return _EXIT_USAGE

    try:
        if args.command == "bootstrap":
            assert identity is not None
            _print_bootstrap(bootstrap_owner(identity[0], identity[1], reason=reason))
        else:
            _print_recovery(
                recover(
                    reason=reason,
                    enroll_identity=identity,
                    grant_permissions=grants,
                    suspend_operator_id=suspend_id,
                )
            )
        return _EXIT_OK
    except PlatformBootstrapInputError as exc:
        print(f"invalid input: {exc}", file=sys.stderr)
        return _EXIT_USAGE
    except (PlatformBootstrapError, PermissionError, ValueError, LookupError) as exc:
        # Core's typed refusals and state errors: identifiers only.
        print(f"refused: {exc}", file=sys.stderr)
        logger.error("platform_bootstrap_failed", extra={"error_type": type(exc).__name__})
        return _EXIT_FAILURE
    except Exception as exc:  # noqa: BLE001 -- type name only: a driver message could carry a DSN
        print(f"failed: {type(exc).__name__}", file=sys.stderr)
        logger.error("platform_bootstrap_failed", extra={"error_type": type(exc).__name__})
        return _EXIT_FAILURE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
