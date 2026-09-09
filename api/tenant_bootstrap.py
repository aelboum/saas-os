"""First-tenant bootstrap (post-audit F-02) -- the operator command that
provisions the platform's first tenant and its owner, deterministically,
auditably, and without a network surface:

    python -m api.tenant_bootstrap \\
        --tenant-name "Acme Ltd" \\
        --owner-issuer https://<your-zitadel-instance> \\
        --owner-subject <the owner's OIDC subject at that issuer> \\
        [--dry-run] [--confirm-production]

**Placement**: `api/` is this repository's composition root for runtime
processes (`api/server.py`, `api/worker.py`) -- the one layer that may
compose `core.tenancy`, `core.identity`, `core.rbac`, and `core.audit_log`
together. Those Core modules cannot host this themselves: `core.rbac`
already depends on `core.identity` and `core.tenancy`, so a bootstrap
inside either of them would create an import cycle. The existing
import-linter contracts apply unchanged (`api` never imports `products`
or `control_plane`).

**Nothing new underneath**: every mutation goes through the existing,
tested Core service functions -- `create_tenant`/`transition_tenant_status`
(tenancy), `get_or_create_user_for_external_identity`/`add_tenant_membership`
(identity), `register_permission`/`create_role`/`grant_permission`/
`assign_role` (rbac), `core.audit_log.record` (audit) -- each running as
the restricted, RLS-enforced application role through
`infra.db.session_scope()`/`tenant_session_scope()` exactly as the HTTP
process does. No table is touched directly, no SQL is written here, and
`infra.db.validate_application_role()` (P1.2) runs first so an unsafe
(superuser/BYPASSRLS) `DATABASE_URL` refuses to bootstrap at all. The
one Core addition F-02 needed, `core.tenancy.find_tenants_by_name()`, is a
read.

**Owner identity**: the existing identity model keys a user on the OIDC
`(issuer, subject)` pair (`core.identity.ExternalIdentity`). The operator
supplies exactly those two values -- never a password, never a token,
never an authorization code. `--owner-issuer` must be the *exact* `iss`
the identity provider puts in its ID tokens (ZITADEL: the instance URL,
no trailing slash -- `core.identity.provider` strips one, and so does this
module); on the owner's first login, `api/auth/routes.py` resolves the
very same pair to the very same user row this bootstrap created.

**Step order is the safety argument** (there is no single transaction
across Core services, and none is invented): every step before the last
produces only *inert* state, and the last step is the only one that
confers authority --

    1. tenant           (registry row; a tenant with no members grants nothing)
    2. activation       (`pending -> active`; status gates nothing in `can()`)
    3. owner user       (a bare `core.users` row grants nothing)
    4. `owner` role     (a role with no assignment grants nothing)
    5. permission grants to that role (still unassigned -> nothing)
    6. owner membership (member with no role -> `can()` denies everything)
    7. role assignment  <- authority appears here, and only here
    8. verification     (`core.rbac.can()` for every granted permission)

A failure at any step leaves no privilege behind. Re-running the same
command *resumes*: each step is find-or-create against the existing
uniqueness rules (`uq_external_identities_issuer_subject`,
`uq_roles_tenant_name`, `uq_tenant_memberships_tenant_user`,
`uq_role_permissions_role_permission`, `uq_membership_roles_membership_role`)
plus the tenant-name rule below, so the second identical run is a
deterministic no-op and a crashed first run is completed, never
duplicated. That is both the idempotency and the recovery story.

**Tenant-name rule** (`core.tenants.name` is a display name with no
uniqueness constraint): a run whose `--tenant-name` matches exactly one
existing tenant resumes it only if that tenant has no members yet, or
this owner identity is already one of its members; if it has other
members, or two or more tenants share the name, the run refuses with a
conflict -- never a silent second tenant, never a claim on someone else's
tenant. A suspended/deleted tenant is never resurrected by this command.

**Least privilege**: the `owner` role receives exactly the permissions the
external API enforces today (`FIRST_TENANT_OWNER_PERMISSIONS`, pinned by
a unit test to the routes' own `RESOURCE`/`ACTION` constants so the two
cannot drift) -- no AI Control Plane tool permission, no platform-wide
authority, nothing speculative. Adding a route means adding its
permission here deliberately.

**Production confirmation**: when `ENVIRONMENT=production`
(`core.config.get_settings()`, the existing mechanism), the command
refuses to run -- before any database access -- unless
`--confirm-production` is passed. `--dry-run` validates the inputs and
reports what a real run would do (read-only) in any environment.

**What is never printed or logged**: the database URL, any secret, any
token. Structured log events carry identifiers only.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.config import get_settings

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.identity import (
    add_tenant_membership,
    find_external_identity,
    get_membership,
    get_or_create_user_for_external_identity,
    list_tenant_members,
)
from core.rbac import (
    DuplicateRoleNameError,
    assign_role,
    can,
    create_role,
    get_membership_role,
    get_role_permission,
    grant_permission,
    list_roles,
    register_permission,
)
from core.tenancy import (
    Tenant,
    TenantStatus,
    create_tenant,
    find_tenants_by_name,
    transition_tenant_status,
)
from infra.db import get_engine, validate_application_role
from infra.observability import configure_logging

logger = logging.getLogger(__name__)

FIRST_TENANT_OWNER_ROLE_NAME = "owner"

# Exactly what the external API enforces today (module docstring, "Least
# privilege") -- one entry per `require_permission(RESOURCE, ACTION)` route
# (`api/v1/tenant_status.py`). Written out literally rather than imported
# from the route module: importing `api.v1` pulls in the whole route graph,
# whose Core job registrations resolve `REDIS_URL` at import time, and this
# command must be able to print `--help`, validate inputs, and apply the
# production gate without queue configuration.
# `tests/api/test_tenant_bootstrap_unit.py` pins this tuple to the routes'
# own `RESOURCE`/`ACTION` constants so the two cannot drift.
FIRST_TENANT_OWNER_PERMISSIONS: tuple[tuple[str, str], ...] = (("tenant", "read_status"),)

_MAX_TENANT_NAME_LENGTH = 255  # core.tenants.name String(255)
_MAX_ISSUER_LENGTH = 2048  # core.external_identities.issuer String(2048)
_MAX_SUBJECT_LENGTH = 255  # core.external_identities.subject String(255)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s")

_EXIT_OK = 0
_EXIT_FAILURE = 1
_EXIT_USAGE = 2


class BootstrapError(RuntimeError):
    """Base class: every failure this module raises deliberately. Messages
    name inputs by *field*, never by value, and never wrap a database
    driver message."""


class BootstrapInputError(BootstrapError):
    """An operator input failed validation."""


class BootstrapConflictError(BootstrapError):
    """The requested bootstrap would collide with existing tenant state
    (module docstring, "Tenant-name rule") -- refused, nothing changed."""


class ProductionConfirmationRequiredError(BootstrapError):
    """`ENVIRONMENT=production` without `--confirm-production`."""


class BootstrapVerificationError(BootstrapError):
    """Provisioning completed but the owner's authority could not be
    confirmed through `core.rbac.can()` -- treated as a failure."""


@dataclass(frozen=True)
class BootstrapRequest:
    """Validated operator inputs -- construct via `validate_request()`."""

    tenant_name: str
    owner_issuer: str
    owner_subject: str


@dataclass(frozen=True)
class BootstrapResult:
    tenant_id: uuid.UUID
    tenant_status: str
    owner_user_id: uuid.UUID
    membership_id: uuid.UUID
    role_id: uuid.UUID
    role_name: str
    permissions: tuple[str, ...]
    # Which steps performed a mutation in *this* run (a resumed/idempotent
    # run reports fewer). Names only, never values.
    created: tuple[str, ...]

    @property
    def was_noop(self) -> bool:
        return not self.created


@dataclass(frozen=True)
class BootstrapPlan:
    """What `--dry-run` reports: read-only assessment of existing state."""

    request: BootstrapRequest
    matching_tenants: int
    tenant_id: uuid.UUID | None
    tenant_status: str | None
    tenant_member_count: int | None
    owner_identity_known: bool
    owner_already_member: bool
    would_create: tuple[str, ...]


# --- Input validation (pure) --------------------------------------------------


def validate_request(tenant_name: str, owner_issuer: str, owner_subject: str) -> BootstrapRequest:
    """Fail closed on anything that is not a plausible tenant name and a
    plausible OIDC `(issuer, subject)` pair. Pure -- no I/O."""
    name = _validate_text(tenant_name, field="tenant name", max_length=_MAX_TENANT_NAME_LENGTH)

    issuer = _validate_text(owner_issuer, field="owner issuer", max_length=_MAX_ISSUER_LENGTH)
    if _WHITESPACE.search(issuer):
        raise BootstrapInputError("owner issuer must not contain whitespace.")
    parts = urlsplit(issuer)
    if parts.scheme not in ("https", "http") or not parts.netloc or parts.query or parts.fragment:
        raise BootstrapInputError(
            "owner issuer must be the identity provider's issuer URL "
            "(https://host[/path], no query/fragment)."
        )
    issuer = issuer.rstrip("/")  # matches core.identity.provider's own normalization

    subject = _validate_text(owner_subject, field="owner subject", max_length=_MAX_SUBJECT_LENGTH)
    if _WHITESPACE.search(subject):
        raise BootstrapInputError("owner subject must not contain whitespace.")

    return BootstrapRequest(tenant_name=name, owner_issuer=issuer, owner_subject=subject)


def _validate_text(raw: object, *, field: str, max_length: int) -> str:
    if not isinstance(raw, str):
        raise BootstrapInputError(f"{field} must be a string.")
    value = raw.strip()
    if not value:
        raise BootstrapInputError(f"{field} must not be empty.")
    if len(value) > max_length:
        raise BootstrapInputError(f"{field} exceeds {max_length} characters.")
    if _CONTROL_CHARACTERS.search(value):
        raise BootstrapInputError(f"{field} must not contain control characters.")
    return value


# --- Provisioning steps (each find-or-create) ---------------------------------


def _audit(
    tenant_id: uuid.UUID,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    metadata: dict[str, object] | None = None,
) -> None:
    """One `core.audit_log` entry per privileged mutation this bootstrap
    performs, attributed to the SYSTEM actor (an operator command, not a
    logged-in user). Metadata carries identifiers only -- never the
    issuer/subject pair, a credential, or a token."""
    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.SYSTEM,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=AuditOutcome.SUCCESS,
        metadata={"bootstrap": "first_tenant", **(metadata or {})},
    )


def _resolve_tenant(request: BootstrapRequest) -> tuple[Tenant, bool]:
    """The tenant-name rule (module docstring). Returns `(tenant, created)`."""
    matches = find_tenants_by_name(request.tenant_name)
    if len(matches) > 1:
        raise BootstrapConflictError(
            "more than one tenant already carries this tenant name -- refusing to choose; "
            "resolve the ambiguity before bootstrapping."
        )
    if not matches:
        tenant = create_tenant(request.tenant_name)
        _audit(
            tenant.id,
            action="tenant.bootstrap_created",
            resource_type="tenant",
            resource_id=str(tenant.id),
        )
        return tenant, True

    tenant = matches[0]
    if tenant.status not in (TenantStatus.PENDING.value, TenantStatus.ACTIVE.value):
        raise BootstrapConflictError(
            f"a tenant with this name exists in status {tenant.status!r} -- this command never "
            "resurrects a suspended or deleted tenant."
        )
    members = list_tenant_members(tenant.id)
    if members:
        identity = find_external_identity(request.owner_issuer, request.owner_subject)
        already_member = identity is not None and any(
            m.user_id == identity.user_id for m in members
        )
        if not already_member:
            raise BootstrapConflictError(
                "a tenant with this name already exists and has members that are not this "
                "owner identity -- refusing to create a duplicate or to claim it."
            )
    return tenant, False


def _ensure_active(tenant: Tenant) -> tuple[Tenant, bool]:
    if tenant.status == TenantStatus.ACTIVE.value:
        return tenant, False
    activated = transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    _audit(
        tenant.id,
        action="tenant.activated",
        resource_type="tenant",
        resource_id=str(tenant.id),
        metadata={"from_status": tenant.status, "to_status": activated.status},
    )
    return activated, True


def _ensure_owner_role(tenant_id: uuid.UUID) -> tuple[uuid.UUID, bool]:
    for role in list_roles(tenant_id):
        if role.name == FIRST_TENANT_OWNER_ROLE_NAME:
            return role.id, False
    try:
        role = create_role(tenant_id, FIRST_TENANT_OWNER_ROLE_NAME)
    except DuplicateRoleNameError:
        # Lost a race with a concurrent run: the other run's row is canonical.
        for role in list_roles(tenant_id):
            if role.name == FIRST_TENANT_OWNER_ROLE_NAME:
                return role.id, False
        raise
    _audit(
        tenant_id,
        action="rbac.role_created",
        resource_type="role",
        resource_id=str(role.id),
        metadata={"role_name": FIRST_TENANT_OWNER_ROLE_NAME},
    )
    return role.id, True


def _ensure_permission_grants(tenant_id: uuid.UUID, role_id: uuid.UUID) -> list[str]:
    granted: list[str] = []
    for resource, action in FIRST_TENANT_OWNER_PERMISSIONS:
        permission = register_permission(resource, action)  # idempotent, global catalog
        if get_role_permission(tenant_id, role_id, permission.id) is not None:
            continue
        grant_permission(tenant_id, role_id, permission.id)
        label = f"{resource}:{action}"
        _audit(
            tenant_id,
            action="rbac.permission_granted",
            resource_type="role",
            resource_id=str(role_id),
            metadata={"permission": label},
        )
        granted.append(label)
    return granted


def _ensure_membership(tenant_id: uuid.UUID, user_id: uuid.UUID) -> tuple[uuid.UUID, bool]:
    existing = get_membership(tenant_id, user_id)
    if existing is not None:
        return existing.id, False
    membership = add_tenant_membership(tenant_id, user_id)
    _audit(
        tenant_id,
        action="tenant.owner_membership_created",
        resource_type="tenant_membership",
        resource_id=str(membership.id),
        metadata={"user_id": str(user_id)},
    )
    return membership.id, True


def _ensure_role_assignment(
    tenant_id: uuid.UUID, membership_id: uuid.UUID, role_id: uuid.UUID
) -> bool:
    if get_membership_role(tenant_id, membership_id, role_id) is not None:
        return False
    assign_role(tenant_id, membership_id, role_id)
    _audit(
        tenant_id,
        action="rbac.role_assigned",
        resource_type="tenant_membership",
        resource_id=str(membership_id),
        metadata={"role_id": str(role_id), "role_name": FIRST_TENANT_OWNER_ROLE_NAME},
    )
    return True


def _verify_owner_authority(user_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    """The same chokepoint the HTTP layer uses -- `core.rbac.can()` -- must
    now say yes for every granted permission, or the run is a failure."""
    for resource, action in FIRST_TENANT_OWNER_PERMISSIONS:
        if not can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource):
            raise BootstrapVerificationError(
                f"owner authority could not be verified for {resource}:{action} after "
                "provisioning -- refusing to report success."
            )


# --- Public entry points ----------------------------------------------------------


def assess_bootstrap(request: BootstrapRequest) -> BootstrapPlan:
    """`--dry-run`: read-only. Applies the tenant-name rule without
    mutating anything and reports which steps a real run would perform."""
    validate_application_role(get_engine())
    matches = find_tenants_by_name(request.tenant_name)
    identity = find_external_identity(request.owner_issuer, request.owner_subject)

    if len(matches) > 1:
        raise BootstrapConflictError(
            "more than one tenant already carries this tenant name -- refusing to choose."
        )
    if not matches:
        return BootstrapPlan(
            request=request,
            matching_tenants=0,
            tenant_id=None,
            tenant_status=None,
            tenant_member_count=None,
            owner_identity_known=identity is not None,
            owner_already_member=False,
            would_create=(
                "tenant",
                "activation",
                "owner_user" if identity is None else "owner_user (existing)",
                "owner_role",
                "permission_grants",
                "owner_membership",
                "role_assignment",
            ),
        )

    tenant = matches[0]
    members = list_tenant_members(tenant.id)
    already_member = identity is not None and any(m.user_id == identity.user_id for m in members)
    if tenant.status not in (TenantStatus.PENDING.value, TenantStatus.ACTIVE.value):
        raise BootstrapConflictError(
            f"a tenant with this name exists in status {tenant.status!r} -- refusing."
        )
    if members and not already_member:
        raise BootstrapConflictError(
            "a tenant with this name already exists and has members that are not this "
            "owner identity -- refusing."
        )
    would: list[str] = []
    if tenant.status != TenantStatus.ACTIVE.value:
        would.append("activation")
    if identity is None:
        would.append("owner_user")
    if not any(r.name == FIRST_TENANT_OWNER_ROLE_NAME for r in list_roles(tenant.id)):
        would.append("owner_role")
    would.append("permission_grants (any missing)")
    if not already_member:
        would.append("owner_membership")
    would.append("role_assignment (if missing)")
    return BootstrapPlan(
        request=request,
        matching_tenants=1,
        tenant_id=tenant.id,
        tenant_status=tenant.status,
        tenant_member_count=len(members),
        owner_identity_known=identity is not None,
        owner_already_member=already_member,
        would_create=tuple(would),
    )


def bootstrap_first_tenant(request: BootstrapRequest) -> BootstrapResult:
    """Provision (or resume provisioning of) the first tenant and its
    owner -- module docstring for the step order and its safety argument."""
    validate_application_role(get_engine())  # fail closed: never as a superuser/BYPASSRLS role
    logger.info("tenant_bootstrap_started")

    created: list[str] = []
    tenant, tenant_created = _resolve_tenant(request)
    if tenant_created:
        created.append("tenant")
    tenant, activated = _ensure_active(tenant)
    if activated:
        created.append("activation")

    identity_known = find_external_identity(request.owner_issuer, request.owner_subject)
    user = get_or_create_user_for_external_identity(request.owner_issuer, request.owner_subject)
    if identity_known is None:
        created.append("owner_user")

    role_id, role_created = _ensure_owner_role(tenant.id)
    if role_created:
        created.append("owner_role")
    created.extend(f"grant:{label}" for label in _ensure_permission_grants(tenant.id, role_id))

    membership_id, membership_created = _ensure_membership(tenant.id, user.id)
    if membership_created:
        created.append("owner_membership")
    if _ensure_role_assignment(tenant.id, membership_id, role_id):
        created.append("role_assignment")

    _verify_owner_authority(user.id, tenant.id)

    result = BootstrapResult(
        tenant_id=tenant.id,
        tenant_status=tenant.status,
        owner_user_id=user.id,
        membership_id=membership_id,
        role_id=role_id,
        role_name=FIRST_TENANT_OWNER_ROLE_NAME,
        permissions=tuple(f"{r}:{a}" for r, a in FIRST_TENANT_OWNER_PERMISSIONS),
        created=tuple(created),
    )
    logger.info(
        "tenant_bootstrap_completed",
        extra={
            "tenant_id": str(result.tenant_id),
            "owner_user_id": str(result.owner_user_id),
            "role_id": str(result.role_id),
            "created_steps": list(result.created),
        },
    )
    return result


# --- CLI ------------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m api.tenant_bootstrap",
        description="Provision the platform's first tenant and its owner (docs/RUNBOOKS.md).",
    )
    parser.add_argument("--tenant-name", required=True, help="Display name of the tenant.")
    parser.add_argument(
        "--owner-issuer",
        required=True,
        help="The identity provider's exact OIDC issuer URL (ZITADEL: the instance URL).",
    )
    parser.add_argument(
        "--owner-subject",
        required=True,
        help="The owner's OIDC subject (`sub`) at that issuer -- an identifier, never a secret.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and report what a real run would do; changes nothing.",
    )
    parser.add_argument(
        "--confirm-production",
        action="store_true",
        help="Required when ENVIRONMENT=production: an explicit acknowledgement that this "
        "creates persistent tenant state in production.",
    )
    return parser


def _print_plan(plan: BootstrapPlan) -> None:
    print("DRY RUN -- nothing was changed.")
    print(f"tenant name:            {plan.request.tenant_name}")
    print(f"matching tenants:       {plan.matching_tenants}")
    if plan.tenant_id is not None:
        print(f"existing tenant id:     {plan.tenant_id}")
        print(f"existing tenant status: {plan.tenant_status}")
        print(f"existing member count:  {plan.tenant_member_count}")
    print(f"owner identity known:   {'yes' if plan.owner_identity_known else 'no'}")
    print(f"owner already member:   {'yes' if plan.owner_already_member else 'no'}")
    print("a real run would perform:")
    for step in plan.would_create:
        print(f"  - {step}")


def _print_result(result: BootstrapResult) -> None:
    print("first-tenant bootstrap: " + ("no-op (already provisioned)" if result.was_noop else "OK"))
    print(f"tenant id:      {result.tenant_id}")
    print(f"tenant status:  {result.tenant_status}")
    print(f"owner user id:  {result.owner_user_id}")
    print(f"membership id:  {result.membership_id}")
    print(f"owner role:     {result.role_name} ({result.role_id})")
    print(f"permissions:    {', '.join(result.permissions)}")
    print("performed:      " + (", ".join(result.created) if result.created else "nothing"))


def main(argv: list[str] | None = None) -> int:
    """Process entrypoint (`python -m api.tenant_bootstrap`). Exit codes:
    0 success (including an idempotent no-op), 1 a refused/failed
    bootstrap, 2 usage or missing production confirmation. Neither a
    database URL nor any secret is ever printed."""
    configure_logging()
    parser = _build_parser()
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:  # argparse already printed usage/help
        return int(exc.code) if isinstance(exc.code, int) else _EXIT_USAGE

    try:
        request = validate_request(args.tenant_name, args.owner_issuer, args.owner_subject)
    except BootstrapInputError as exc:
        print(f"invalid input: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    environment = get_settings().environment
    if environment == "production" and not args.dry_run and not args.confirm_production:
        print(
            "ENVIRONMENT=production: refusing to create tenant state without "
            "--confirm-production (docs/RUNBOOKS.md, First-tenant bootstrap).",
            file=sys.stderr,
        )
        logger.error("tenant_bootstrap_refused", extra={"reason": "production_confirmation"})
        return _EXIT_USAGE

    try:
        if args.dry_run:
            _print_plan(assess_bootstrap(request))
            return _EXIT_OK
        _print_result(bootstrap_first_tenant(request))
        return _EXIT_OK
    except BootstrapError as exc:
        print(f"bootstrap refused: {exc}", file=sys.stderr)
        logger.error("tenant_bootstrap_failed", extra={"error_type": type(exc).__name__})
        return _EXIT_FAILURE
    except Exception as exc:  # noqa: BLE001 -- type name only: a driver message could carry a DSN
        print(f"bootstrap failed: {type(exc).__name__}", file=sys.stderr)
        logger.error("tenant_bootstrap_failed", extra={"error_type": type(exc).__name__})
        return _EXIT_FAILURE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
