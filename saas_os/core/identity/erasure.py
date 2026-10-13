"""RA-12-3 -- individual identity erasure.

Distinct from `saas_os.core.tenancy.purge_tenant()` (RA-12 finding: "tenant purge
and individual identity erasure are different operations"). `core.users`
and `core.external_identities` are `GLOBAL_IDENTITY` in
`saas_os.core.tenancy.retention.RETENTION_CLASSIFICATION` precisely because a
`User` may hold memberships in many tenants -- purging one tenant must
never touch them, and nothing about purging one tenant tells this module
anything about a user's *other* tenants. This module is the independent
mechanism the retention audit found missing: an operation that erases one
person's own identity data, wherever it lives, without touching any other
person's data or any tenant's own business data.

**What is actually erasable.** `core.users` itself carries no personal
data at all (`id`, `is_active`, timestamps only -- confirmed by its own
migration) -- the identity-*linking* data lives entirely in
`core.external_identities` (`issuer`, `subject`: the actual link to a
real external account) and the live credentials in `core.sessions`
(bearer tokens). Both are leaf tables (no foreign key anywhere targets
either), so deleting them is safe by construction and needs no tombstone.

**Why `core.users.id` itself is never deleted.** Many retained,
security-relevant tables hold a `NOT NULL`, no-`ondelete` foreign key to
`core.users.id` (`core.invitations.inviter_user_id`,
`core.support_access_requests.requester_user_id`,
`control_plane.approval_requests.proposer_user_id`, several
`self_learning.*` `created_by_user_id` columns): PostgreSQL's default
`NO ACTION` means deleting a referenced `core.users` row is rejected
outright while any such row exists, and none of those NOT-NULL columns
can be nulled out either. Retaining the bare, already-non-identifying
`core.users` row is therefore not merely a design choice but the only
schema-consistent option -- the exact same reasoning
`saas_os.core.tenancy.retention`'s `TOMBSTONE` class already documents for
`core.tenants`, applied here to a row that (unlike a tenant) never needed
a name-scrubbing step in the first place because it never had one.

**Multi-tenant membership.** A user's own `core.tenant_memberships` row
in each tenant -- and only the rows that exist solely because of that
one membership (`saas_os.core.api_keys`, `saas_os.core.notifications`, the composite FKs
onto it force this order; `core.membership_roles`) -- are deleted.
Nothing else that tenant owns is ever touched: no other member's rows,
no billing/usage/webhook data, no audit trail. This mirrors
`saas_os.core.tenancy.purge_tenant()`'s own per-step deletion pattern exactly,
scoped to one user's own rows in one tenant instead of an entire tenant's
rows.

**Tenant discovery is the caller's responsibility, by design.**
`core.tenant_memberships` is Row-Level-Security-protected on `tenant_id`;
no session scoped to the ordinary application role can enumerate "every
tenant a given user belongs to" across tenant boundaries without
bypassing RLS, and this module deliberately does not introduce the first
use of the privileged migrations role inside `core`'s own business logic
to do so (every existing use of that role is confined to
`saas_os.infra.db.migration_runner`, `saas_os.infra.db.backup`, and test/ops tooling).
`erase_user_identity()` therefore takes the tenant ids to check as an
explicit `tenant_ids` argument -- exactly the same "the caller supplies
the target, this function does not discover it" contract
`purge_tenant(tenant_id)` itself already has for a single tenant. An
incomplete list makes this call incomplete, not unsafe: every step is
independently idempotent, so a caller that later discovers another
membership can call this again.

**Retained records, unchanged.** `saas_os.core.audit_log`, `core.support_access_requests`,
`core.billing_subscriptions`, `core.usage_events`, and every AI Control
Plane table keep whatever `actor_user_id`/`*_by_user_id` reference they
already had -- valid, because `core.users.id` is never deleted, and
carrying no personal data of their own to begin with (the retained
reference is an opaque id, not a name or an external subject). No
`RETENTION_CLASSIFICATION` value is changed by this module.

**Authorization.** This module intentionally exposes no HTTP route and
is not imported by `api` or `control_plane`
(`tests/architecture/test_layer_boundaries.py`'s existing "layer
boundary" style is extended with one more forbidden edge for exactly
this module -- see that test file). Mirrors
`saas_os.infra.db.backup`'s own "not an application-runtime capability" import-
linter contract: a destructive, platform-level, cross-tenant capability
this repository does not yet have a general admin-authorization model
for is fenced at the import boundary rather than left to convention.
`erase_user_identity()` still requires an explicit, existing
`actor_user_id` (fails closed via `UserNotFoundError` for a fabricated
one) so every call is attributable -- the same attribution discipline
`purge_tenant(..., actor_user_id=...)` already uses -- but the caller
(trusted ops/admin tooling, exactly like `purge_tenant()`'s own callers)
remains responsible for having verified that caller is actually
authorized to erase identities, since no platform-wide capability model
exists in `saas_os.core.rbac` to check against (`saas_os.core.rbac.can()` is inherently
tenant-scoped).

**Non-enumeration.** `erase_user_identity()` never checks whether
`user_id` itself exists. Every deletion step is a plain `WHERE user_id =
...` (or `WHERE tenant_id = ... AND user_id = ...`) query that finds zero
rows for a genuinely nonexistent id, an id that was never a member of the
given tenants, or an id that was already fully erased -- all three
produce the exact same all-zero `IdentityErasureResult`, so a caller
cannot distinguish "never existed" from "already erased" from the return
value alone.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field

from saas_os.core.audit_log import ActorType, AuditOutcome
from saas_os.core.audit_log import record as record_audit_event
from saas_os.core.identity.errors import UserNotFoundError
from saas_os.core.identity.models import TenantMembership
from saas_os.core.identity.service import get_user, purge_user_external_identities
from saas_os.core.identity.sessions import purge_user_sessions
from saas_os.infra.db import select, tenant_session_scope

_ACTION_MEMBERSHIP_ERASED = "identity.erasure_membership_removed"
_RESOURCE_TYPE = "user"


@dataclass(frozen=True)
class IdentityErasureResult:
    """Outcome of one `erase_user_identity()` call. Counts only -- never
    the deleted rows, an external subject, or any other personal data.
    `tenants_with_membership_removed` names which of the *given*
    `tenant_ids` actually had a membership (and so were actually
    touched); a tenant the user was never a member of contributes
    nothing and is silently absent from it -- consistent with this
    module's own non-enumeration property.
    """

    user_id: uuid.UUID
    external_identities_deleted: int
    sessions_deleted: int
    tenants_with_membership_removed: tuple[uuid.UUID, ...] = ()
    api_keys_deleted: int = 0
    notifications_deleted: int = 0
    membership_roles_deleted: int = 0
    notification_events_deleted: int = 0
    checked_tenant_ids: tuple[uuid.UUID, ...] = field(default=())

    @property
    def memberships_removed(self) -> int:
        return len(self.tenants_with_membership_removed)


def _erase_membership_in_tenant(
    tenant_id: uuid.UUID, user_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> tuple[bool, int, int, int, int]:
    """One tenant's own share of `erase_user_identity()` -- mirrors
    `saas_os.core.tenancy.service._run_purge_pass()`'s own fixed, FK-safe order,
    scoped to one user's own rows: API keys and notifications (both carry
    a composite FK onto the membership) before `core.membership_roles`,
    before the membership row itself. Deferred imports for the same
    load-time-cycle reason `_run_purge_pass()` and `create_invitation()`
    already document: `saas_os.core.api_keys.service`/`saas_os.core.notifications.service`/
    `saas_os.core.rbac.authorization` each import `saas_os.core.identity` at module
    scope. Returns `(membership_removed, api_keys_deleted,
    notifications_deleted, membership_roles_deleted,
    notification_events_deleted)` -- the last being the user's undispatched
    notification events in the outbox (RE-1), which carry the user's
    notification content and (encrypted) address.
    """
    from saas_os.core.api_keys.service import purge_user_api_keys_in_tenant
    from saas_os.core.notifications.service import (
        purge_user_notification_events_in_tenant,
        purge_user_notifications_in_tenant,
    )
    from saas_os.core.rbac.service import purge_user_membership_roles_in_tenant

    api_keys_deleted = purge_user_api_keys_in_tenant(tenant_id, user_id)
    notifications_deleted = purge_user_notifications_in_tenant(tenant_id, user_id)
    notification_events_deleted = purge_user_notification_events_in_tenant(tenant_id, user_id)

    membership_roles_deleted = 0
    membership_removed = False
    with tenant_session_scope(tenant_id) as session:
        membership = session.execute(
            select(TenantMembership)
            .where(TenantMembership.tenant_id == tenant_id, TenantMembership.user_id == user_id)
            .with_for_update()
        ).scalar_one_or_none()
        if membership is not None:
            membership_id = membership.id
            session.expunge(membership)
        else:
            membership_id = None

    if membership_id is not None:
        membership_roles_deleted = purge_user_membership_roles_in_tenant(tenant_id, membership_id)
        with tenant_session_scope(tenant_id) as session:
            row = session.execute(
                select(TenantMembership)
                .where(TenantMembership.id == membership_id)
                .with_for_update()
            ).scalar_one_or_none()
            if row is not None:
                session.delete(row)
                membership_removed = True

    if membership_removed:
        record_audit_event(
            tenant_id=tenant_id,
            actor_type=ActorType.USER,
            actor_user_id=actor_user_id,
            action=_ACTION_MEMBERSHIP_ERASED,
            resource_type=_RESOURCE_TYPE,
            resource_id=str(user_id),
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "api_keys_deleted": api_keys_deleted,
                "notifications_deleted": notifications_deleted,
                "notification_events_deleted": notification_events_deleted,
                "membership_roles_deleted": membership_roles_deleted,
            },
        )
    return (
        membership_removed,
        api_keys_deleted,
        notifications_deleted,
        membership_roles_deleted,
        notification_events_deleted,
    )


def erase_user_identity(
    user_id: uuid.UUID,
    tenant_ids: Iterable[uuid.UUID],
    *,
    actor_user_id: uuid.UUID,
) -> IdentityErasureResult:
    """Erase `user_id`'s own identity-linking data and remove their own
    membership (and everything that exists solely because of it) from
    each tenant in `tenant_ids`. See this module's own docstring for the
    full erasable/retained/discovery/authorization contract.

    **A user who is an enrolled platform operator is not erased**
    (ADR-0045 section 6): while the user has an operator row that is not
    revoked, the call raises `EnrolledOperatorErasureError` before anything
    is deleted and records one `denied` platform audit row. Revoke the
    operator first (`revoke_operator`, which passes the last-owner
    invariant), then erase.

    `actor_user_id` must be a real, existing user (`UserNotFoundError`
    otherwise, fail closed) -- the caller's own identity, attributed on
    every per-tenant audit event this call writes. It is never checked
    against `user_id` (an identity may erase its own data or another's;
    which is appropriate is the caller's authorization decision, not
    this function's).

    Idempotent and safe to call concurrently, including against itself
    for the same `user_id`: every step locks only the specific rows it
    is about to delete (`with_for_update()`, exactly like every
    `saas_os.core.tenancy.purge_tenant()` step), so two overlapping calls
    serialize per-row rather than racing, and a row already deleted by
    the other call is simply not found. Once `core.external_identities`
    is deleted and committed, a later login with the same `(issuer,
    subject)` provisions a genuinely new, unrelated `User`
    (`get_or_create_user_for_external_identity()`'s own existing
    "not found" path) -- it can never resolve back to this `user_id`.
    """
    if get_user(actor_user_id) is None:
        raise UserNotFoundError(actor_user_id)
    # ADR-0045 section 6: an enrolled platform operator is not erased.
    # Before anything is deleted; raises `EnrolledOperatorErasureError`.
    from saas_os.core.identity.user_authority import refuse_erasure_of_enrolled_operator

    refuse_erasure_of_enrolled_operator(user_id, actor_user_id=actor_user_id)

    tenants_touched: list[uuid.UUID] = []
    total_api_keys = 0
    total_notifications = 0
    total_membership_roles = 0
    total_notification_events = 0
    checked: list[uuid.UUID] = []
    for tenant_id in tenant_ids:
        checked.append(tenant_id)
        (
            removed,
            api_keys_deleted,
            notifications_deleted,
            membership_roles_deleted,
            notification_events_deleted,
        ) = _erase_membership_in_tenant(tenant_id, user_id, actor_user_id=actor_user_id)
        if removed:
            tenants_touched.append(tenant_id)
        total_api_keys += api_keys_deleted
        total_notifications += notifications_deleted
        total_membership_roles += membership_roles_deleted
        total_notification_events += notification_events_deleted

    external_identities_deleted = purge_user_external_identities(user_id)
    sessions_deleted = purge_user_sessions(user_id)

    return IdentityErasureResult(
        user_id=user_id,
        external_identities_deleted=external_identities_deleted,
        sessions_deleted=sessions_deleted,
        tenants_with_membership_removed=tuple(tenants_touched),
        api_keys_deleted=total_api_keys,
        notifications_deleted=total_notifications,
        membership_roles_deleted=total_membership_roles,
        notification_events_deleted=total_notification_events,
        checked_tenant_ids=tuple(checked),
    )
