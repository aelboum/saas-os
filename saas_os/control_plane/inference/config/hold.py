"""The platform hold on one tenant's AI (ADR-0054 amendment of 2026-11-09;
Gap 20b, owner decision of that day).

A platform operator can stop a tenant's *new* AI requests for a security,
contractual, spending or operator reason, whatever the tenant's own policy
says. The hold overrides tenant enablement and every model grant: the
governed inference path (`resolution.load_snapshot` and `evaluate`) refuses
with `InferencePolicyDeniedError("tenant_ai_held")` before it looks at the
tenant's policy, and it does so in every transaction that decides whether a
request or an attempt may start (the first resolution and again before each
attempt, including every retry and fallback candidate).

**Default.** No row means no hold. Nothing creates a row implicitly, so no
existing tenant is suspended by this feature.

**Authority.** Setting and releasing are platform operations
(`ai_tenant_hold.set`, `ai_tenant_hold.release`) under the one permission
`platform.ai_tenant_hold:manage`, which `platform.ai_policy:manage` does not
imply and no tenant permission can grant. A person only: a service account or
a system purpose is refused. Support access, tenant roles and tenant policy
toggles cannot write the hold, and a hold survives `set_tenant_ai_policy`.

**Storage (ADR-0056).** `control_plane.ai_tenant_holds` is one of the protected
installation-wide AI tables: the application role can only read it, and the
two operations run their transaction -- authorization, the change and the
platform audit row -- as the platform-configuration role
(`PLATFORM_CONFIG_DATABASE_URL`, like every other AI configuration write). The
table also refuses every write made while a tenant is bound (trigger,
migration c8e5a2f7d1b3).

**Evidence.** The hold row and one platform audit row
(`platform.ai_tenant_hold.set` or `.release`, the tenant as target, the closed
reason code) commit in one transaction; a refusal writes a `denied` platform
row; a change that fails leaves neither. The tenant's own audit row
(`ai.policy.hold` or `ai.policy.release_hold`, the closed reason code, the
operator as the actor, marked `platform: true`) is written in a second
transaction, in the tenant's scope, *after* the hold has committed: the
platform-configuration role may not write a tenant's audit log (ADR-0056 D2),
so the two cannot share a transaction. The consequence is recorded in the
ADR-0054 amendment: if that second write fails (or the process dies between
the two), the hold is in force and the platform trail is complete, but the
tenant's trail lacks the row; the failure is logged
(`ai_tenant_hold_tenant_audit_failed`) and the call still returns. The tenant
still sees every refusal the hold causes in its own audit log. Only the closed
`HoldReason` values are ever stored, logged or audited; there is no free text.

**In-flight behaviour.** An attempt whose `started` row has committed before
the hold's transaction took its gate completes and settles normally: the
provider call is not cut, its usage is recorded. A hold never aborts a call in
progress. Every attempt that *starts* after the hold commits is refused,
including the retry or fallback candidate of a request that was in flight
when the hold arrived (`service._begin_attempt` re-reads the hold per
attempt). The hold's transaction takes an exclusive transaction-level advisory
lock on the tenant's hold key, and each attempt's start transaction takes the
same lock shared before it reads the hold, so there is no instant at which an
attempt can both miss a committed hold and start: either the attempt's start
committed first (it is in flight) or it sees the hold. A hold waits for
attempt-start transactions already under way, bounded by the platform
mutation statement timeout.

**Tenant lifecycle.** The row references the tenant with a `NO ACTION` foreign
key onto `core.tenants`, whose rows are never deleted (a purged tenant stays
as a tombstone), so a tenant purge is neither blocked by the hold nor needs to
clean it; the hold is retained like the other platform records. The
configuration role cannot read `core.tenants` (ADR-0056 D2), so the foreign key
is what refuses an unknown tenant (`tenant_unavailable`); a closed tenant can
still be held or released (a hold only reduces authority, and a closed tenant
must remain windable-down).

**Repeats.** Holding an already held tenant is refused (`already_held`) and
releasing a tenant that is not held is refused (`not_held`); both change
nothing and write no audit row. To change a hold's reason, release it and set
it again.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from saas_os.control_plane.inference.config.errors import AITenantHoldError
from saas_os.control_plane.inference.config.models import AITenantHold, HoldReason
from saas_os.core.audit_log import record_in_transaction
from saas_os.core.platform_authority import (
    OversightOutcome,
    PlatformChange,
    run_oversight_read,
    run_platform_change,
)
from saas_os.core.platform_authority.operations import (
    AI_CONFIG_READ,
    AI_TENANT_HOLD_RELEASE,
    AI_TENANT_HOLD_SET,
)
from saas_os.infra.db import (
    IntegrityError,
    Session,
    acquire_global_advisory_lock,
    select,
    tenant_session_scope,
)

logger = logging.getLogger(__name__)

_TARGET_HOLD = "ai_tenant_hold"
_TENANT_RESOURCE = "ai_tenant_policy"
ACTION_HOLD = "ai.policy.hold"
ACTION_RELEASE_HOLD = "ai.policy.release_hold"
_LOCK_NAMESPACE = "ai_tenant_hold"
_FK_CONSTRAINT = "fk_ai_tenant_holds_target_tenant_id"


@dataclass(frozen=True)
class TenantAIHoldView:
    """One tenant's hold state. `held` is false for a tenant that was never
    held. Reason codes only; never a person or free text."""

    tenant_id: uuid.UUID
    held: bool
    reason: str | None
    held_at: datetime | None
    released_at: datetime | None
    version: int


def _view(tenant_id: uuid.UUID, row: AITenantHold | None) -> TenantAIHoldView:
    if row is None:
        return TenantAIHoldView(tenant_id, False, None, None, None, 0)
    return TenantAIHoldView(
        tenant_id, bool(row.active), row.reason, row.held_at, row.released_at, row.version
    )


# --- the governed inference side (read only; no authorization of its own) ---------


def lock_hold_gate_shared(session: Session, tenant_id: uuid.UUID) -> None:
    """Take the tenant's hold gate *shared* for the rest of the transaction.
    The start of every attempt calls it before reading the hold; a hold or a
    release takes the same key exclusive, so the two serialize (module
    docstring, "In-flight behaviour")."""
    acquire_global_advisory_lock(session, _LOCK_NAMESPACE, str(tenant_id), shared=True)


def tenant_ai_held(session: Session, tenant_id: uuid.UUID) -> bool:
    """Whether the platform currently holds `tenant_id`'s AI, as read in the
    caller's own transaction. No row is no hold."""
    active = session.execute(
        select(AITenantHold.active).where(AITenantHold.target_tenant_id == tenant_id)
    ).scalar_one_or_none()
    return bool(active)


# --- the platform operations ---------------------------------------------------


def _reason(reason: object) -> HoldReason:
    if isinstance(reason, HoldReason):
        return reason
    if isinstance(reason, str):
        try:
            return HoldReason(reason)
        except ValueError:
            pass
    raise AITenantHoldError("invalid_reason")


def _locked_row(session: Session, tenant_id: uuid.UUID) -> AITenantHold | None:
    # Exclusive on the tenant's gate: attempt starts that are under way finish
    # first, and none that begins later reads the hold before this commits.
    acquire_global_advisory_lock(session, _LOCK_NAMESPACE, str(tenant_id))
    return session.execute(
        select(AITenantHold).where(AITenantHold.target_tenant_id == tenant_id).with_for_update()
    ).scalar_one_or_none()


def _flush(session: Session) -> None:
    try:
        session.flush()
    except IntegrityError as error:
        constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
        # One refusal for a tenant that does not exist; a concurrent first
        # hold of the same tenant lost the race to the unique key.
        raise AITenantHoldError(
            "tenant_unavailable" if constraint == _FK_CONSTRAINT else "already_held"
        ) from None


def _record_for_tenant(
    caller: object, tenant_id: uuid.UUID, action: str, metadata: dict[str, object]
) -> None:
    """The tenant's own audit row, after the hold committed (module docstring,
    "Evidence"). Never raises: the hold is already in force."""
    try:
        with tenant_session_scope(tenant_id) as session:
            record_in_transaction(
                session,
                caller=caller,  # type: ignore[arg-type]  # vetted by run_platform_change: a person
                tenant_id=tenant_id,
                action=action,
                resource_type=_TENANT_RESOURCE,
                resource_id=str(tenant_id),
                metadata={**metadata, "platform": True},
            )
    except Exception as error:  # noqa: BLE001 -- the hold stands; evidence gap is logged
        logger.error(
            "ai_tenant_hold_tenant_audit_failed",
            extra={"ai_action": action, "error_type": type(error).__name__},
        )


def set_tenant_ai_hold(
    tenant_id: uuid.UUID, *, reason: HoldReason, caller: object
) -> TenantAIHoldView:
    """Hold `tenant_id`'s AI: from the commit of this call every new request
    and attempt of the tenant is refused (`tenant_ai_held`), whatever its
    policy says. Authority: `platform.ai_tenant_hold:manage`. `reason` is one
    of `HoldReason`. Runs as the platform-configuration role. See the module
    docstring for evidence and in-flight behaviour."""
    if not isinstance(tenant_id, uuid.UUID):
        raise AITenantHoldError("tenant_unavailable")
    chosen = _reason(reason)
    metadata: dict[str, object] = {"change": "hold", "reason": chosen.value}

    def change(session: Session) -> PlatformChange:
        row = _locked_row(session, tenant_id)
        if row is not None and row.active:
            raise AITenantHoldError("already_held")
        at = datetime.now(UTC)
        if row is None:
            row = AITenantHold(
                target_tenant_id=tenant_id,
                reason=chosen.value,
                active=True,
                held_at=at,
                released_at=None,
                version=1,
            )
            session.add(row)
        else:
            row.reason = chosen.value
            row.active = True
            row.held_at = at
            row.released_at = None
            row.version += 1
        _flush(session)
        return PlatformChange(
            _view(tenant_id, row),
            target_id=str(tenant_id),
            target_tenant_id=tenant_id,
            metadata=metadata,
        )

    view = run_platform_change(
        caller=caller,
        operation=AI_TENANT_HOLD_SET,
        target_type=_TARGET_HOLD,
        change=change,
        reason=chosen.value,
    )
    _record_for_tenant(caller, tenant_id, ACTION_HOLD, metadata)
    return view


def release_tenant_ai_hold(tenant_id: uuid.UUID, *, caller: object) -> TenantAIHoldView:
    """Lift the hold on `tenant_id`'s AI: requests are decided by the tenant's
    own policy again from the commit of this call. Authority:
    `platform.ai_tenant_hold:manage`. Runs as the platform-configuration role.
    The audit rows record the reason the hold had."""
    if not isinstance(tenant_id, uuid.UUID):
        raise AITenantHoldError("tenant_unavailable")
    released: dict[str, object] = {}

    def change(session: Session) -> PlatformChange:
        row = _locked_row(session, tenant_id)
        if row is None or not row.active:
            raise AITenantHoldError("not_held")
        released.update({"change": "release_hold", "reason": row.reason})
        row.active = False
        row.released_at = datetime.now(UTC)
        row.version += 1
        _flush(session)
        return PlatformChange(
            _view(tenant_id, row),
            target_id=str(tenant_id),
            target_tenant_id=tenant_id,
            metadata=dict(released),
        )

    view = run_platform_change(
        caller=caller,
        operation=AI_TENANT_HOLD_RELEASE,
        target_type=_TARGET_HOLD,
        change=change,
        reason=None,
    )
    _record_for_tenant(caller, tenant_id, ACTION_RELEASE_HOLD, released)
    return view


def read_tenant_ai_hold(tenant_id: uuid.UUID, *, caller: object) -> TenantAIHoldView:
    """One tenant's hold state. Authority: `platform.ai_config:read`, audited
    as an oversight read; uses the application role. A tenant that was never
    held, and an id that names no tenant, read identically (not held)."""
    if not isinstance(tenant_id, uuid.UUID):
        raise AITenantHoldError("tenant_unavailable")

    def read(session: Session) -> OversightOutcome:
        row = session.execute(
            select(AITenantHold).where(AITenantHold.target_tenant_id == tenant_id)
        ).scalar_one_or_none()
        return OversightOutcome(value=_view(tenant_id, row), returned=0 if row is None else 1)

    return run_oversight_read(
        caller=caller, operation=AI_CONFIG_READ, target_type=_TARGET_HOLD, read=read
    )
