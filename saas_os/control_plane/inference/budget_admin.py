"""Changing and reading the monetary AI budget (ADR-0054 amendment of
2026-11-10; Gap 21b, stage 5; owner decisions of 2026-11-09). The budget
itself, and how admission and settlement use it, are in `budget.py`.

**Tenant operations** (the tenant's own scope, application role):

- `set_tenant_budget_cap`: the tenant's own cap, which can only lower its
  effective budget (owner decision 3). Authority: the tenant permission
  `ai.budget:manage`, which no other permission implies, support access never
  satisfies (`AI_SUPPORT_ACCESS_EXCLUDED_ACTIONS`), and SaaS OS grants to no
  role (a product binds it, ADR-0060). A user only: a service account or a
  system purpose is refused. The change and its `ai.budget.set_cap` audit row
  commit together; a refusal writes a `denied` row after the rollback.
- `read_tenant_budget`: the current month's status (`budget.BudgetStatus`).
  Authority: `ai.usage:read`, a user only (owner decision: cost reads are
  audited and denied to support by default). Every allowed read writes one
  `ai.budget.read` audit row in the same transaction, without figures.

**Platform operations** (permission `platform.ai_budget:manage`, a person
only, no system purpose):

- `set_plan_budget`: a new immutable budget version of one billing plan
  (`ai_plan_budgets`), on the platform-configuration role.
- `set_tenant_budget_override` / `clear_tenant_budget_override`: raise (or
  lower) one tenant's plan budget until a required expiry, with a closed
  reason code (`ai_budget_overrides`), on the platform-configuration role.
  As for the AI hold, the tenant's own audit row (`ai.budget.override_set`,
  `ai.budget.override_clear`) is written after the platform change commits:
  the configuration role may not write a tenant's audit log (ADR-0056 D2).
  If that second write fails the override is in force, the platform trail is
  complete, and `ai_budget_override_tenant_audit_failed` is logged.
- `release_budget_reservation`: release one `expired_unknown` reservation
  (owner decision 6: the recovery process for unknown outcomes), taking its
  worst case out of the month's `retained`. The tenant's rows, its
  `ai.budget.reservation_release` audit row and the platform audit row
  commit in one transaction (application role,
  `run_tenant_platform_change`).

Amounts are `Decimal` (at most 8 decimal places, 0 to 9 999 999 999), in an
ISO-4217 code. No commercial value is set by SaaS OS; every amount is the
operator's or the tenant's input. They are estimated platform spend, never
invoice amounts.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from saas_os.control_plane.inference.budget import (
    BudgetStatus,
    InvalidThresholdsError,
    budget_status,
    database_time,
    parse_thresholds,
)
from saas_os.control_plane.inference.budget_models import (
    AIBudgetOverride,
    AIBudgetPeriod,
    AIBudgetReservation,
    AIPlanBudget,
    AITenantBudget,
    OverrideReason,
    ReservationState,
)
from saas_os.control_plane.inference.permissions import AI_BUDGET, AI_USAGE
from saas_os.core.audit_log import ActorType, AuditOutcome, record, record_in_transaction
from saas_os.core.authority import ServiceAccountCaller, UserCaller, require_caller
from saas_os.core.billing import entitlement_plan_ids
from saas_os.core.platform_authority import (
    PlatformChange,
    run_platform_change,
    run_tenant_platform_change,
)
from saas_os.core.platform_authority.operations import (
    AI_BUDGET_OVERRIDE_CLEAR,
    AI_BUDGET_OVERRIDE_SET,
    AI_BUDGET_RESERVATION_RELEASE,
    AI_PLAN_BUDGET_CONFIGURE,
)
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import authorize_caller
from saas_os.core.tenancy import lock_open_tenant, require_open_tenant
from saas_os.infra.db import IntegrityError, Session, select, tenant_session_scope

logger = logging.getLogger(__name__)

_CURRENCY = re.compile(r"[A-Z]{3}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
# numeric(18,8): ten digits before the point.
MAX_AMOUNT = Decimal("9999999999.99999999")
# An override must end; the longest it may run in one setting.
MAX_OVERRIDE_DURATION = timedelta(days=366)
_RESOURCE_BUDGET = "ai_budget"
_TARGET_PLAN_BUDGET = "ai_plan_budget"
_TARGET_OVERRIDE = "ai_budget_override"
_TARGET_RESERVATION = "ai_budget_reservation"
ACTION_SET_CAP = "ai.budget.set_cap"
ACTION_READ = "ai.budget.read"
ACTION_OVERRIDE_SET = "ai.budget.override_set"
ACTION_OVERRIDE_CLEAR = "ai.budget.override_clear"
ACTION_RESERVATION_RELEASE = "ai.budget.reservation_release"
_FK_TENANT = "fk_ai_budget_overrides_target_tenant_id"
_FK_PLAN = "fk_ai_plan_budgets_plan_id"


class AIBudgetError(ValueError):
    """A refused budget request; nothing was changed. `reason` is a short
    code: `invalid_currency`, `invalid_amount`, `invalid_version`,
    `invalid_effective_from`, `invalid_reason`, `invalid_expiry`,
    `invalid_thresholds`, `currency_conflict`, `version_exists`, `plan_unavailable`,
    `tenant_unavailable`, `not_overridden`, `reservation_unavailable` (no
    such reservation, or not `expired_unknown`)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"AI budget request refused: {reason}")


def _currency(value: object) -> str:
    if not isinstance(value, str) or not _CURRENCY.fullmatch(value):
        raise AIBudgetError("invalid_currency")
    return value


def _amount(value: object, *, optional: bool = False) -> Decimal | None:
    if value is None and optional:
        return None
    if (
        not isinstance(value, Decimal)
        or not value.is_finite()
        or not Decimal(0) <= value <= MAX_AMOUNT
        or value.as_tuple().exponent < -8  # type: ignore[operator]
    ):
        raise AIBudgetError("invalid_amount")
    return value


def _thresholds(value: object) -> tuple[int, ...] | None:
    try:
        return parse_thresholds(value)
    except InvalidThresholdsError:
        raise AIBudgetError("invalid_thresholds") from None


def _aware(value: object, reason: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AIBudgetError(reason)
    return value.astimezone(UTC)


# --- tenant operations ----------------------------------------------------------------


@dataclass(frozen=True)
class TenantBudgetCapView:
    tenant_id: uuid.UUID
    currency: str
    cap_amount: Decimal | None
    version: int
    warn_thresholds: tuple[int, ...] | None = None


def _record_denied(tenant_id: uuid.UUID, caller: object, action: str) -> None:
    """The refusal row, written after the refused transaction rolled back.
    Best effort: the refusal stands without it."""
    if not isinstance(caller, (UserCaller, ServiceAccountCaller)):
        return
    is_user = isinstance(caller, UserCaller)
    try:
        record(
            tenant_id=tenant_id,
            actor_type=ActorType.USER if is_user else ActorType.SERVICE_ACCOUNT,
            actor_user_id=caller.user_id if isinstance(caller, UserCaller) else None,
            actor_service_account_id=(
                caller.service_account_id if isinstance(caller, ServiceAccountCaller) else None
            ),
            action=action,
            resource_type=_RESOURCE_BUDGET,
            outcome=AuditOutcome.DENIED,
            metadata={"reason": "not_authorized"},
        )
    except Exception as exc:  # noqa: BLE001 -- the refusal stands without its row
        logger.warning("ai_budget_denial_unrecorded", extra={"error_type": type(exc).__name__})


def set_tenant_budget_cap(
    tenant_id: uuid.UUID,
    *,
    currency: str,
    amount: Decimal | None,
    caller: object,
    warn_thresholds: Sequence[int] | None = None,
) -> TenantBudgetCapView:
    """Set (or with `amount=None`, remove) the tenant's own monthly cap in
    `currency`, and its warning thresholds. The cap only ever lowers the
    effective budget: a cap above the plan or override changes nothing. A cap
    in a currency other than the plan's makes admission refuse
    (`budget_currency_conflict`) until it is corrected. `warn_thresholds`
    (Gap 21c; `budget.parse_thresholds`: whole percentages 1 to 100, strictly
    ascending, at most ten) replace the plan's; an empty list turns warnings
    off; None (the default) uses the plan's. Every call sets the cap and the
    thresholds together. Authority: `ai.budget:manage`, a user only."""
    operation = "ai_budget.set_cap"
    require_caller(operation, caller)
    if not isinstance(caller, UserCaller):
        _record_denied(tenant_id, caller, ACTION_SET_CAP)
        raise AuthorityNotAuthorizedError(operation, tenant_id)
    chosen_currency = _currency(currency)
    cap = _amount(amount, optional=True)
    thresholds = _thresholds(warn_thresholds)
    require_open_tenant(tenant_id)
    try:
        with tenant_session_scope(tenant_id) as session:
            lock_open_tenant(session, tenant_id)
            authorize_caller(
                caller,
                session=session,
                operation=operation,
                tenant_id=tenant_id,
                resource=AI_BUDGET,
                action="manage",
            )
            row = session.execute(
                select(AITenantBudget)
                .where(AITenantBudget.tenant_id == tenant_id)
                .with_for_update()
            ).scalar_one_or_none()
            if row is None:
                row = AITenantBudget(
                    tenant_id=tenant_id,
                    currency=chosen_currency,
                    cap_amount=cap,
                    warn_thresholds=None if thresholds is None else list(thresholds),
                    version=1,
                )
                session.add(row)
            else:
                row.currency = chosen_currency
                row.cap_amount = cap
                row.warn_thresholds = None if thresholds is None else list(thresholds)
                row.version += 1
            session.flush()
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action=ACTION_SET_CAP,
                resource_type=_RESOURCE_BUDGET,
                resource_id=str(tenant_id),
                metadata={
                    "change": "set_cap" if cap is not None else "remove_cap",
                    "currency": chosen_currency,
                    "warn_thresholds": None if thresholds is None else list(thresholds),
                },
            )
            return TenantBudgetCapView(
                tenant_id, row.currency, row.cap_amount, row.version, thresholds
            )
    except AuthorityNotAuthorizedError:
        _record_denied(tenant_id, caller, ACTION_SET_CAP)
        raise


def read_tenant_budget(
    tenant_id: uuid.UUID,
    *,
    caller: object,
    plans: Callable[[uuid.UUID], Sequence[uuid.UUID]] = entitlement_plan_ids,
) -> BudgetStatus:
    """The tenant's budget this UTC month (`BudgetStatus`). Authority:
    `ai.usage:read`, a user only; audited. Unreadable billing data reads as
    `unavailable`, never as no budget."""
    operation = "ai_budget.read"
    require_caller(operation, caller)
    if not isinstance(caller, UserCaller):
        _record_denied(tenant_id, caller, ACTION_READ)
        raise AuthorityNotAuthorizedError(operation, tenant_id)
    try:
        with tenant_session_scope(tenant_id) as session:
            authorize_caller(
                caller,
                session=session,
                operation=operation,
                tenant_id=tenant_id,
                resource=AI_USAGE,
                action="read",
            )
            status = tenant_budget_status(session, tenant_id, plans)
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action=ACTION_READ,
                resource_type=_RESOURCE_BUDGET,
                resource_id=str(tenant_id),
                metadata={"state": status.state},
            )
            return status
    except AuthorityNotAuthorizedError:
        _record_denied(tenant_id, caller, ACTION_READ)
        raise


def tenant_budget_status(
    session: Session,
    tenant_id: uuid.UUID,
    plans: Callable[[uuid.UUID], Sequence[uuid.UUID]] = entitlement_plan_ids,
) -> BudgetStatus:
    """`budget.budget_status` with the plan ids read through `plans`; any
    failure to read is `unavailable`. No authorization of its own."""
    try:
        plan_ids = tuple(plans(tenant_id))
    except Exception as exc:  # noqa: BLE001 -- unreadable billing data
        logger.warning("ai_budget_status_unavailable", extra={"error_type": type(exc).__name__})
        return BudgetStatus("unavailable")
    return budget_status(session, tenant_id, plan_ids)


# --- platform operations --------------------------------------------------------------


@dataclass(frozen=True)
class PlanBudgetView:
    plan_id: uuid.UUID
    budget_version: str
    currency: str | None
    monthly_amount: Decimal | None
    effective_from: datetime
    warn_thresholds: tuple[int, ...] | None = None


def _integrity(error: IntegrityError, mapping: dict[str, str], default: str) -> AIBudgetError:
    constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
    return AIBudgetError(mapping.get(str(constraint), default))


def set_plan_budget(
    plan_id: uuid.UUID,
    *,
    budget_version: str,
    currency: str | None,
    monthly_amount: Decimal | None,
    caller: object,
    reason: str,
    effective_from: datetime | None = None,
    warn_thresholds: Sequence[int] | None = None,
) -> PlanBudgetView:
    """Add an immutable budget version for one billing plan, in effect from
    `effective_from` (default now). `currency` and `monthly_amount` both None
    record that the plan has no budget from then on. A version is never
    rewritten. Authority: `platform.ai_budget:manage`; runs as the
    platform-configuration role. A tenant already in the month keeps the
    lower of its frozen plan budget and the new one (`budget.py`).
    `warn_thresholds` (Gap 21c; `budget.parse_thresholds`) are the plan's
    warning thresholds, used by a tenant that has set none of its own; a
    version with no budget takes none."""
    if not isinstance(plan_id, uuid.UUID):
        raise AIBudgetError("plan_unavailable")
    if not isinstance(budget_version, str) or not _VERSION.fullmatch(budget_version):
        raise AIBudgetError("invalid_version")
    if (currency is None) != (monthly_amount is None):
        raise AIBudgetError("invalid_amount")
    chosen_currency = None if currency is None else _currency(currency)
    amount = _amount(monthly_amount, optional=True)
    thresholds = _thresholds(warn_thresholds)
    if amount is None and thresholds:
        raise AIBudgetError("invalid_thresholds")
    start = (
        datetime.now(UTC)
        if effective_from is None
        else _aware(effective_from, "invalid_effective_from")
    )

    def change(session: Session) -> PlatformChange:
        exists = session.execute(
            select(AIPlanBudget.id).where(
                AIPlanBudget.plan_id == plan_id, AIPlanBudget.budget_version == budget_version
            )
        ).first()
        if exists is not None:
            raise AIBudgetError("version_exists")
        row = AIPlanBudget(
            plan_id=plan_id,
            budget_version=budget_version,
            currency=chosen_currency,
            monthly_amount=amount,
            effective_from=start,
            warn_thresholds=None if thresholds is None else list(thresholds),
        )
        session.add(row)
        try:
            session.flush()
        except IntegrityError as error:
            raise _integrity(error, {_FK_PLAN: "plan_unavailable"}, "version_exists") from None
        return PlatformChange(
            PlanBudgetView(plan_id, budget_version, chosen_currency, amount, start, thresholds),
            target_id=str(plan_id),
            metadata={
                "change": "set_plan_budget",
                "budget_version": budget_version,
                "currency": chosen_currency,
                "has_amount": amount is not None,
                "warn_thresholds": None if thresholds is None else list(thresholds),
            },
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PLAN_BUDGET_CONFIGURE,
        target_type=_TARGET_PLAN_BUDGET,
        change=change,
        reason=reason,
    )


@dataclass(frozen=True)
class BudgetOverrideView:
    tenant_id: uuid.UUID
    active: bool
    currency: str | None
    amount: Decimal | None
    reason: str | None
    expires_at: datetime | None
    version: int


def _override_view(tenant_id: uuid.UUID, row: AIBudgetOverride | None) -> BudgetOverrideView:
    if row is None:
        return BudgetOverrideView(tenant_id, False, None, None, None, None, 0)
    return BudgetOverrideView(
        tenant_id,
        bool(row.active),
        row.currency,
        row.amount,
        row.reason,
        row.expires_at,
        row.version,
    )


def _record_override_for_tenant(
    caller: object, tenant_id: uuid.UUID, action: str, metadata: dict[str, object]
) -> None:
    """The tenant's own audit row, after the override committed (module
    docstring). Never raises: the override is already in force."""
    try:
        with tenant_session_scope(tenant_id) as session:
            record_in_transaction(
                session,
                caller=caller,  # type: ignore[arg-type]  # vetted by run_platform_change: a person
                tenant_id=tenant_id,
                action=action,
                resource_type=_RESOURCE_BUDGET,
                resource_id=str(tenant_id),
                metadata={**metadata, "platform": True},
            )
    except Exception as error:  # noqa: BLE001 -- the override stands; evidence gap is logged
        logger.error(
            "ai_budget_override_tenant_audit_failed",
            extra={"ai_action": action, "error_type": type(error).__name__},
        )


def _locked_override(session: Session, tenant_id: uuid.UUID) -> AIBudgetOverride | None:
    return session.execute(
        select(AIBudgetOverride)
        .where(AIBudgetOverride.target_tenant_id == tenant_id)
        .with_for_update()
    ).scalar_one_or_none()


def set_tenant_budget_override(
    tenant_id: uuid.UUID,
    *,
    currency: str,
    amount: Decimal,
    reason: OverrideReason | str,
    expires_at: datetime,
    caller: object,
) -> BudgetOverrideView:
    """Replace one tenant's plan budget by `amount` in `currency` until
    `expires_at` (in the future, at most 366 days ahead). Setting it again
    replaces the previous override. The tenant's own cap still applies.
    Authority: `platform.ai_budget:manage`; runs as the
    platform-configuration role."""
    if not isinstance(tenant_id, uuid.UUID):
        raise AIBudgetError("tenant_unavailable")
    chosen_currency = _currency(currency)
    chosen_amount = _amount(amount)
    try:
        chosen_reason = OverrideReason(reason)
    except ValueError:
        raise AIBudgetError("invalid_reason") from None
    until = _aware(expires_at, "invalid_expiry")
    metadata: dict[str, object] = {
        "change": "override_set",
        "reason": chosen_reason.value,
        "currency": chosen_currency,
        "expires_at": until.isoformat(),
    }

    def change(session: Session) -> PlatformChange:
        at = database_time(session)
        if not at < until <= at + MAX_OVERRIDE_DURATION:
            raise AIBudgetError("invalid_expiry")
        row = _locked_override(session, tenant_id)
        if row is None:
            row = AIBudgetOverride(
                target_tenant_id=tenant_id,
                currency=chosen_currency,
                amount=chosen_amount,
                reason=chosen_reason.value,
                active=True,
                expires_at=until,
                set_at=at,
                cleared_at=None,
                version=1,
            )
            session.add(row)
        else:
            row.currency = chosen_currency
            row.amount = chosen_amount  # type: ignore[assignment]
            row.reason = chosen_reason.value
            row.active = True
            row.expires_at = until
            row.set_at = at
            row.cleared_at = None
            row.version += 1
        try:
            session.flush()
        except IntegrityError as error:
            raise _integrity(
                error, {_FK_TENANT: "tenant_unavailable"}, "tenant_unavailable"
            ) from None
        return PlatformChange(
            _override_view(tenant_id, row),
            target_id=str(tenant_id),
            target_tenant_id=tenant_id,
            metadata=metadata,
        )

    view = run_platform_change(
        caller=caller,
        operation=AI_BUDGET_OVERRIDE_SET,
        target_type=_TARGET_OVERRIDE,
        change=change,
        reason=chosen_reason.value,
    )
    _record_override_for_tenant(caller, tenant_id, ACTION_OVERRIDE_SET, metadata)
    return view


def clear_tenant_budget_override(tenant_id: uuid.UUID, *, caller: object) -> BudgetOverrideView:
    """End one tenant's override now: its plan budget applies again (the
    month's frozen plan part, lowered by any lower plan budget). Refused
    (`not_overridden`) when no override is active. Authority:
    `platform.ai_budget:manage`; runs as the platform-configuration role."""
    if not isinstance(tenant_id, uuid.UUID):
        raise AIBudgetError("tenant_unavailable")
    cleared: dict[str, object] = {}

    def change(session: Session) -> PlatformChange:
        row = _locked_override(session, tenant_id)
        if row is None or not row.active:
            raise AIBudgetError("not_overridden")
        cleared.update({"change": "override_clear", "reason": row.reason})
        row.active = False
        row.cleared_at = database_time(session)
        row.version += 1
        session.flush()
        return PlatformChange(
            _override_view(tenant_id, row),
            target_id=str(tenant_id),
            target_tenant_id=tenant_id,
            metadata=dict(cleared),
        )

    view = run_platform_change(
        caller=caller,
        operation=AI_BUDGET_OVERRIDE_CLEAR,
        target_type=_TARGET_OVERRIDE,
        change=change,
        reason=None,
    )
    _record_override_for_tenant(caller, tenant_id, ACTION_OVERRIDE_CLEAR, cleared)
    return view


@dataclass(frozen=True)
class ReleasedReservationView:
    tenant_id: uuid.UUID
    reservation_id: uuid.UUID
    amount: Decimal
    currency: str
    period_start: datetime


def release_budget_reservation(
    tenant_id: uuid.UUID, reservation_id: uuid.UUID, *, caller: object, reason: str
) -> ReleasedReservationView:
    """Release one `expired_unknown` reservation of `tenant_id`: its worst
    case leaves the month's `retained` amount and it becomes
    `operator_released`. For an operator who has established, outside SaaS
    OS (the provider's records), that the attempt was not charged. Only
    `expired_unknown` reservations can be released; a held one is resolved
    by its own settlement or the stale-attempt sweep. Authority:
    `platform.ai_budget:manage`, a person only; audited in the tenant's
    trail and the platform's, in one transaction."""
    if not isinstance(tenant_id, uuid.UUID) or not isinstance(reservation_id, uuid.UUID):
        raise AIBudgetError("reservation_unavailable")

    def change(session: Session) -> PlatformChange:
        row = session.execute(
            select(AIBudgetReservation)
            .where(
                AIBudgetReservation.id == reservation_id,
                AIBudgetReservation.tenant_id == tenant_id,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if row is None or row.state != ReservationState.EXPIRED_UNKNOWN.value:
            raise AIBudgetError("reservation_unavailable")
        period = session.execute(
            select(AIBudgetPeriod).where(AIBudgetPeriod.id == row.period_id).with_for_update()
        ).scalar_one()
        period.retained = max(Decimal(0), period.retained - row.amount)
        row.state = ReservationState.OPERATOR_RELEASED.value
        row.resolved_at = database_time(session)
        session.flush()
        return PlatformChange(
            ReleasedReservationView(
                tenant_id, reservation_id, row.amount, row.currency, period.period_start
            ),
            target_id=str(reservation_id),
            target_tenant_id=tenant_id,
            metadata={
                "change": "reservation_release",
                "currency": row.currency,
                "period_start": period.period_start.isoformat(),
            },
        )

    return run_tenant_platform_change(
        caller=caller,
        operation=AI_BUDGET_RESERVATION_RELEASE,
        target_type=_TARGET_RESERVATION,
        tenant_id=tenant_id,
        tenant_action=ACTION_RESERVATION_RELEASE,
        tenant_resource_type=_RESOURCE_BUDGET,
        change=change,
        reason=reason,
    )


__all__ = [
    "ACTION_OVERRIDE_CLEAR",
    "ACTION_OVERRIDE_SET",
    "ACTION_READ",
    "ACTION_RESERVATION_RELEASE",
    "ACTION_SET_CAP",
    "AIBudgetError",
    "BudgetOverrideView",
    "PlanBudgetView",
    "ReleasedReservationView",
    "TenantBudgetCapView",
    "clear_tenant_budget_override",
    "read_tenant_budget",
    "release_budget_reservation",
    "set_plan_budget",
    "set_tenant_budget_cap",
    "set_tenant_budget_override",
    "tenant_budget_status",
]
