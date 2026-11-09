"""A tenant's own AI usage report (ADR-0054 amendment of 2026-11-09; Gap 22a,
owner decisions of that day).

`read_tenant_ai_usage` aggregates the tenant's `ai_inference_attempts` over a
bounded window: attempt counts by state, token sums, **estimated** cost per
currency, and how much of that the totals do not include (attempts with
unknown usage, attempts with no price). It is a read over tenant-owned rows
inside the tenant's own RLS scope; there is no write path and no new ledger.

**Isolation.** The read runs in the tenant's own RLS scope. An unknown tenant and a
tenant the caller has no membership in are refused identically.

**Authority.** The tenant permission `ai.usage:read`, which no other
permission implies (not `billing.subscription:read`, not `ai.policy:read`) and
which SaaS OS grants to no role (ADR-0060 review note: a product binds it, by
default to owners and administrators). A user only: a service account or a
system purpose is refused (owner decision: self view and service accounts are
out of v1). Support access never satisfies it
(`AI_SUPPORT_ACCESS_EXCLUDED_ACTIONS`; owner decision: denied by default).
There is no descendant or parent roll-up: a report is for one tenant and
never merges another (owner decision: parent roll-up is out of v1).

**Evidence.** Every allowed read writes one `ai.usage.read` tenant audit row
in the same transaction as the read, holding the window and the grouping only
-- no figure, no content, no identity beyond the audit actor. If the audit
write fails the read fails. A refusal writes a `denied` row after the refused
transaction rolled back.

**What it returns and does not.** Counts, token sums, cost sums and closed
vocabulary keys (provider, model, use case, state, provenance, UTC day). Never
a prompt, a completion, a provider request id, a credential, the stored
`decision` JSON, `other_usage` or an error detail. Cost is an *estimate*
priced with the price version in effect when the attempt settled; it is not an
invoice and the report never says "bill" or "hard limit". Money is a `Decimal`
per currency, never summed across currencies. Provenance stays visible:
`provider_reported` and `estimated` tokens are reported separately and
`unknown` is counted, never treated as zero tokens.

**Basis.** The report reads the attempt rows that exist. No retention period
is promised here (`ai_inference_attempts` is `DEFERRED_POLICY`; the owner's
target of 90 days is not yet enforced).

**Limits block.** The soft monthly token quota (`ai.tokens`, current UTC
month, the same recorded sums admission uses) with its `invalid` and
`unavailable` states kept distinct from "no limit". The budget block reports
`unconfigured` until Gap 21 ships.
"""

from __future__ import annotations

import enum
import logging
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from saas_os.control_plane.inference.accounting import (
    _limit,  # pyright: ignore[reportPrivateUsage]
    month_window,
)
from saas_os.control_plane.inference.attempts import AIInferenceAttempt
from saas_os.control_plane.inference.errors import InferenceQuotaExceededError
from saas_os.control_plane.inference.permissions import AI_USAGE
from saas_os.core.audit_log import ActorType, AuditOutcome, record, record_in_transaction
from saas_os.core.authority import ServiceAccountCaller, UserCaller, require_caller
from saas_os.core.billing import get_entitlements
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import authorize_caller
from saas_os.infra.db import IntegrityError, Session, select, sum_, tenant_session_scope

logger = logging.getLogger(__name__)

MAX_WINDOW = timedelta(days=93)
ACTION_READ = "ai.usage.read"
_OPERATION = "ai_usage.read_tenant"
_RESOURCE_TYPE = "ai_usage"
BASIS_ROWS_PRESENT = "rows_present"
QUOTA_BASIS = "soft_monthly_token_quota"
BUDGET_UNCONFIGURED = "unconfigured"


class AIUsageGroupBy(enum.StrEnum):
    """The closed set of groupings."""

    PROVIDER = "provider"
    MODEL = "model"
    USE_CASE = "use_case"
    DAY = "day"
    PROVENANCE = "provenance"
    STATE = "state"


class AIUsageReadError(ValueError):
    """A refused usage request; nothing was read or audited as a success.
    `reason` is a short code: `invalid_group_by`, `invalid_window`."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"tenant AI usage read refused: {reason}")


@dataclass(frozen=True)
class AICostAmount:
    """Estimated cost in one currency. Never summed across currencies."""

    currency: str
    estimated: Decimal


@dataclass(frozen=True)
class AIProvenanceTokens:
    provenance: str
    attempts: int
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class AIUsageAmounts:
    """What one group (or the whole window) adds up to, and what it leaves
    out: `usage_unknown_attempts` have no token counts (contributing none),
    `cost_unknown_attempts` have no price (contributing no cost)."""

    attempts: int
    attempts_by_state: tuple[tuple[str, int], ...]
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    tokens_by_provenance: tuple[AIProvenanceTokens, ...]
    cost: tuple[AICostAmount, ...]
    usage_unknown_attempts: int
    cost_unknown_attempts: int


@dataclass(frozen=True)
class AIUsageGroup:
    key: str
    amounts: AIUsageAmounts


@dataclass(frozen=True)
class AIQuotaStatus:
    """The soft monthly token quota. `state`: `unlimited` (no `ai.tokens`;
    `limit` and `remaining` are `None`), `ok`, `exhausted`, `invalid` (a
    malformed plan value; never read as unlimited) or `unavailable`."""

    state: str
    limit: int | None
    used: int | None
    remaining: int | None
    basis: str = QUOTA_BASIS


@dataclass(frozen=True)
class AIBudgetStatus:
    state: str = BUDGET_UNCONFIGURED


@dataclass(frozen=True)
class AIUsageReport:
    tenant_id: uuid.UUID
    since: datetime
    until: datetime
    group_by: AIUsageGroupBy
    basis: str
    totals: AIUsageAmounts
    groups: tuple[AIUsageGroup, ...]
    quota: AIQuotaStatus
    budget: AIBudgetStatus


@dataclass(frozen=True)
class _Row:
    """One aggregate row: the finest grain the query returns."""

    provider_key: str
    model_id: str
    use_case: str
    state: str
    provenance: str
    currency: str | None
    cost_unknown: bool
    attempts: int
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    cost: Decimal


def _validate(
    since: datetime | None, until: datetime | None, group_by: object
) -> tuple[datetime, datetime, AIUsageGroupBy]:
    try:
        grouping = AIUsageGroupBy(group_by)
    except ValueError:
        raise AIUsageReadError("invalid_group_by") from None
    if (since is None) != (until is None):
        raise AIUsageReadError("invalid_window")
    if since is None or until is None:
        since, until = month_window()
    if not isinstance(since, datetime) or not isinstance(until, datetime):
        raise AIUsageReadError("invalid_window")
    if since.tzinfo is None or until.tzinfo is None:
        raise AIUsageReadError("invalid_window")
    since, until = since.astimezone(UTC), until.astimezone(UTC)
    if not since < until or until - since > MAX_WINDOW:
        raise AIUsageReadError("invalid_window")
    return since, until, grouping


def _money(value: object) -> Decimal:
    """A summed `numeric` as a `Decimal`; `NULL` (no priced row) is zero here,
    and the rows that had no price are counted separately."""
    return value if isinstance(value, Decimal) else Decimal(0)


def _aggregate(
    session: Session, tenant_id: uuid.UUID, since: datetime, until: datetime
) -> list[_Row]:
    a = AIInferenceAttempt
    result = session.execute(
        select(
            a.provider_key,
            a.model_id,
            a.use_case,
            a.state,
            a.usage_provenance,
            a.currency,
            a.estimated_cost.is_(None),
            # `func` is deliberately not re-exported (CP-07 J-INFRA-05): a row
            # count is the SUM of a constant 1 per row.
            sum_(a.attempt_number - a.attempt_number + 1),
            sum_(a.input_tokens),
            sum_(a.output_tokens),
            sum_(a.cached_input_tokens),
            sum_(a.estimated_cost),
        )
        .where(a.tenant_id == tenant_id, a.started_at >= since, a.started_at < until)
        .group_by(
            a.provider_key,
            a.model_id,
            a.use_case,
            a.state,
            a.usage_provenance,
            a.currency,
            a.estimated_cost.is_(None),
        )
    ).all()
    return [
        _Row(
            provider_key=r[0],
            model_id=r[1],
            use_case=r[2],
            state=r[3],
            provenance=r[4],
            currency=r[5],
            cost_unknown=bool(r[6]),
            attempts=int(r[7] or 0),
            input_tokens=int(r[8] or 0),
            output_tokens=int(r[9] or 0),
            cached_input_tokens=int(r[10] or 0),
            cost=_money(r[11]),
        )
        for r in result
    ]


def _days(since: datetime, until: datetime) -> list[tuple[str, datetime, datetime]]:
    """UTC calendar-day slices of `[since, until)`; the first and last may be
    partial. The key is the slice's UTC date."""
    slices: list[tuple[str, datetime, datetime]] = []
    cursor = since
    while cursor < until:
        midnight = (cursor + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        end = min(midnight, until)
        slices.append((cursor.date().isoformat(), cursor, end))
        cursor = end
    return slices


def _fold(rows: Iterable[_Row]) -> AIUsageAmounts:
    by_state: dict[str, int] = {}
    by_provenance: dict[str, list[int]] = {}
    cost: dict[str, Decimal] = {}
    attempts = inputs = outputs = cached = usage_unknown = cost_unknown = 0
    for row in rows:
        attempts += row.attempts
        inputs += row.input_tokens
        outputs += row.output_tokens
        cached += row.cached_input_tokens
        by_state[row.state] = by_state.get(row.state, 0) + row.attempts
        bucket = by_provenance.setdefault(row.provenance, [0, 0, 0])
        bucket[0] += row.attempts
        bucket[1] += row.input_tokens
        bucket[2] += row.output_tokens
        if row.provenance == "unknown":
            usage_unknown += row.attempts
        if row.cost_unknown:
            cost_unknown += row.attempts
        elif row.currency is not None:
            cost[row.currency] = cost.get(row.currency, Decimal(0)) + row.cost
    return AIUsageAmounts(
        attempts=attempts,
        attempts_by_state=tuple(sorted(by_state.items())),
        input_tokens=inputs,
        output_tokens=outputs,
        cached_input_tokens=cached,
        tokens_by_provenance=tuple(
            AIProvenanceTokens(p, v[0], v[1], v[2]) for p, v in sorted(by_provenance.items())
        ),
        cost=tuple(AICostAmount(c, v) for c, v in sorted(cost.items())),
        usage_unknown_attempts=usage_unknown,
        cost_unknown_attempts=cost_unknown,
    )


_KEYS: Mapping[AIUsageGroupBy, Callable[[_Row], str]] = {
    AIUsageGroupBy.PROVIDER: lambda r: r.provider_key,
    AIUsageGroupBy.MODEL: lambda r: f"{r.provider_key}/{r.model_id}",
    AIUsageGroupBy.USE_CASE: lambda r: r.use_case,
    AIUsageGroupBy.PROVENANCE: lambda r: r.provenance,
    AIUsageGroupBy.STATE: lambda r: r.state,
}


def _quota(
    session: Session,
    tenant_id: uuid.UUID,
    entitlements: Callable[[uuid.UUID], Mapping[str, object]],
) -> AIQuotaStatus:
    """The same projection source admission uses: recorded input plus output
    tokens of the current UTC month, against `ai.tokens`."""
    try:
        limit = _limit(entitlements(tenant_id))
    except InferenceQuotaExceededError:
        return AIQuotaStatus("invalid", None, None, None)
    except Exception:  # noqa: BLE001 -- unreadable configuration is reported, not hidden
        logger.warning("ai_usage_quota_unavailable")
        return AIQuotaStatus("unavailable", None, None, None)
    since, until = month_window()
    a = AIInferenceAttempt
    inputs, outputs = session.execute(
        select(sum_(a.input_tokens), sum_(a.output_tokens)).where(
            a.tenant_id == tenant_id, a.started_at >= since, a.started_at < until
        )
    ).one()
    used = int(inputs or 0) + int(outputs or 0)
    if limit is None:
        return AIQuotaStatus("unlimited", None, used, None)
    return AIQuotaStatus("exhausted" if used >= limit else "ok", limit, used, max(limit - used, 0))


def _record_denied(tenant_id: uuid.UUID, caller: UserCaller | ServiceAccountCaller) -> None:
    """The refusal row. A refusal for a tenant that does not exist (or for a
    service account that does not belong to it) has nothing to attach evidence
    to: the audit foreign key refuses the row, and that must not turn the
    refusal into a different error -- an unknown tenant and a foreign one stay
    indistinguishable. Any other failure to write it propagates."""
    is_user = isinstance(caller, UserCaller)
    try:
        record(
            tenant_id=tenant_id,
            actor_type=ActorType.USER if is_user else ActorType.SERVICE_ACCOUNT,
            actor_user_id=caller.user_id if isinstance(caller, UserCaller) else None,
            actor_service_account_id=(
                caller.service_account_id if isinstance(caller, ServiceAccountCaller) else None
            ),
            action=ACTION_READ,
            resource_type=_RESOURCE_TYPE,
            outcome=AuditOutcome.DENIED,
            metadata={"reason": "not_authorized"},
        )
    except IntegrityError:
        logger.info("ai_usage_denied_audit_not_attachable")


def read_tenant_ai_usage(
    tenant_id: uuid.UUID,
    *,
    caller: object,
    since: datetime | None = None,
    until: datetime | None = None,
    group_by: AIUsageGroupBy | str = AIUsageGroupBy.PROVIDER,
    entitlements: Callable[[uuid.UUID], Mapping[str, object]] = get_entitlements,
) -> AIUsageReport:
    """The tenant's AI usage over `[since, until)` (both or neither; default
    the current UTC month; at most 93 days), grouped by `group_by`. Authority:
    `ai.usage:read` at the tenant, a user only. See the module docstring."""
    require_caller(_OPERATION, caller)
    # Users only: a service account or a system purpose never reads usage (v1).
    if not isinstance(caller, UserCaller):
        if isinstance(caller, ServiceAccountCaller):
            _record_denied(tenant_id, caller)
        raise AuthorityNotAuthorizedError(_OPERATION, tenant_id)
    since_utc, until_utc, grouping = _validate(since, until, group_by)
    # No `require_open_tenant`: a read-only path never calls it (a closed tenant's
    # usage stays readable), and an existence check ahead of authorization would
    # tell a caller that a tenant it does not belong to exists. An unknown tenant
    # and a tenant the caller is not a member of are refused identically by
    # `authorize_caller`.
    try:
        with tenant_session_scope(tenant_id) as session:
            authorize_caller(
                caller,
                session=session,
                operation=_OPERATION,
                tenant_id=tenant_id,
                resource=AI_USAGE,
                action="read",
            )
            if grouping is AIUsageGroupBy.DAY:
                per_day = {
                    key: _aggregate(session, tenant_id, start, end)
                    for key, start, end in _days(since_utc, until_utc)
                }
                rows = [row for day_rows in per_day.values() for row in day_rows]
                groups = tuple(
                    AIUsageGroup(key, _fold(day_rows)) for key, day_rows in per_day.items()
                )
            else:
                rows = _aggregate(session, tenant_id, since_utc, until_utc)
                keyed: dict[str, list[_Row]] = {}
                for row in rows:
                    keyed.setdefault(_KEYS[grouping](row), []).append(row)
                groups = tuple(AIUsageGroup(key, _fold(keyed[key])) for key in sorted(keyed))
            quota = _quota(session, tenant_id, entitlements)
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action=ACTION_READ,
                resource_type=_RESOURCE_TYPE,
                resource_id=str(tenant_id),
                metadata={
                    "since": since_utc.isoformat(),
                    "until": until_utc.isoformat(),
                    "group_by": grouping.value,
                },
            )
            return AIUsageReport(
                tenant_id=tenant_id,
                since=since_utc,
                until=until_utc,
                group_by=grouping,
                basis=BASIS_ROWS_PRESENT,
                totals=_fold(rows),
                groups=groups,
                quota=quota,
                budget=AIBudgetStatus(),
            )
    except AuthorityNotAuthorizedError:
        _record_denied(tenant_id, caller)
        raise


__all__ = [
    "ACTION_READ",
    "MAX_WINDOW",
    "AIBudgetStatus",
    "AICostAmount",
    "AIProvenanceTokens",
    "AIQuotaStatus",
    "AIUsageAmounts",
    "AIUsageGroup",
    "AIUsageGroupBy",
    "AIUsageReadError",
    "AIUsageReport",
    "read_tenant_ai_usage",
]
