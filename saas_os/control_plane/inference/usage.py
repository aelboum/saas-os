"""Platform read of one tenant's AI usage totals (ADR-0054 Phase AI-D;
decision Q9: `platform.ai_usage:read` arrives with this operation).

Aggregates only -- attempt counts by state and token sums by provenance, per
provider and model, over a bounded window. No content, no request ids, no
actor identities. Audited as an oversight read (attempt and completion rows)
through `run_tenant_oversight_read`, which binds the one tenant's RLS scope
for the read and writes the platform rows outside it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from saas_os.control_plane.inference.attempts import AIInferenceAttempt
from saas_os.core.platform_authority import (
    InvalidPlatformRequestError,
    OversightOutcome,
    run_tenant_oversight_read,
)
from saas_os.core.platform_authority.operations import AI_USAGE_READ
from saas_os.infra.db import Session, select, sum_

MAX_WINDOW = timedelta(days=93)
_TARGET = "ai_usage"


@dataclass(frozen=True)
class AIUsageLine:
    provider_key: str
    model_id: str
    state: str
    usage_provenance: str
    attempts: int
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class AIUsageTotals:
    tenant_id: uuid.UUID
    since: datetime
    until: datetime
    lines: tuple[AIUsageLine, ...]


def _validate_window(since: datetime, until: datetime) -> None:
    if not isinstance(since, datetime) or not isinstance(until, datetime):
        raise InvalidPlatformRequestError("since and until must be datetimes.")
    if since.tzinfo is None or until.tzinfo is None:
        raise InvalidPlatformRequestError("since and until must be timezone-aware.")
    if not since < until or until - since > MAX_WINDOW:
        raise InvalidPlatformRequestError("the window must be positive and at most 93 days.")


def read_ai_usage_totals(
    *, caller: object, tenant_id: uuid.UUID, since: datetime, until: datetime
) -> AIUsageTotals:
    _validate_window(since, until)

    def read(session: Session) -> OversightOutcome[AIUsageTotals]:
        a = AIInferenceAttempt
        rows = session.execute(
            select(
                a.provider_key,
                a.model_id,
                a.state,
                a.usage_provenance,
                # `func` is deliberately not re-exported (CP-07 J-INFRA-05):
                # a row count is the SUM of a constant 1 per row.
                sum_(a.attempt_number - a.attempt_number + 1),
                sum_(a.input_tokens),
                sum_(a.output_tokens),
            )
            .where(a.tenant_id == tenant_id, a.started_at >= since, a.started_at < until)
            .group_by(a.provider_key, a.model_id, a.state, a.usage_provenance)
            .order_by(a.provider_key, a.model_id, a.state, a.usage_provenance)
        ).all()
        lines = tuple(
            AIUsageLine(
                provider_key=r[0],
                model_id=r[1],
                state=r[2],
                usage_provenance=r[3],
                attempts=int(r[4] or 0),
                input_tokens=int(r[5] or 0),
                output_tokens=int(r[6] or 0),
            )
            for r in rows
        )
        totals = AIUsageTotals(tenant_id=tenant_id, since=since, until=until, lines=lines)
        return OversightOutcome(value=totals, returned=len(lines))

    return run_tenant_oversight_read(
        caller=caller,
        operation=AI_USAGE_READ,
        tenant_id=tenant_id,
        target_type=_TARGET,
        read=read,
        request_metadata={"since": since.isoformat(), "until": until.isoformat()},
    )
