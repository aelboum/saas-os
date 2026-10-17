"""Admission of governed inference (ADR-0054 section 7; decision Q12;
AI-INFERENCE-CONTRACTS section 5).

Before any provider content is sent:

1. **Entitlement.** The tenant's plan must grant the boolean entitlement
   `ai.inference` (`saas_os.core.billing.has_entitlement`). Missing,
   non-boolean or unreadable entitlement information denies
   (`InferenceEntitlementDeniedError`).
2. **Bounded concurrency.** One slot of the tenant's limit *and* one of the
   installation-wide limit, held as one Redis lease across all application
   instances (`saas_os.infra.ratelimit.ConcurrencyLeases`). Full: the
   request is refused (`InferenceCapacityExhaustedError`, logged as
   `ai_inference_capacity_exhausted` with the full scope). Redis unavailable:
   refused, fail closed (`InferenceInternalError("admission_unavailable")`)
   -- never admitted without a slot.

The lease expires on its own after the request's total deadline plus a
margin, so a crashed process frees its slot; it is released on every exit
path (success, error, cancellation). Releasing an expired lease is a no-op
and cannot release another request's slot.

Limits are provisional (P-ROADMAP ledger) and read from
`AI_INFERENCE_TENANT_CONCURRENCY` (default 4) and
`AI_INFERENCE_GLOBAL_CONCURRENCY` (default 64).
"""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from saas_os.control_plane.inference.errors import (
    InferenceCapacityExhaustedError,
    InferenceEntitlementDeniedError,
    InferenceInternalError,
)
from saas_os.core.billing import has_entitlement
from saas_os.infra.ratelimit import (
    ConcurrencyLeases,
    Lease,
    LeaseRefusal,
    LeaseScope,
    RateLimitBackendError,
    get_ratelimit_config,
)

logger = logging.getLogger(__name__)

ENTITLEMENT_KEY = "ai.inference"
PROVISIONAL_TENANT_CONCURRENCY = 4
PROVISIONAL_GLOBAL_CONCURRENCY = 64
LEASE_MARGIN_SECONDS = 30.0
_GLOBAL_SCOPE = "ai_inference:global"


def _limit(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise InferenceInternalError(f"invalid_{name.lower()}") from exc
    if not 0 < value <= 100_000:
        raise InferenceInternalError(f"invalid_{name.lower()}")
    return value


@dataclass(frozen=True)
class ConcurrencyLimits:
    tenant: int
    installation: int

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ConcurrencyLimits:
        source = os.environ if env is None else env
        return cls(
            tenant=_limit(
                source, "AI_INFERENCE_TENANT_CONCURRENCY", PROVISIONAL_TENANT_CONCURRENCY
            ),
            installation=_limit(
                source, "AI_INFERENCE_GLOBAL_CONCURRENCY", PROVISIONAL_GLOBAL_CONCURRENCY
            ),
        )


class Admission(Protocol):
    async def admit(self, tenant_id: uuid.UUID, *, ttl_seconds: float) -> object: ...

    async def release(self, slot: object) -> None: ...


def check_entitlement(
    tenant_id: uuid.UUID, *, check: Callable[[uuid.UUID, str], bool] = has_entitlement
) -> None:
    """Fail closed: anything but a literal `True` denies, including an
    error while reading the entitlement."""
    try:
        entitled = check(tenant_id, ENTITLEMENT_KEY)
    except Exception as exc:  # noqa: BLE001 -- unreadable entitlement information denies
        raise InferenceEntitlementDeniedError("entitlement_unavailable") from exc
    if entitled is not True:
        raise InferenceEntitlementDeniedError("not_entitled")


class RedisAdmission:
    """Per-tenant and installation-wide concurrency, one atomic lease."""

    def __init__(
        self,
        *,
        leases: ConcurrencyLeases | None = None,
        limits: ConcurrencyLimits | None = None,
    ) -> None:
        self._leases = leases
        self._limits = limits

    def _resolved(self) -> tuple[ConcurrencyLeases, ConcurrencyLimits]:
        leases = self._leases
        if leases is None:
            config = get_ratelimit_config()
            leases = ConcurrencyLeases(
                redis_url=config.redis_url,
                timeout_seconds=config.redis_timeout_seconds,
                key_prefix=f"{config.key_prefix}:lease",
            )
            self._leases = leases
        limits = self._limits or ConcurrencyLimits.from_env()
        return leases, limits

    async def admit(self, tenant_id: uuid.UUID, *, ttl_seconds: float) -> Lease:
        try:
            leases, limits = self._resolved()
            outcome = await leases.acquire(
                (
                    LeaseScope(f"ai_inference:tenant:{tenant_id}", limits.tenant),
                    LeaseScope(_GLOBAL_SCOPE, limits.installation),
                ),
                ttl_seconds=ttl_seconds + LEASE_MARGIN_SECONDS,
            )
        except RateLimitBackendError as exc:
            logger.warning("ai_inference_admission_unavailable")
            raise InferenceInternalError("admission_unavailable") from exc
        except InferenceInternalError:
            raise
        except Exception as exc:  # noqa: BLE001 -- misconfiguration fails closed
            logger.warning(
                "ai_inference_admission_unavailable", extra={"error_type": type(exc).__name__}
            )
            raise InferenceInternalError("admission_unavailable") from exc
        if isinstance(outcome, LeaseRefusal):
            scope = "installation" if outcome.scope == _GLOBAL_SCOPE else "tenant"
            logger.warning("ai_inference_capacity_exhausted", extra={"ai_capacity_scope": scope})
            raise InferenceCapacityExhaustedError(f"{scope}_concurrency")
        return outcome

    async def release(self, slot: object) -> None:
        if isinstance(slot, Lease) and self._leases is not None:
            await self._leases.release(slot)
