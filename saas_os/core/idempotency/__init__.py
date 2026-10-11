"""`saas_os/core/idempotency` -- generic idempotency primitives for state-changing
Core operations a client may safely retry (P1.11).

Owns:
- the tenant-owned `IdempotencyRecord` entity (`core.idempotency_records`,
  RLS-protected) -- one reservation/outcome per `(tenant_id, operation,
  idempotency_key)`;
- `compute_fingerprint()`/`validate_idempotency_key()` -- the key/request
  contract every consumer shares;
- `run_idempotent()` -- full atomic (single-transaction) coupling, for a
  business operation with no external call in the middle;
- `begin_idempotent_operation()`/`finalize_idempotent_operation()` -- the
  two-step primitive for a business operation that must make an external
  call (e.g. a billing provider) in between;
- `purge_expired_idempotency_records()` for retention.

See `saas_os/core/idempotency/service.py`'s own module docstring for the full
contract, including the documented limitation of the two-step primitive
and the structural separation from `saas_os/core/webhooks`'s P1.10 replay
protection (a different mechanism, never merged with this one).

Real consumers: `saas_os.core.billing.service.subscribe_idempotent()` (two-step
-- calls a `BillingProvider`) and `saas_os.core.usage.service.consume_quota_idempotent()`
(fully atomic -- database-only).

Does NOT own: webhook replay protection (P1.10, `saas_os/core/webhooks`), job
deduplication (`saas_os/infra/jobs`' own retry/dead-letter semantics are
unrelated and untouched), any HTTP/API surface of its own (`saas_os/api/dependencies.py`
owns the one `Idempotency-Key` header-reading dependency that calls into
this module).
"""

from saas_os.core.idempotency.config import IdempotencyConfig, get_idempotency_config
from saas_os.core.idempotency.errors import (
    IdempotencyConfigurationError,
    IdempotencyInProgressError,
    IdempotencyKeyInvalidError,
    IdempotencyKeyReusedError,
)
from saas_os.core.idempotency.models import IdempotencyRecord
from saas_os.core.idempotency.service import (
    IdempotencyReservation,
    IdempotencyStatus,
    begin_idempotent_operation,
    compute_fingerprint,
    finalize_idempotent_operation,
    purge_expired_idempotency_records,
    run_idempotent,
    validate_idempotency_key,
)

__all__ = [
    "IdempotencyRecord",
    "IdempotencyStatus",
    "IdempotencyReservation",
    "IdempotencyConfig",
    "get_idempotency_config",
    "validate_idempotency_key",
    "compute_fingerprint",
    "run_idempotent",
    "begin_idempotent_operation",
    "finalize_idempotent_operation",
    "purge_expired_idempotency_records",
    "IdempotencyKeyInvalidError",
    "IdempotencyKeyReusedError",
    "IdempotencyInProgressError",
    "IdempotencyConfigurationError",
]
