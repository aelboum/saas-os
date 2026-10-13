"""`saas_os/core/tenancy` configuration (architecture research: universal
multi-tenant tenancy, Phase A). Mirrors `saas_os/core/idempotency/config.py`'s own
shape exactly: a plain, non-secret tunable read directly from the
environment, validated, cached process-wide.

One tunable:

- `TENANT_MAX_HIERARCHY_DEPTH` -- an *operational* guardrail on how deep a
  tenant may be placed in the hierarchy (root = depth 0). The data model
  itself (`core.tenant_ancestry`) supports arbitrary depth; this exists so
  a runaway or malicious chain of moves/creates cannot grow a tree without
  bound, not because depth beyond it is architecturally meaningless.
  Default 6: covers the deepest scenario the architecture research
  actually modeled (holding -> company -> branch -> department -> team,
  with one level of headroom) while keeping ancestor-chain size, and any
  future hierarchy-aware authorization/RLS work built on top of it,
  bounded by construction. Deployments with a genuine need for a deeper
  tree can raise it; nothing here hardcodes 6 into the schema.

Missing configuration always falls back to this safe default -- never to
"unbounded."

- `PLATFORM_TENANT_ID` -- the deployment-level designation of which
  ordinary tenant is "the platform": the tenant that owns the
  deployment's own `saas_os.core.billing` merchant account and platform-owned
  plans (docs/ADR/0029-commercial-parties-and-billing-relationships.md,
  Decision 0.2). Deliberately a *configuration value*, not a tenant
  attribute: there is no `is_platform` column and no platform tenant
  type -- the platform is a normal `core.tenants` row, and which one plays
  that role is a per-deployment fact (each deployment has its own
  database, ADR-0015). Unlike the depth guardrail it has **no default**:
  unset means "no platform tenant is designated", and every operation
  that needs one fails closed (`PlatformTenantNotConfiguredError`,
  `saas_os/core/tenancy/service.py::get_platform_tenant_id()`) rather than
  guessing. A malformed value is a configuration error, raised as soon as
  the configuration is read.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from functools import lru_cache

from saas_os.core.tenancy.errors import TenancyConfigurationError

_DEFAULT_MAX_HIERARCHY_DEPTH = 6


@dataclass(frozen=True)
class TenancyConfig:
    max_hierarchy_depth: int = _DEFAULT_MAX_HIERARCHY_DEPTH
    platform_tenant_id: uuid.UUID | None = None

    def __post_init__(self) -> None:
        if self.max_hierarchy_depth < 1:
            raise TenancyConfigurationError(
                f"TENANT_MAX_HIERARCHY_DEPTH must be >= 1, got: {self.max_hierarchy_depth}"
            )


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise TenancyConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _parse_uuid(name: str, raw: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw.strip())
    except ValueError as exc:
        raise TenancyConfigurationError(f"{name} must be a UUID, got: {raw!r}") from exc


def _tenancy_config_from_env() -> TenancyConfig:
    max_depth_raw = os.environ.get("TENANT_MAX_HIERARCHY_DEPTH")
    platform_tenant_raw = os.environ.get("PLATFORM_TENANT_ID")
    return TenancyConfig(
        max_hierarchy_depth=(
            _parse_int("TENANT_MAX_HIERARCHY_DEPTH", max_depth_raw)
            if max_depth_raw is not None
            else _DEFAULT_MAX_HIERARCHY_DEPTH
        ),
        platform_tenant_id=(
            _parse_uuid("PLATFORM_TENANT_ID", platform_tenant_raw)
            if platform_tenant_raw is not None and platform_tenant_raw.strip()
            else None
        ),
    )


@lru_cache
def get_tenancy_config() -> TenancyConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need a different value should call
    `get_tenancy_config.cache_clear()` after `monkeypatch.setenv(...)`.
    """
    return _tenancy_config_from_env()
