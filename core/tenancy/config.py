"""`core/tenancy` configuration (architecture research: universal
multi-tenant tenancy, Phase A). Mirrors `core/idempotency/config.py`'s own
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
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from core.tenancy.errors import TenancyConfigurationError

_DEFAULT_MAX_HIERARCHY_DEPTH = 6


@dataclass(frozen=True)
class TenancyConfig:
    max_hierarchy_depth: int = _DEFAULT_MAX_HIERARCHY_DEPTH

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


def _tenancy_config_from_env() -> TenancyConfig:
    max_depth_raw = os.environ.get("TENANT_MAX_HIERARCHY_DEPTH")
    return TenancyConfig(
        max_hierarchy_depth=(
            _parse_int("TENANT_MAX_HIERARCHY_DEPTH", max_depth_raw)
            if max_depth_raw is not None
            else _DEFAULT_MAX_HIERARCHY_DEPTH
        )
    )


@lru_cache
def get_tenancy_config() -> TenancyConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need a different value should call
    `get_tenancy_config.cache_clear()` after `monkeypatch.setenv(...)`.
    """
    return _tenancy_config_from_env()
