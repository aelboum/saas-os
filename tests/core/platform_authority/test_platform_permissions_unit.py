"""The platform-permission vocabulary (ADR-0045 section 4) -- hermetic.

Pins the closed vocabulary three ways: against a literal written in this
file (so a change is always a visible diff in two places), against the
literal in the migration that creates `ck_platform_grants_permission`, and
by shape.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from saas_os.core.platform_authority import (
    OWNER_PERMISSION,
    PLATFORM_PERMISSION_VALUES,
    PlatformPermission,
)

_REPO = Path(__file__).resolve().parents[3]
_MIGRATION = (
    _REPO / "saas_os/infra/db/migrations/versions/c4a9e1f07b52_create_platform_authority_tables.py"
)

# ADR-0045 section 4, in its order.
_REVIEWED_VOCABULARY = (
    "platform.tenant:read",
    "platform.user:read",
    "platform.operator:read",
    "platform.audit:read",
    "platform.billing:read",
    "platform.feature_flag:read",
    "platform.tenant:create",
    "platform.tenant:suspend",
    "platform.tenant:reactivate",
    "platform.tenant:move",
    "platform.tenant:delete",
    "platform.user:deactivate",
    "platform.user:reactivate",
    "platform.session:revoke",
    "platform.api_key:revoke",
    "platform.feature_flag:define",
    "platform.feature_flag:override",
    "platform.authority:manage",
)


def _migration_permissions() -> tuple[str, ...]:
    spec = importlib.util.spec_from_file_location("_platform_authority_migration", _MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PLATFORM_PERMISSIONS


def test_vocabulary_is_exactly_the_eighteen_reviewed_permissions_in_order() -> None:
    assert tuple(p.value for p in PlatformPermission) == _REVIEWED_VOCABULARY
    assert len(PlatformPermission) == 18
    assert PLATFORM_PERMISSION_VALUES == frozenset(_REVIEWED_VOCABULARY)


def test_migration_check_constraint_lists_exactly_the_vocabulary() -> None:
    assert _migration_permissions() == _REVIEWED_VOCABULARY


def test_every_permission_is_namespaced_and_fits_the_column() -> None:
    for permission in PlatformPermission:
        resource, _, action = permission.value.partition(":")
        assert resource.startswith("platform.") and action, permission
        assert len(permission.value) <= 100, permission


def test_owner_permission_is_authority_manage() -> None:
    assert OWNER_PERMISSION is PlatformPermission.AUTHORITY_MANAGE


def test_no_permission_exists_for_infrastructure_operations() -> None:
    """Purge, erasure, migrations, backup, bootstrap and recovery are never
    grantable (ADR-0045 section 4)."""
    for word in ("purge", "erase", "erasure", "migrat", "backup", "bootstrap", "recover"):
        assert not any(word in p.value for p in PlatformPermission), word
