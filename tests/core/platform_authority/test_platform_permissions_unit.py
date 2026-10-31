"""The platform-permission vocabulary (ADR-0045 section 4) -- hermetic.

Pins the closed vocabulary three ways: against a literal written in this
file (so a change is always a visible diff in two places), against the
literal in the latest migration that defines `ck_platform_grants_permission`
(a7f3c91e2d48, ADR-0054 AI-D), and by shape.
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
_VERSIONS = _REPO / "saas_os/infra/db/migrations/versions"
_ORIGINAL_MIGRATION = _VERSIONS / "c4a9e1f07b52_create_platform_authority_tables.py"
_AI_C_MIGRATION = _VERSIONS / "e4b8c2d6f1a3_create_ai_inference_configuration.py"
_AI_D_MIGRATION = _VERSIONS / "a7f3c91e2d48_create_ai_inference_attempts.py"
_MIGRATION = _VERSIONS / "b3d5f7a9c2e4_add_outbox_replay_permission.py"

# ADR-0045 section 4, in its order; ADR-0054 AI-C added four AI permissions and
# AI-D `platform.ai_usage:read`; the ADR-0045 amendment of 2026-10-31
# `platform.outbox:replay`.
_REVIEWED_VOCABULARY = (
    "platform.tenant:read",
    "platform.user:read",
    "platform.operator:read",
    "platform.audit:read",
    "platform.billing:read",
    "platform.feature_flag:read",
    "platform.ai_config:read",
    "platform.ai_usage:read",
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
    "platform.ai_provider:manage",
    "platform.ai_endpoint_trust:manage",
    "platform.ai_policy:manage",
    "platform.outbox:replay",
    "platform.authority:manage",
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _migration_permissions() -> tuple[str, ...]:
    return _load(_MIGRATION, "_ai_inference_migration").PLATFORM_PERMISSIONS


def test_vocabulary_is_exactly_the_twenty_four_reviewed_permissions_in_order() -> None:
    assert tuple(p.value for p in PlatformPermission) == _REVIEWED_VOCABULARY
    assert len(PlatformPermission) == 24
    assert PLATFORM_PERMISSION_VALUES == frozenset(_REVIEWED_VOCABULARY)


def test_migration_check_constraint_lists_exactly_the_vocabulary() -> None:
    assert _migration_permissions() == _REVIEWED_VOCABULARY


def test_the_widening_migration_restores_exactly_the_original_vocabulary() -> None:
    """Each widening's downgrade puts back exactly the constraint before it,
    and each upgrade only adds its reviewed permissions."""
    original = _load(_ORIGINAL_MIGRATION, "_platform_authority_migration")
    widening = _load(_AI_C_MIGRATION, "_ai_inference_migration_before")
    ai_d = _load(_AI_D_MIGRATION, "_ai_inference_attempts_migration")
    replay = _load(_MIGRATION, "_outbox_replay_migration")
    assert replay.PLATFORM_PERMISSIONS_BEFORE == ai_d.PLATFORM_PERMISSIONS
    assert set(replay.PLATFORM_PERMISSIONS) - set(ai_d.PLATFORM_PERMISSIONS) == {
        "platform.outbox:replay"
    }
    assert set(ai_d.PLATFORM_PERMISSIONS) <= set(replay.PLATFORM_PERMISSIONS)
    assert ai_d.PLATFORM_PERMISSIONS_BEFORE == widening.PLATFORM_PERMISSIONS
    assert set(ai_d.PLATFORM_PERMISSIONS) - set(widening.PLATFORM_PERMISSIONS) == {
        "platform.ai_usage:read"
    }
    assert widening.PLATFORM_PERMISSIONS_BEFORE == original.PLATFORM_PERMISSIONS
    added = set(widening.PLATFORM_PERMISSIONS) - set(original.PLATFORM_PERMISSIONS)
    assert added == {
        "platform.ai_config:read",
        "platform.ai_provider:manage",
        "platform.ai_endpoint_trust:manage",
        "platform.ai_policy:manage",
    }
    assert set(original.PLATFORM_PERMISSIONS) <= set(widening.PLATFORM_PERMISSIONS)


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
