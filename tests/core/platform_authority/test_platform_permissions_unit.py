"""The platform-permission vocabulary (ADR-0045 section 4) -- hermetic.

Pins the closed vocabulary three ways: against a literal written in this
file (so a change is always a visible diff in two places), against the
literal in the latest migration that defines `ck_platform_grants_permission`
(a9c3e5f7b1d4, the ADR-0045 amendment of 2026-11-02), and by shape.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from saas_os.core.platform_authority import (
    OWNER_PERMISSION,
    PLATFORM_PERMISSION_VALUES,
    PlatformPermission,
)

P = PlatformPermission

_REPO = Path(__file__).resolve().parents[3]
_VERSIONS = _REPO / "saas_os/infra/db/migrations/versions"
_ORIGINAL_MIGRATION = _VERSIONS / "c4a9e1f07b52_create_platform_authority_tables.py"
_AI_C_MIGRATION = _VERSIONS / "e4b8c2d6f1a3_create_ai_inference_configuration.py"
_AI_D_MIGRATION = _VERSIONS / "a7f3c91e2d48_create_ai_inference_attempts.py"
_REPLAY_MIGRATION = _VERSIONS / "b3d5f7a9c2e4_add_outbox_replay_permission.py"
_REENCRYPT_MIGRATION = _VERSIONS / "c5e8a1d3f7b2_add_webhook_secret_reencrypt_permission.py"
_GRANTS_MIGRATION = _VERSIONS / "d7e2a9c4f1b6_add_permission_grant_apply_permission.py"
_MIGRATION = _VERSIONS / "a9c3e5f7b1d4_create_core_permission_grant_ledger_holds.py"

# ADR-0045 section 4, in its order; ADR-0054 AI-C added four AI permissions and
# AI-D `platform.ai_usage:read`; the ADR-0045 amendment of 2026-10-31
# `platform.outbox:replay`, and the amendments of 2026-11-01
# `platform.webhook_secret:reencrypt` (finding F7, PR #192) and then
# `platform.permission_grant:apply` (ADR 0060); the amendment of 2026-11-02
# (owner decision A) the two security-retention permissions.
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
    "platform.webhook_secret:reencrypt",  # pragma: allowlist secret
    "platform.permission_grant:apply",
    "platform.security_retention:report",
    "platform.security_retention_hold:manage",
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


def test_vocabulary_is_exactly_the_twenty_eight_reviewed_permissions_in_order() -> None:
    assert tuple(p.value for p in PlatformPermission) == _REVIEWED_VOCABULARY
    assert len(PlatformPermission) == 28
    assert PLATFORM_PERMISSION_VALUES == frozenset(_REVIEWED_VOCABULARY)


def test_migration_check_constraint_lists_exactly_the_vocabulary() -> None:
    assert _migration_permissions() == _REVIEWED_VOCABULARY


def test_the_widening_migration_restores_exactly_the_original_vocabulary() -> None:
    """Each widening's downgrade puts back exactly the constraint before it,
    and each upgrade adds exactly its reviewed permissions, listed here."""
    original = _load(_ORIGINAL_MIGRATION, "_platform_authority_migration")
    widening = _load(_AI_C_MIGRATION, "_ai_inference_migration_before")
    ai_d = _load(_AI_D_MIGRATION, "_ai_inference_attempts_migration")
    replay = _load(_REPLAY_MIGRATION, "_outbox_replay_migration")
    reencrypt = _load(_REENCRYPT_MIGRATION, "_webhook_secret_reencrypt_migration")
    grants = _load(_GRANTS_MIGRATION, "_permission_grant_apply_migration")
    holds = _load(_MIGRATION, "_permission_grant_ledger_holds_migration")
    # PR #192's step first, then ADR 0060's, then the retention step (owner
    # decision A of 2026-11-02, two permissions in the holds migration):
    # each widening starts from exactly the list the previous step ended
    # with and adds exactly the set listed for it.
    chain = (
        (ai_d, replay, {"platform.outbox:replay"}),
        (replay, reencrypt, {"platform.webhook_secret:reencrypt"}),  # pragma: allowlist secret
        (reencrypt, grants, {"platform.permission_grant:apply"}),
        (
            grants,
            holds,
            {"platform.security_retention:report", "platform.security_retention_hold:manage"},
        ),
    )
    for previous, step, added in chain:
        assert step.PLATFORM_PERMISSIONS_BEFORE == previous.PLATFORM_PERMISSIONS
        assert set(step.PLATFORM_PERMISSIONS) - set(previous.PLATFORM_PERMISSIONS) == added
        assert len(step.PLATFORM_PERMISSIONS) == len(previous.PLATFORM_PERMISSIONS) + len(added)
        assert len(set(step.PLATFORM_PERMISSIONS)) == len(step.PLATFORM_PERMISSIONS)
        assert set(previous.PLATFORM_PERMISSIONS) <= set(step.PLATFORM_PERMISSIONS)
    assert tuple(holds.RETENTION_PERMISSIONS) == (
        "platform.security_retention:report",
        "platform.security_retention_hold:manage",
    )
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


def test_every_action_is_one_lower_case_word() -> None:
    """The naming convention every permission follows: `platform.<resource>`
    in snake_case, then one verb (`read`, `manage`, `report`, ...). A
    compound subject goes into the resource (`ai_endpoint_trust:manage`,
    `security_retention_hold:manage`), never into the verb."""
    for permission in PlatformPermission:
        resource, _, action = permission.value.partition(":")
        assert action.isalpha() and action.islower(), permission
        assert all(part.replace("_", "").isalpha() for part in resource.split(".")), permission


def test_retention_permissions_are_separate_from_permission_grant_apply() -> None:
    """Owner decision A of 2026-11-02: least privilege. The report and the
    holds have their own permissions; none implies another (a grant is
    exactly one permission, and `platform_can()` matches it exactly)."""
    retention = {P.SECURITY_RETENTION_REPORT, P.SECURITY_RETENTION_HOLD_MANAGE}
    assert len(retention | {P.PERMISSION_GRANT_APPLY}) == 3
    assert OWNER_PERMISSION not in retention


def test_owner_permission_is_authority_manage() -> None:
    assert OWNER_PERMISSION is PlatformPermission.AUTHORITY_MANAGE


def test_no_permission_exists_for_infrastructure_operations() -> None:
    """Purge, erasure, migrations, backup, bootstrap and recovery are never
    grantable (ADR-0045 section 4)."""
    for word in ("purge", "erase", "erasure", "migrat", "backup", "bootstrap", "recover"):
        assert not any(word in p.value for p in PlatformPermission), word
