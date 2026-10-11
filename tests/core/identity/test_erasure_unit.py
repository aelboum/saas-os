"""RA-12-3 -- pure unit tests for `saas_os.core.identity.erasure`: the result
dataclass's own shape and the module's declared, non-database-dependent
properties. No database needed; the real end-to-end erasure flow is
covered by `tests/core/identity/test_erasure_integration.py`.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest

from saas_os.core.identity.erasure import IdentityErasureResult


def test_result_reports_zero_effect_when_nothing_was_found() -> None:
    """The exact shape a nonexistent id, a never-a-member id, and an
    already-fully-erased id all produce -- see `erase_user_identity()`'s
    own non-enumeration docstring."""
    result = IdentityErasureResult(
        user_id=uuid.uuid4(),
        external_identities_deleted=0,
        sessions_deleted=0,
    )
    assert result.tenants_with_membership_removed == ()
    assert result.memberships_removed == 0
    assert result.api_keys_deleted == 0
    assert result.notifications_deleted == 0
    assert result.membership_roles_deleted == 0
    assert result.checked_tenant_ids == ()


def test_memberships_removed_reflects_only_tenants_actually_touched() -> None:
    checked = (uuid.uuid4(), uuid.uuid4(), uuid.uuid4())
    touched = (checked[0], checked[2])  # the middle tenant had no membership
    result = IdentityErasureResult(
        user_id=uuid.uuid4(),
        external_identities_deleted=1,
        sessions_deleted=2,
        tenants_with_membership_removed=touched,
        checked_tenant_ids=checked,
    )
    assert result.memberships_removed == 2
    assert checked[1] not in result.tenants_with_membership_removed


def test_result_is_immutable() -> None:
    result = IdentityErasureResult(
        user_id=uuid.uuid4(), external_identities_deleted=0, sessions_deleted=0
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.sessions_deleted = 5  # type: ignore[misc]
