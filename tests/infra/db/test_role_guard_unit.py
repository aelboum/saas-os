"""Unit tests for `infra.db.role_guard._evaluate_role_safety` (P1.2:
the RLS role-misconfiguration startup guard). Pure-function logic -- no
database required, part of the default `pytest` run. The real PostgreSQL
`pg_roles` semantics (rolsuper/rolbypassrls actually reflecting a real
role) are proven separately, against a real database, in
`tests/infra/db/test_role_guard_integration.py` -- this file only proves
the decision logic given a row shaped like what that query returns.
"""

from __future__ import annotations

import pytest
from infra.db.role_guard import (
    ApplicationRoleValidation,
    UnsafeDatabaseRoleError,
    _evaluate_role_safety,
)


def test_safe_role_passes() -> None:
    result = _evaluate_role_safety(("saas_os_app", False, False))
    assert result == ApplicationRoleValidation(role_name="saas_os_app")


def test_superuser_role_is_denied() -> None:
    with pytest.raises(UnsafeDatabaseRoleError, match="superuser"):
        _evaluate_role_safety(("saas_os", True, False))


def test_bypassrls_role_is_denied() -> None:
    with pytest.raises(UnsafeDatabaseRoleError, match="BYPASSRLS"):
        _evaluate_role_safety(("some_role", False, True))


def test_superuser_and_bypassrls_role_is_denied() -> None:
    """Superuser is checked first (either alone is sufficient to deny) --
    this proves the combination is denied too, not skipped over by some
    ordering quirk."""
    with pytest.raises(UnsafeDatabaseRoleError):
        _evaluate_role_safety(("postgres", True, True))


def test_missing_row_fails_closed() -> None:
    """`pg_roles` lookup found no matching row for `current_user` --
    identity could not be established at all."""
    with pytest.raises(UnsafeDatabaseRoleError, match="no matching pg_roles entry"):
        _evaluate_role_safety(None)


def test_malformed_row_fails_closed() -> None:
    """Otherwise-unverifiable role attributes (wrong shape/type) must
    deny, never be silently treated as safe."""
    with pytest.raises(UnsafeDatabaseRoleError, match="could not be determined"):
        _evaluate_role_safety(("saas_os_app", None, None))  # type: ignore[arg-type]


def test_non_boolean_attributes_fail_closed() -> None:
    with pytest.raises(UnsafeDatabaseRoleError, match="could not be determined"):
        _evaluate_role_safety(("saas_os_app", "true", False))  # type: ignore[arg-type]


def test_denial_message_never_contains_a_password_or_connection_string() -> None:
    """The only content a denial may carry is the role name and a fixed
    reason string (module docstring) -- never a credential-shaped value."""
    suspicious_substrings = ["postgresql://", "password", "://", "@"]
    for row in [
        None,
        ("saas_os", True, False),
        ("some_role", False, True),
        ("saas_os_app", None, None),  # type: ignore[arg-type]
    ]:
        with pytest.raises(UnsafeDatabaseRoleError) as excinfo:
            _evaluate_role_safety(row)  # type: ignore[arg-type]
        message = str(excinfo.value)
        for needle in suspicious_substrings:
            assert needle not in message.lower(), (row, message)
