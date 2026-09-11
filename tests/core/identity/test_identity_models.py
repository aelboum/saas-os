"""Identity model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2) --
inspect SQLAlchemy metadata only, no database connection needed. Mirrors
tests/core/tenancy/test_models.py.
"""

from __future__ import annotations

import inspect

from core.identity.models import ExternalIdentity, Session, TenantMembership, User
from sqlalchemy import Table, UniqueConstraint

_users: Table = User.__table__  # type: ignore[assignment]
_external_identities: Table = ExternalIdentity.__table__  # type: ignore[assignment]
_sessions: Table = Session.__table__  # type: ignore[assignment]
_tenant_memberships: Table = TenantMembership.__table__  # type: ignore[assignment]


def test_users_table_is_schema_qualified_core() -> None:
    assert _users.schema == "core"
    assert _users.name == "users"


def test_users_has_expected_columns() -> None:
    assert {c.name for c in _users.columns} == {"id", "is_active", "created_at", "updated_at"}


def test_users_has_no_email_column() -> None:
    """Email must never silently become the canonical identity key
    (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 section 5) -- the simplest
    structural guarantee of that is that it isn't a column at all yet.
    """
    assert "email" not in {c.name for c in _users.columns}


def test_users_has_no_permission_or_role_column() -> None:
    """Authorization is core/rbac's exclusive concern (Phase 3.3) --
    core/identity must not pre-add permission-shaped columns."""
    names = {c.name for c in _users.columns}
    assert not any("role" in n or "permission" in n for n in names)


def test_external_identities_table_is_schema_qualified_core() -> None:
    assert _external_identities.schema == "core"
    assert _external_identities.name == "external_identities"


def test_external_identities_has_expected_columns() -> None:
    assert {c.name for c in _external_identities.columns} == {
        "id",
        "user_id",
        "issuer",
        "subject",
        "created_at",
        "updated_at",
    }


def test_external_identities_issuer_and_subject_are_uniquely_constrained() -> None:
    unique_column_sets = [
        {c.name for c in constraint.columns}
        for constraint in _external_identities.constraints
        if isinstance(constraint, UniqueConstraint)
    ]
    assert {"issuer", "subject"} in unique_column_sets


def test_external_identities_user_id_is_a_foreign_key_to_users() -> None:
    fk_targets = {fk.target_fullname for fk in _external_identities.foreign_keys}
    assert "core.users.id" in fk_targets


def test_sessions_table_is_schema_qualified_core() -> None:
    assert _sessions.schema == "core"
    assert _sessions.name == "sessions"


def test_sessions_has_expected_columns() -> None:
    assert {c.name for c in _sessions.columns} == {
        "id",
        "user_id",
        "token_hash",
        "expires_at",
        "revoked_at",
        "created_at",
        "updated_at",
    }


def test_sessions_has_no_plaintext_token_column() -> None:
    """Only a hash is ever persisted (docs/SECURITY.md) -- no column named
    or shaped for a raw bearer secret exists on this table."""
    names = {c.name for c in _sessions.columns}
    assert "token" not in names
    assert "bearer_token" not in names
    assert "secret" not in names


def test_sessions_token_hash_is_unique() -> None:
    assert _sessions.columns["token_hash"].unique is True


def test_sessions_expires_at_is_not_nullable() -> None:
    assert _sessions.columns["expires_at"].nullable is False


def test_sessions_revoked_at_is_nullable() -> None:
    assert _sessions.columns["revoked_at"].nullable is True


def test_tenant_memberships_table_is_schema_qualified_core() -> None:
    assert _tenant_memberships.schema == "core"
    assert _tenant_memberships.name == "tenant_memberships"


def test_tenant_memberships_has_expected_columns() -> None:
    """architecture research Phase G ("Invitation / Membership Lifecycle")
    adds `status` -- see tests/core/identity/test_membership_invitation_models.py
    for the dedicated `MembershipStatus` coverage."""
    assert {c.name for c in _tenant_memberships.columns} == {
        "id",
        "tenant_id",
        "user_id",
        "status",
        "created_at",
        "updated_at",
    }


def test_tenant_memberships_has_no_permission_or_role_column() -> None:
    names = {c.name for c in _tenant_memberships.columns}
    assert not any("role" in n or "permission" in n for n in names)


def test_tenant_memberships_tenant_and_user_are_uniquely_constrained() -> None:
    unique_column_sets = [
        {c.name for c in constraint.columns}
        for constraint in _tenant_memberships.constraints
        if isinstance(constraint, UniqueConstraint)
    ]
    assert {"tenant_id", "user_id"} in unique_column_sets


def test_tenant_memberships_tenant_id_is_a_foreign_key_to_tenants() -> None:
    fk_targets = {fk.target_fullname for fk in _tenant_memberships.foreign_keys}
    assert "core.tenants.id" in fk_targets


def test_core_identity_models_does_not_import_sqlalchemy_directly() -> None:
    """Non-vacuous documentation of the boundary this module relies on --
    the real enforcement is the import-linter contract
    (tests/architecture/test_layer_boundaries.py); this just confirms the
    module's own source doesn't contain a direct sqlalchemy import.
    """
    import core.identity.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
