"""ADR 0060, option C: a product's declared permission grant migrations are
validated before any database work (docs/architecture/
PERMISSION-GRANT-MIGRATIONS-DESIGN.md section 2.1). Hermetic."""

from __future__ import annotations

import dataclasses

import pytest

from saas_os.core.permission_grants import (
    AuthorityPermissionGrantError,
    InvalidPermissionGrantMigrationError,
    PermissionGrantMigration,
    permission_grant_migration_digest,
    validate_permission_grant_migrations,
)
from saas_os.core.rbac.authorization import (
    AUTHORITY_RESOURCES,
    BILLING_MUTATION_ACTIONS,
    TENANT_SELF_SUSPEND_ACTION,
)

_NS = "crm_app"


def _m(
    migration_id: str = "2026-11-reports",
    *,
    namespace: str = _NS,
    role_name: str = "admin",
    permissions: tuple[tuple[str, str], ...] = (("report", "read"), ("report", "export")),
    reason: str = "Reports module, release 4.2",
) -> PermissionGrantMigration:
    return PermissionGrantMigration(migration_id, namespace, role_name, permissions, reason)


def test_a_valid_list_is_returned_in_order_with_digests() -> None:
    first, second = _m("a-1"), _m("a-2", permissions=(("report", "share"),))
    validated = validate_permission_grant_migrations([first, second], namespace=_NS)
    assert [v.migration for v in validated] == [first, second]
    assert [v.digest for v in validated] == [
        permission_grant_migration_digest(first),
        permission_grant_migration_digest(second),
    ]
    assert all(len(v.digest) == 64 for v in validated)


def test_an_empty_list_is_valid_and_applies_nothing() -> None:
    assert validate_permission_grant_migrations((), namespace=_NS) == ()


def test_the_digest_changes_with_every_field_and_with_order() -> None:
    base = _m()
    digest = permission_grant_migration_digest(base)
    assert permission_grant_migration_digest(_m()) == digest  # deterministic
    for change in (
        {"id": "other"},
        {"namespace": "other_app"},
        {"role_name": "owner"},
        {"permissions": (("report", "read"),)},
        {"permissions": (("report", "export"), ("report", "read"))},
        {"reason": "Reports module, release 4.3"},
    ):
        assert permission_grant_migration_digest(dataclasses.replace(base, **change)) != digest


def test_a_duplicate_id_is_refused() -> None:
    with pytest.raises(InvalidPermissionGrantMigrationError, match="more than once"):
        validate_permission_grant_migrations([_m("x"), _m("x")], namespace=_NS)


def test_a_migration_of_another_namespace_is_refused() -> None:
    with pytest.raises(InvalidPermissionGrantMigrationError, match="another namespace"):
        validate_permission_grant_migrations([_m(namespace="other_app")], namespace=_NS)


@pytest.mark.parametrize(
    "bad",
    [
        _m(""),
        _m("has space"),
        _m("-leading"),
        _m("x" * 101),
        _m(role_name=""),
        _m(role_name="ad\x00min"),
        _m(role_name="r" * 101),
        _m(reason=""),
        _m(reason="r" * 501),
        _m(permissions=()),
        _m(permissions=[("report", "read")]),  # type: ignore[arg-type]
        _m(permissions=(("report",),)),  # type: ignore[arg-type]
        _m(permissions=(("report", ""),)),
        _m(permissions=(("rep\nort", "read"),)),
        _m(permissions=(("report", "read"), ("report", "read"))),
        _m(permissions=tuple(("report", f"a{n}") for n in range(101))),
    ],
)
def test_a_malformed_declaration_is_refused(bad: PermissionGrantMigration) -> None:
    with pytest.raises(InvalidPermissionGrantMigrationError):
        validate_permission_grant_migrations([bad], namespace=_NS)


@pytest.mark.parametrize("bad", ["", "has space", "n" * 101, "ns\x00"])
def test_a_malformed_namespace_is_refused(bad: str) -> None:
    with pytest.raises(InvalidPermissionGrantMigrationError):
        validate_permission_grant_migrations([], namespace=bad)


def test_something_that_is_not_a_declaration_is_refused() -> None:
    class Lookalike:
        id = "x"
        namespace = _NS
        role_name = "admin"
        permissions = (("report", "read"),)
        reason = "r"

    with pytest.raises(InvalidPermissionGrantMigrationError):
        validate_permission_grant_migrations([Lookalike()], namespace=_NS)  # type: ignore[list-item]
    with pytest.raises(InvalidPermissionGrantMigrationError):
        validate_permission_grant_migrations("not a list", namespace=_NS)  # type: ignore[arg-type]


_AUTHORITY_PAIRS = sorted(
    {(resource, "grant") for resource in AUTHORITY_RESOURCES}
    | {(resource, "read") for resource in AUTHORITY_RESOURCES}
    | set(BILLING_MUTATION_ACTIONS)
    | {TENANT_SELF_SUSPEND_ACTION}
)


@pytest.mark.parametrize("pair", _AUTHORITY_PAIRS, ids=[f"{r}:{a}" for r, a in _AUTHORITY_PAIRS])
def test_every_authority_changing_permission_is_refused(pair: tuple[str, str]) -> None:
    """Roles, grants, memberships, delegations, deny grants, service
    accounts, API keys, invitations, support access, webhooks, billing
    mutations and tenant self-suspension: only a tenant administrator may
    grant them, never a migration."""
    with pytest.raises(AuthorityPermissionGrantError) as refused:
        validate_permission_grant_migrations(
            [_m(permissions=(("report", "read"), pair))], namespace=_NS
        )
    assert refused.value.code == "authority_permission"
    assert refused.value.permission == pair
