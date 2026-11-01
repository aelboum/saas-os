"""Typed refusals of a permission grant migration run (ADR 0060, option C).

Each carries a short, fixed `code`, which is what the refusal's `denied`
platform audit row records. Messages carry identifiers only: a migration
id, a namespace or a permission the product itself declared, never data of
a tenant. Every one of them is raised before any tenant is changed, except
`PermissionGrantMigrationChangedError` found inside a tenant's transaction
(a concurrent run applied a different declaration between the pre-flight
check and that tenant), which rolls that tenant back and stops the run.
"""

from __future__ import annotations


class PermissionGrantMigrationError(ValueError):
    """Base class: the declaration or the run was refused."""

    code = "refused"


class InvalidPermissionGrantMigrationError(PermissionGrantMigrationError):
    """The declaration is malformed: a wrong type, an empty or overlong
    field, a control character, a duplicate migration id or permission, or
    a migration of another namespace than the run's."""

    code = "invalid_declaration"


class AuthorityPermissionGrantError(PermissionGrantMigrationError):
    """A migration grants a permission that changes authority
    (`saas_os.core.rbac.is_authority_changing`): every capability on an
    authority resource, a billing mutation or tenant self-suspension. Only
    a tenant administrator may grant those."""

    code = "authority_permission"

    def __init__(self, migration_id: str, resource: str, action: str) -> None:
        self.migration_id = migration_id
        self.permission = (resource, action)
        super().__init__(
            f"Permission grant migration {migration_id!r} grants {resource}:{action}, "
            "which changes authority; only a tenant administrator may grant it."
        )


class UnregisteredPermissionGrantError(PermissionGrantMigrationError):
    """A migration grants a permission that is not in the global catalog
    (`core.permissions`). Register it first; a migration never registers
    one."""

    code = "unregistered_permission"

    def __init__(self, migration_id: str, resource: str, action: str) -> None:
        self.migration_id = migration_id
        self.permission = (resource, action)
        super().__init__(
            f"Permission grant migration {migration_id!r} grants {resource}:{action}, "
            "which is not registered."
        )


class PermissionGrantMigrationChangedError(PermissionGrantMigrationError):
    """A migration already applied to a tenant was edited: its content
    digest differs from the one the ledger recorded. A declared migration
    is never edited; declare a new one instead."""

    code = "declaration_changed"

    def __init__(self, namespace: str, migration_id: str) -> None:
        self.namespace = namespace
        self.migration_id = migration_id
        super().__init__(
            f"Permission grant migration {namespace}/{migration_id} was changed after it was "
            "applied; declare a new migration instead of editing it."
        )
