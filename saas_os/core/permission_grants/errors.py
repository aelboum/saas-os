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


class PermissionGrantLedgerRetentionError(ValueError):
    """Base class: a request about the permission grant ledger's retention
    (the eligibility report, or placing or releasing a legal hold; owner
    policy of 2026-11-02) was refused. `code` is what the refusal's
    `denied` platform audit row records."""

    code = "refused"


class InvalidLedgerRetentionRequestError(PermissionGrantLedgerRetentionError):
    """An argument is malformed: a wrong type, a reference that is not an
    identifier-shaped string, an inconsistent scope or a time without a
    UTC offset."""

    code = "invalid_request"


class LedgerHoldTenantNotFoundError(PermissionGrantLedgerRetentionError):
    """A hold names a tenant for which no `core.tenants` row exists."""

    code = "tenant_not_found"

    def __init__(self, tenant_id: object) -> None:
        self.tenant_id = tenant_id
        super().__init__(f"Tenant {tenant_id} does not exist.")


class LedgerHoldAlreadyActiveError(PermissionGrantLedgerRetentionError):
    """An active hold with the same reference already exists on the tenant."""

    code = "hold_already_active"

    def __init__(self, tenant_id: object, reference: str) -> None:
        self.tenant_id = tenant_id
        self.reference = reference
        super().__init__(f"Tenant {tenant_id} already has an active hold {reference!r}.")


class LedgerHoldNotFoundError(PermissionGrantLedgerRetentionError):
    """No hold has this id."""

    code = "hold_not_found"

    def __init__(self, hold_id: object) -> None:
        self.hold_id = hold_id
        super().__init__(f"Ledger hold {hold_id} does not exist.")


class LedgerHoldAlreadyReleasedError(PermissionGrantLedgerRetentionError):
    """The hold was released before; a release is never repeated or undone."""

    code = "hold_already_released"

    def __init__(self, hold_id: object) -> None:
        self.hold_id = hold_id
        super().__init__(f"Ledger hold {hold_id} was already released.")


class LedgerExpiryConfirmationMismatchError(PermissionGrantLedgerRetentionError):
    """The deletion of expired ledger rows was not confirmed with exactly
    the eligible row count and digest it recomputed under lock (owner
    decision B of 2026-11-02): something changed since the report, or the
    operator confirmed another report. Nothing is deleted."""

    code = "confirmation_mismatch"

    def __init__(self) -> None:
        super().__init__(
            "The confirmed row count or digest differs from the rows eligible now; "
            "run the report again."
        )


class LedgerDeletionDisabledError(PermissionGrantLedgerRetentionError):
    """Deleting expired ledger rows is disabled (owner decision of
    2026-11-02, separation of duties). Every entry point to these commands
    takes a *declared* operator id, which is not an authenticated identity,
    so nothing can verify that the person who authorises a deletion is not
    the person who released a legal hold on the same rows. Deletion stays
    off until a verifiable approval control is approved and built
    (`docs/RUNBOOKS.md`, "Deleting expired permission grant ledger rows").
    The read-only report is unaffected. Nothing is deleted."""

    code = "deletion_disabled"

    def __init__(self) -> None:
        super().__init__(
            "Deleting expired permission grant ledger rows is disabled pending a "
            "verifiable approval control; nothing was deleted."
        )
