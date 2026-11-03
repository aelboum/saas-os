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


# --- the approval mechanism (owner decisions of 2026-11-02 and 2026-11-03) ---------

# Every code a refusal of the retention API, the approver register or the
# authorised deletion can carry, each a fixed literal recorded as the
# `denied` row's reason. The platform-admin router maps each to exactly one
# HTTP status (the router's `RETENTION_STATUS` table).
APPROVAL_REFUSAL_CODES: frozenset[str] = frozenset(
    {
        # the session the request presented
        "session_evidence_invalid",
        "multi_factor_not_enforced",
        # request, approval, execution authorisation and execution
        "scope_not_eligible",
        "overlapping_request",
        "request_expired",
        "request_already_approved",
        "approver_is_requester",
        "approver_released_hold",
        "approver_linked_to_requester",
        "unauthenticated_release_in_scope",
        "approval_missing",
        "approval_expired",
        "approval_consumed",
        "approval_invalidated",
        "approval_no_longer_authorized",
        "authorizer_is_approver",
        "authorizer_released_hold",
        "authorizer_linked_to_approver",
        "approver_not_eligible",
        "authorizer_not_eligible",
        "same_natural_person",
        "party_holds_authority_manage",
        "party_holds_hold_manage",
        "execution_authorization_expired",
        "execution_authorization_consumed",
        "execution_authorization_invalidated",
        # the approver eligibility register
        "not_a_representative",
        "register_subject_is_caller",
        "subject_holds_authority_manage",
        "subject_holds_hold_manage",
        "subject_is_representative",
        "subject_is_approver",
        "subject_linked_to_representative",
        "proposal_expired",
        "proposal_already_confirmed",
        "confirmer_is_proposer",
        "approver_already_enrolled",
        "natural_person_already_enrolled",
        "invalid_renewal",
        "entry_already_revoked",
    }
)

# The records a request can name that may not exist.
APPROVAL_NOT_FOUND_CODES: frozenset[str] = frozenset(
    {
        "request_not_found",
        "register_entry_not_found",
        "subject_not_found",
        "execution_authorization_not_found",
    }
)


class LedgerApprovalRefusedError(PermissionGrantLedgerRetentionError):
    """A retention API act, a register write or the authorised deletion
    was refused by a rule (docs/architecture/LEDGER-DELETION-APPROVAL-
    DESIGN.md, section 3.4). `code` is one of `APPROVAL_REFUSAL_CODES`;
    the message names the code and no stored value. Nothing changed."""

    def __init__(self, code: str) -> None:
        if code not in APPROVAL_REFUSAL_CODES:
            raise ValueError(f"unknown approval refusal code: {code!r}")
        self.code = code
        super().__init__(f"Refused: {code}.")


class LedgerApprovalRecordNotFoundError(PermissionGrantLedgerRetentionError):
    """The request, register entry, subject user or execution authorisation
    a call names does not exist (or, for a register entry, does not belong
    to the subject the path names). `code` is one of
    `APPROVAL_NOT_FOUND_CODES`."""

    def __init__(self, code: str) -> None:
        if code not in APPROVAL_NOT_FOUND_CODES:
            raise ValueError(f"unknown not-found code: {code!r}")
        self.code = code
        super().__init__(f"Not found: {code}.")
