"""The declaration of a permission grant migration (ADR 0060, option C;
docs/architecture/PERMISSION-GRANT-MIGRATIONS-DESIGN.md section 2.1).

A product declares, in its own code, an ordered, append-only list of
`PermissionGrantMigration`s. Each adds registered permissions to one role
name the product created at provisioning. `validate_permission_grant_migrations`
checks the whole list before any database work: unique ids, well-formed
fields, one namespace, and no permission that changes authority. Whether
each permission is registered, and whether an applied migration was
edited since, are checked by the run (`apply.py`), which needs the
database.

The content digest is the SHA-256 of a canonical JSON form of every field
(the permissions in their declared order). The ledger records it per
tenant; a different digest for an id already applied is refused, so a
declared migration is never edited.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

from saas_os.core.permission_grants.errors import (
    AuthorityPermissionGrantError,
    InvalidPermissionGrantMigrationError,
)
from saas_os.core.rbac import is_authority_changing

MAX_ID_LENGTH = 100  # core.permission_grant_applications.migration_id
MAX_NAMESPACE_LENGTH = 100  # core.permission_grant_applications.namespace
MAX_ROLE_NAME_LENGTH = 100  # core.roles.name
MAX_PERMISSION_PART_LENGTH = 100  # core.permissions.resource / action
MAX_REASON_LENGTH = 500
MAX_PERMISSIONS_PER_MIGRATION = 100

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class PermissionGrantMigration:
    """One declared migration: add `permissions` (each a `(resource,
    action)` pair, registered by the product) to the role named
    `role_name` in every tenant it is applied to.

    `id` is stable and unique within `namespace` (the product's own
    namespace) and is never reused. `reason` says why, for the evidence.
    Once applied anywhere, a migration must not change: declare a new one.
    """

    id: str
    namespace: str
    role_name: str
    permissions: tuple[tuple[str, str], ...]
    reason: str


def _text(value: object, *, field: str, migration_id: str, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise InvalidPermissionGrantMigrationError(
            f"Permission grant migration {migration_id!r}: {field} must be a non-empty string "
            f"of at most {limit} characters."
        )
    if _CONTROL_CHARACTERS.search(value):
        raise InvalidPermissionGrantMigrationError(
            f"Permission grant migration {migration_id!r}: {field} contains a control character."
        )
    return value


def _identifier(value: object, *, field: str, migration_id: str) -> str:
    text = _text(value, field=field, migration_id=migration_id, limit=MAX_ID_LENGTH)
    if not _IDENTIFIER.fullmatch(text):
        raise InvalidPermissionGrantMigrationError(
            f"Permission grant migration {migration_id!r}: {field} may hold only letters, digits "
            "and . _ : - and must start with a letter or digit."
        )
    return text


def permission_grant_migration_digest(migration: PermissionGrantMigration) -> str:
    """The SHA-256 (hex) of `migration`'s canonical JSON form: every field,
    the permissions in their declared order."""
    canonical = json.dumps(
        {
            "id": migration.id,
            "namespace": migration.namespace,
            "role_name": migration.role_name,
            "permissions": [list(pair) for pair in migration.permissions],
            "reason": migration.reason,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class ValidatedMigration:
    """A declaration that passed validation, with its digest."""

    migration: PermissionGrantMigration
    digest: str


def validate_permission_grant_migrations(
    migrations: Sequence[PermissionGrantMigration], *, namespace: str
) -> tuple[ValidatedMigration, ...]:
    """Validate a product's whole declared list for `namespace`, in order,
    before any database work. Raises `InvalidPermissionGrantMigrationError`
    for a malformed declaration (including a duplicate id, a duplicate
    permission within a migration, or a migration of another namespace)
    and `AuthorityPermissionGrantError` for a permission that changes
    authority. An empty list is valid and applies nothing."""
    namespace = _identifier(namespace, field="namespace", migration_id="<run>")
    if isinstance(migrations, str | bytes) or not isinstance(migrations, Sequence):
        raise InvalidPermissionGrantMigrationError(
            "The declared permission grant migrations must be a list or tuple."
        )
    seen: set[str] = set()
    validated: list[ValidatedMigration] = []
    for migration in migrations:
        if type(migration) is not PermissionGrantMigration:
            raise InvalidPermissionGrantMigrationError(
                "Every declared permission grant migration must be a PermissionGrantMigration."
            )
        migration_id = _identifier(migration.id, field="id", migration_id=str(migration.id)[:100])
        if migration_id in seen:
            raise InvalidPermissionGrantMigrationError(
                f"Permission grant migration id {migration_id!r} is declared more than once."
            )
        seen.add(migration_id)
        if migration.namespace != namespace:
            raise InvalidPermissionGrantMigrationError(
                f"Permission grant migration {migration_id!r} belongs to another namespace "
                "than the run's."
            )
        _text(
            migration.role_name,
            field="role_name",
            migration_id=migration_id,
            limit=MAX_ROLE_NAME_LENGTH,
        )
        _text(migration.reason, field="reason", migration_id=migration_id, limit=MAX_REASON_LENGTH)
        permissions = migration.permissions
        if (
            not isinstance(permissions, tuple)
            or not permissions
            or len(permissions) > MAX_PERMISSIONS_PER_MIGRATION
        ):
            raise InvalidPermissionGrantMigrationError(
                f"Permission grant migration {migration_id!r}: permissions must be a non-empty "
                f"tuple of at most {MAX_PERMISSIONS_PER_MIGRATION} (resource, action) pairs."
            )
        pairs: set[tuple[str, str]] = set()
        for pair in permissions:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise InvalidPermissionGrantMigrationError(
                    f"Permission grant migration {migration_id!r}: each permission must be a "
                    "(resource, action) tuple."
                )
            resource = _text(
                pair[0],
                field="permission resource",
                migration_id=migration_id,
                limit=MAX_PERMISSION_PART_LENGTH,
            )
            action = _text(
                pair[1],
                field="permission action",
                migration_id=migration_id,
                limit=MAX_PERMISSION_PART_LENGTH,
            )
            if (resource, action) in pairs:
                raise InvalidPermissionGrantMigrationError(
                    f"Permission grant migration {migration_id!r} names {resource}:{action} "
                    "more than once."
                )
            pairs.add((resource, action))
            if is_authority_changing(resource, action):
                raise AuthorityPermissionGrantError(migration_id, resource, action)
        validated.append(
            ValidatedMigration(migration, permission_grant_migration_digest(migration))
        )
    return tuple(validated)


def declaration_digest(validated: Sequence[ValidatedMigration]) -> str:
    """The SHA-256 (hex) of the whole declared list: each migration's id and
    digest, in order. The run's platform audit row records it, so the exact
    list a run applied can be identified without naming every id."""
    canonical = json.dumps(
        [[item.migration.id, item.digest] for item in validated], separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()
