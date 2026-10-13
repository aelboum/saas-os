"""Feature flag definition, per-tenant targeting, and evaluation
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.2).

`create_flag`/`get_flag`/`list_flags` operate on the global flag catalog
(`saas_os.core.feature_flags`) via plain `saas_os.infra.db.session_scope()` -- mirroring
how `saas_os/core/rbac`'s `register_permission`/`get_permission`/`list_permissions`
read the equally-global `core.permissions` table (`saas_os/core/rbac/service.py`).
A flag *definition* has no tenant to attribute a change to, so the reads
write no audit entry.

**Authority (docs/ADR/0045-installation-scoped-platform-authority.md
section 13).** The three mutations take a required, keyword-only `caller`
and authorize it in their own transaction through the platform chokepoint:

- `create_flag`: a `UserCaller` holding `platform.feature_flag:define`,
  or `SystemCaller(SystemAuthority.PROVISIONING)` for a product's seed
  code. One platform audit row, in the same transaction.
- `set_tenant_override`/`remove_tenant_override`: a `UserCaller` holding
  `platform.feature_flag:override`. No system purpose is accepted: an
  override changes what a tenant may do, and the self-learning kill
  switch is a flag. Dual evidence, in the same transaction: a platform
  audit row, and a row in the tenant's own `core.audit_log` naming the
  operator, so the tenant's administrators see that the platform acted.

One transaction, opened with no tenant bound: the platform rows are read
and written first; the override and the tenant's audit row are written
inside one `bind_tenant_scope` block (ADR-0045 section 9c). A refusal
writes one `denied` platform row, separately.

`evaluate_flag` is the consuming SDK entrypoint
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.2's own "evaluation SDK"
objective). It takes a caller-supplied `default` and returns it -- rather
than raising -- for both an unknown flag key and a database read failure
(`saas_os.infra.db.OperationalError`), which is exactly the roadmap's Rollback
Strategy requirement: "flags default to a documented safe default on read
failure." A *known* flag with no tenant override simply evaluates to its
own `enabled_by_default` -- that is not a failure path, so it does not
fall back to the caller's `default`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from saas_os.core.audit_log import record_in_transaction
from saas_os.core.authority import ServiceAccountCaller, UserCaller, require_caller
from saas_os.core.feature_flags.errors import (
    DuplicateFeatureFlagKeyError,
    FeatureFlagNotFoundError,
    InvalidFeatureFlagKeyError,
)
from saas_os.core.feature_flags.models import FeatureFlag, FeatureFlagTenantOverride
from saas_os.core.platform_authority import (
    DEFAULT_OVERSIGHT_PAGE_SIZE,
    MAX_OVERSIGHT_PAGE_SIZE,
    InvalidPlatformRequestError,
    OversightOutcome,
    PlatformNotAuthorizedError,
    authorize_platform_caller,
    platform_operation,
    record_platform_event_in_transaction,
    recording_platform_refusal,
    require_oversight_caller,
    run_oversight_read,
    validate_page_request,
    validate_reason,
)
from saas_os.core.platform_authority.operations import (
    FEATURE_FLAG_DEFINE,
    FEATURE_FLAG_OVERRIDE,
    FEATURE_FLAG_READ,
)
from saas_os.core.tenancy import (
    TenantNotFoundError,
    lock_open_tenant,
    require_purging_tenant,
    tenant_row_exists,
)
from saas_os.infra.db import (
    IntegrityError,
    OperationalError,
    Session,
    bind_tenant_scope,
    select,
    session_scope,
    tenant_session_scope,
)

_MAX_KEY_LENGTH = 150


def _validate_key(key: str) -> None:
    if not key or not key.strip():
        raise InvalidFeatureFlagKeyError("key must be a non-empty string.")
    if len(key) > _MAX_KEY_LENGTH:
        raise InvalidFeatureFlagKeyError(f"key exceeds {_MAX_KEY_LENGTH} characters.")


# --- Flag definitions (global catalog) -----------------------------------

_TARGET_FLAG = "feature_flag"
_ACTION_OVERRIDE_SET = "feature_flag.override_set"
_ACTION_OVERRIDE_REMOVED = "feature_flag.override_removed"


def _require_platform_caller(operation: str, caller: object) -> None:
    """`CallerTypeError` for a missing or wrongly typed caller; a service
    account is refused before any read (it never holds platform
    authority)."""
    require_caller(operation, caller)
    if isinstance(caller, ServiceAccountCaller):
        raise PlatformNotAuthorizedError(operation)


def create_flag(key: str, *, enabled_by_default: bool = False, caller: object) -> FeatureFlag:
    """Define a flag in the global catalog. Authority:
    `platform.feature_flag:define`, or the provisioning purpose."""
    _require_platform_caller(FEATURE_FLAG_DEFINE, caller)
    _validate_key(key)
    try:
        with (
            recording_platform_refusal(
                caller=caller, operation=FEATURE_FLAG_DEFINE, target_type=_TARGET_FLAG
            ),
            session_scope() as session,
        ):
            authorize_platform_caller(caller, session=session, operation=FEATURE_FLAG_DEFINE)
            flag = FeatureFlag(key=key, enabled_by_default=enabled_by_default)
            session.add(flag)
            session.flush()
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=platform_operation(FEATURE_FLAG_DEFINE).audit_action,
                target_type=_TARGET_FLAG,
                target_id=str(flag.id),
                metadata={"enabled_by_default": enabled_by_default},
            )
            session.refresh(flag)
            session.expunge(flag)
            return flag
    except IntegrityError as exc:
        raise DuplicateFeatureFlagKeyError(key) from exc


def get_flag(key: str) -> FeatureFlag:
    with session_scope() as session:
        flag = session.execute(
            select(FeatureFlag).where(FeatureFlag.key == key)
        ).scalar_one_or_none()
        if flag is None:
            raise FeatureFlagNotFoundError(key)
        session.expunge(flag)
        return flag


def list_flags() -> list[FeatureFlag]:
    with session_scope() as session:
        flags = session.execute(select(FeatureFlag)).scalars().all()
        for flag in flags:
            session.expunge(flag)
        return list(flags)


# --- Per-tenant targeting --------------------------------------------------


# --- oversight reads (ADR-0045 sections 4, 8 and 9d) -------------------------------------

_TARGET_CATALOG = "feature_flag_catalog"
_TARGET_OVERRIDES = "feature_flag_overrides"


@dataclass(frozen=True)
class FlagCatalogEntry:
    """The complete oversight projection of one flag definition."""

    key: str
    enabled_by_default: bool


@dataclass(frozen=True)
class FlagCatalogPage:
    """`next_cursor` is the flag key to pass as `cursor` for the following
    page, or `None` when this page was not full. A key is part of the
    projection: the cursor discloses nothing the page does not."""

    flags: tuple[FlagCatalogEntry, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class TenantFlagOverride:
    """The complete oversight projection of one tenant override."""

    key: str
    enabled: bool


@dataclass(frozen=True)
class TenantFlagOverridesPage:
    tenant_id: uuid.UUID
    overrides: tuple[TenantFlagOverride, ...]
    next_cursor: str | None


def _validate_flag_page_request(cursor: object, limit: object) -> None:
    """Decision D3 for a page keyed by flag key: rejected, never clamped."""
    if cursor is not None and (
        not isinstance(cursor, str) or not cursor or len(cursor) > _MAX_KEY_LENGTH
    ):
        raise InvalidPlatformRequestError("cursor must be a flag key.")
    validate_page_request(None, limit, maximum=MAX_OVERSIGHT_PAGE_SIZE)


def read_flag_catalog(
    *, caller: object, cursor: str | None = None, limit: int = DEFAULT_OVERSIGHT_PAGE_SIZE
) -> FlagCatalogPage:
    """One page of the flag catalog, by keyset on the flag key (unique).
    Authority: `platform.feature_flag:read`. A read of a global table
    only: no tenant scope is entered. Audited by two rows, like every
    oversight read."""
    require_oversight_caller(FEATURE_FLAG_READ, caller)
    _validate_flag_page_request(cursor, limit)

    def read(session: Session) -> OversightOutcome[FlagCatalogPage]:
        query = select(FeatureFlag.key, FeatureFlag.enabled_by_default)
        if cursor is not None:
            query = query.where(FeatureFlag.key > cursor)
        rows = session.execute(query.order_by(FeatureFlag.key).limit(limit)).all()
        page = FlagCatalogPage(
            flags=tuple(FlagCatalogEntry(row.key, row.enabled_by_default) for row in rows),
            next_cursor=rows[-1].key if len(rows) == limit else None,
        )
        return OversightOutcome(page, len(rows))

    return run_oversight_read(
        caller=caller,
        operation=FEATURE_FLAG_READ,
        target_type=_TARGET_CATALOG,
        request_metadata={"cursor": cursor, "page_size": limit},
        read=read,
    )


def read_tenant_flag_overrides(
    tenant_id: uuid.UUID,
    *,
    caller: object,
    cursor: str | None = None,
    limit: int = DEFAULT_OVERSIGHT_PAGE_SIZE,
) -> TenantFlagOverridesPage:
    """One page of one named tenant's flag overrides, by keyset on the
    flag key: flag key and value, nothing else. Authority:
    `platform.feature_flag:read`.

    A read that enters a tenant scope (ADR-0045 section 9d): authorized
    and audited with no tenant bound, then one fixed query inside
    `bind_tenant_scope` for exactly that tenant, carrying the explicit
    `tenant_id` predicate as well. No tenant permission is consulted and
    none could grant the read; the tenant's status is not consulted
    either, so a suspended or deleted tenant's overrides are readable.

    A `tenant_id` that names no tenant is a call like any other (the
    failure table of section 9d): both audit rows are committed, the
    completion recording that nothing was returned, and only then is
    `TenantNotFoundError` raised. A caller without the permission is
    refused before the lookup and learns nothing about existence."""
    require_oversight_caller(FEATURE_FLAG_READ, caller)
    if not isinstance(tenant_id, uuid.UUID):
        raise InvalidPlatformRequestError("tenant_id must be a uuid.UUID.")
    _validate_flag_page_request(cursor, limit)

    def read(session: Session) -> OversightOutcome[TenantFlagOverridesPage | None]:
        # The global registry, with no tenant bound.
        if not tenant_row_exists(session, tenant_id):
            return OversightOutcome(None, 0)
        query = (
            select(FeatureFlag.key, FeatureFlagTenantOverride.enabled)
            .join(FeatureFlag, FeatureFlag.id == FeatureFlagTenantOverride.flag_id)
            .where(FeatureFlagTenantOverride.tenant_id == tenant_id)
        )
        if cursor is not None:
            query = query.where(FeatureFlag.key > cursor)
        with bind_tenant_scope(session, tenant_id):
            rows = session.execute(query.order_by(FeatureFlag.key).limit(limit)).all()
        page = TenantFlagOverridesPage(
            tenant_id=tenant_id,
            overrides=tuple(TenantFlagOverride(row.key, row.enabled) for row in rows),
            next_cursor=rows[-1].key if len(rows) == limit else None,
        )
        return OversightOutcome(page, len(rows), target_tenant_id=tenant_id)

    page = run_oversight_read(
        caller=caller,
        operation=FEATURE_FLAG_READ,
        target_type=_TARGET_OVERRIDES,
        target_id=str(tenant_id),
        request_metadata={"cursor": cursor, "page_size": limit},
        read=read,
        records_failure=True,
    )
    if page is None:
        raise TenantNotFoundError(tenant_id)
    return page


def _override_query(tenant_id: uuid.UUID, flag_id: uuid.UUID):
    return select(FeatureFlagTenantOverride).where(
        FeatureFlagTenantOverride.tenant_id == tenant_id,
        FeatureFlagTenantOverride.flag_id == flag_id,
    )


def _record_override(
    session: Session,
    *,
    caller: UserCaller,
    tenant_id: uuid.UUID,
    flag_id: uuid.UUID,
    reason: str | None,
    metadata: dict[str, object],
) -> None:
    """The platform audit row of an override change. Must run before the
    bind block: no tenant may be bound when a platform table is written."""
    record_platform_event_in_transaction(
        session,
        caller=caller,
        action=platform_operation(FEATURE_FLAG_OVERRIDE).audit_action,
        target_type=_TARGET_FLAG,
        target_id=str(flag_id),
        target_tenant_id=tenant_id,
        reason=reason,
        metadata=metadata,
    )


def set_tenant_override(
    tenant_id: uuid.UUID,
    key: str,
    enabled: bool,
    *,
    caller: object,
    reason: str | None = None,
) -> FeatureFlagTenantOverride:
    """Set (creating or replacing) `tenant_id`'s override for the flag
    identified by `key`. Idempotent in effect: calling this twice with the
    same `enabled` value leaves exactly one override row, updated in
    place -- never a duplicate. Authority: `platform.feature_flag:override`
    (module docstring).
    """
    _require_platform_caller(FEATURE_FLAG_OVERRIDE, caller)
    if reason is not None:
        reason = validate_reason(reason)
    flag = get_flag(key)

    def _attempt() -> FeatureFlagTenantOverride:
        with session_scope() as session:
            authorize_platform_caller(caller, session=session, operation=FEATURE_FLAG_OVERRIDE)
            assert isinstance(caller, UserCaller)  # the operation accepts no system purpose
            # The lifecycle fence, in this transaction: a closed tenant
            # receives no new override.
            lock_open_tenant(session, tenant_id)
            _record_override(
                session,
                caller=caller,
                tenant_id=tenant_id,
                flag_id=flag.id,
                reason=reason,
                metadata={"enabled": enabled},
            )
            with bind_tenant_scope(session, tenant_id):
                override = session.execute(_override_query(tenant_id, flag.id)).scalar_one_or_none()
                if override is not None:
                    override.enabled = enabled
                else:
                    override = FeatureFlagTenantOverride(
                        tenant_id=tenant_id, flag_id=flag.id, enabled=enabled
                    )
                    session.add(override)
                session.flush()
                record_in_transaction(
                    session,
                    caller=caller,
                    tenant_id=tenant_id,
                    action=_ACTION_OVERRIDE_SET,
                    resource_type=_TARGET_FLAG,
                    resource_id=key,
                    metadata={"enabled": enabled, "platform": True},
                )
                session.refresh(override)
                session.expunge(override)
            return override

    with recording_platform_refusal(
        caller=caller,
        operation=FEATURE_FLAG_OVERRIDE,
        target_type=_TARGET_FLAG,
        target_id=str(flag.id),
    ):
        try:
            return _attempt()
        except IntegrityError:
            # Lost a race to a concurrent set_tenant_override() for the same
            # (tenant_id, flag_id): the whole transaction, evidence included,
            # was rolled back. The other caller's row now exists; a second
            # attempt updates it to this call's value, authorized and
            # recorded afresh.
            return _attempt()


def remove_tenant_override(
    tenant_id: uuid.UUID, key: str, *, caller: object, reason: str | None = None
) -> None:
    """Remove `tenant_id`'s override for `key`, reverting its evaluation
    to the flag's global `enabled_by_default`. Authority:
    `platform.feature_flag:override`. Idempotent: removing an override that
    doesn't exist is a no-op, not an error, and writes no audit entry when
    there was nothing to remove. Not fenced on the tenant's lifecycle: it
    only removes.
    """
    _require_platform_caller(FEATURE_FLAG_OVERRIDE, caller)
    if reason is not None:
        reason = validate_reason(reason)
    flag = get_flag(key)

    with (
        recording_platform_refusal(
            caller=caller,
            operation=FEATURE_FLAG_OVERRIDE,
            target_type=_TARGET_FLAG,
            target_id=str(flag.id),
        ),
        session_scope() as session,
    ):
        authorize_platform_caller(caller, session=session, operation=FEATURE_FLAG_OVERRIDE)
        assert isinstance(caller, UserCaller)  # the operation accepts no system purpose
        with bind_tenant_scope(session, tenant_id):
            override = session.execute(
                _override_query(tenant_id, flag.id).with_for_update()
            ).scalar_one_or_none()
        if override is None:
            return
        _record_override(
            session,
            caller=caller,
            tenant_id=tenant_id,
            flag_id=flag.id,
            reason=reason,
            metadata={"removed": True},
        )
        with bind_tenant_scope(session, tenant_id):
            session.delete(override)
            session.flush()
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action=_ACTION_OVERRIDE_REMOVED,
                resource_type=_TARGET_FLAG,
                resource_id=key,
                metadata={"platform": True},
            )


def get_tenant_override(tenant_id: uuid.UUID, key: str) -> FeatureFlagTenantOverride | None:
    flag = get_flag(key)
    with tenant_session_scope(tenant_id) as session:
        override = session.execute(
            select(FeatureFlagTenantOverride).where(
                FeatureFlagTenantOverride.tenant_id == tenant_id,
                FeatureFlagTenantOverride.flag_id == flag.id,
            )
        ).scalar_one_or_none()
        if override is not None:
            session.expunge(override)
        return override


# --- Evaluation SDK ---------------------------------------------------------


def evaluate_flag(tenant_id: uuid.UUID, key: str, *, default: bool = False) -> bool:
    """Evaluate `key` for `tenant_id`: a tenant override wins if one
    exists, otherwise the flag's global `enabled_by_default`, otherwise
    (unknown key, or a database read failure) the caller-supplied
    `default` -- see this module's own docstring for why an unknown key
    and a read failure share the same safe-default fallback.
    """
    try:
        with session_scope() as session:
            flag = session.execute(
                select(FeatureFlag).where(FeatureFlag.key == key)
            ).scalar_one_or_none()
            if flag is None:
                return default
            session.expunge(flag)

        with tenant_session_scope(tenant_id) as session:
            override = session.execute(
                select(FeatureFlagTenantOverride).where(
                    FeatureFlagTenantOverride.tenant_id == tenant_id,
                    FeatureFlagTenantOverride.flag_id == flag.id,
                )
            ).scalar_one_or_none()
            if override is not None:
                return override.enabled

        return flag.enabled_by_default
    except OperationalError:
        return default


# --- PRIV-03 Phase P3: tenant purge ------------------------------------------


def purge_tenant_feature_flag_overrides(tenant_id: uuid.UUID) -> int:
    """Delete every `core.feature_flag_tenant_overrides` row `tenant_id`
    owns -- one module-owned step of `saas_os.core.tenancy.purge_tenant()`, only
    callable in the purge phase (`TenantNotPurgingError` otherwise). The
    global flag catalog (`saas_os.core.feature_flags`) is never touched. Runs
    under `tenant_session_scope()`/RLS; idempotent.
    """
    require_purging_tenant(tenant_id)
    deleted = 0
    with tenant_session_scope(tenant_id) as session:
        rows = (
            session.execute(
                select(FeatureFlagTenantOverride)
                .where(FeatureFlagTenantOverride.tenant_id == tenant_id)
                .order_by(FeatureFlagTenantOverride.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for row in rows:
            session.delete(row)
            deleted += 1
    return deleted
