"""Feature flag definition, per-tenant targeting, and evaluation
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.2).

`create_flag`/`get_flag`/`list_flags` operate on the global flag catalog
(`core.feature_flags`) via plain `infra.db.session_scope()` -- mirroring
how `core/rbac`'s `register_permission`/`get_permission`/`list_permissions`
read the equally-global `core.permissions` table (`core/rbac/service.py`).
A flag *definition* has no tenant to attribute a change to, so -- again
mirroring `core/rbac`'s own precedent, which does not audit-log
role/permission-catalog changes -- these three functions do not write to
`core.audit_log`.

`set_tenant_override`/`remove_tenant_override` are the one genuinely
tenant-scoped mutation this module has (`core/feature_flags/models.py`'s
own docstring: "targeted per tenant"), so they take an explicit `tenant_id`,
use `infra.db.tenant_session_scope()`, and -- per the roadmap's own
Security Requirement ("flag state changes are audit-logged (via 3.4)") --
each writes one `core.audit_log` entry. `actor_user_id` is optional: a
platform operator or an automated process may flip a tenant's targeting
without acting *as* a member of that tenant, so the audit actor is
`ActorType.SYSTEM` when no `actor_user_id` is supplied, `ActorType.USER`
when one is -- the same two-actor-type vocabulary `core/audit_log/models.py`
already defines, nothing new invented here.

`evaluate_flag` is the consuming SDK entrypoint
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.2's own "evaluation SDK"
objective). It takes a caller-supplied `default` and returns it -- rather
than raising -- for both an unknown flag key and a database read failure
(`infra.db.OperationalError`), which is exactly the roadmap's Rollback
Strategy requirement: "flags default to a documented safe default on read
failure." A *known* flag with no tenant override simply evaluates to its
own `enabled_by_default` -- that is not a failure path, so it does not
fall back to the caller's `default`.
"""

from __future__ import annotations

import uuid

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.feature_flags.errors import (
    DuplicateFeatureFlagKeyError,
    FeatureFlagNotFoundError,
    InvalidFeatureFlagKeyError,
)
from core.feature_flags.models import FeatureFlag, FeatureFlagTenantOverride
from infra.db import IntegrityError, OperationalError, select, session_scope, tenant_session_scope

_MAX_KEY_LENGTH = 150


def _validate_key(key: str) -> None:
    if not key or not key.strip():
        raise InvalidFeatureFlagKeyError("key must be a non-empty string.")
    if len(key) > _MAX_KEY_LENGTH:
        raise InvalidFeatureFlagKeyError(f"key exceeds {_MAX_KEY_LENGTH} characters.")


# --- Flag definitions (global catalog) -----------------------------------


def create_flag(key: str, *, enabled_by_default: bool = False) -> FeatureFlag:
    _validate_key(key)
    try:
        with session_scope() as session:
            flag = FeatureFlag(key=key, enabled_by_default=enabled_by_default)
            session.add(flag)
            session.flush()
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


def set_tenant_override(
    tenant_id: uuid.UUID,
    key: str,
    enabled: bool,
    *,
    actor_user_id: uuid.UUID | None = None,
) -> FeatureFlagTenantOverride:
    """Set (creating or replacing) `tenant_id`'s override for the flag
    identified by `key`. Idempotent in effect: calling this twice with the
    same `enabled` value leaves exactly one override row, updated in
    place -- never a duplicate.
    """
    flag = get_flag(key)

    def _query():
        return select(FeatureFlagTenantOverride).where(
            FeatureFlagTenantOverride.tenant_id == tenant_id,
            FeatureFlagTenantOverride.flag_id == flag.id,
        )

    try:
        with tenant_session_scope(tenant_id) as session:
            existing = session.execute(_query()).scalar_one_or_none()
            if existing is not None:
                existing.enabled = enabled
                session.flush()
                session.refresh(existing)
                session.expunge(existing)
                override = existing
            else:
                override = FeatureFlagTenantOverride(
                    tenant_id=tenant_id, flag_id=flag.id, enabled=enabled
                )
                session.add(override)
                session.flush()
                session.refresh(override)
                session.expunge(override)
    except IntegrityError:
        # Lost a race to a concurrent set_tenant_override() for the same
        # (tenant_id, flag_id) -- tenant_session_scope() has already rolled
        # the failed transaction back by the time this executes (mirrors
        # infra.db.session_scope()'s own rollback-on-exception behavior).
        # The other caller's row now exists; update it to this call's
        # value in a fresh transaction rather than silently losing this
        # call's intent.
        with tenant_session_scope(tenant_id) as session:
            existing = session.execute(_query()).scalar_one()
            existing.enabled = enabled
            session.flush()
            session.refresh(existing)
            session.expunge(existing)
            override = existing

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action="feature_flag.override_set",
        resource_type="feature_flag",
        resource_id=key,
        outcome=AuditOutcome.SUCCESS,
        metadata={"enabled": enabled},
    )
    return override


def remove_tenant_override(
    tenant_id: uuid.UUID, key: str, *, actor_user_id: uuid.UUID | None = None
) -> None:
    """Remove `tenant_id`'s override for `key`, reverting its evaluation
    to the flag's global `enabled_by_default`. Idempotent: removing an
    override that doesn't exist is a no-op, not an error (mirrors
    `core/rbac/service.py::remove_role`) -- and, matching
    `core/api_keys/service.py::revoke_api_key`'s precedent for an
    already-applied no-op, writes no audit entry when there was nothing to
    remove.
    """
    flag = get_flag(key)

    with tenant_session_scope(tenant_id) as session:
        override = session.execute(
            select(FeatureFlagTenantOverride).where(
                FeatureFlagTenantOverride.tenant_id == tenant_id,
                FeatureFlagTenantOverride.flag_id == flag.id,
            )
        ).scalar_one_or_none()
        if override is None:
            return
        session.delete(override)

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action="feature_flag.override_removed",
        resource_type="feature_flag",
        resource_id=key,
        outcome=AuditOutcome.SUCCESS,
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
