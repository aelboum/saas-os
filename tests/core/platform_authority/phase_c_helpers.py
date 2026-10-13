"""Scenario helpers for the ADR-0045 Phase C integration tests: tenants,
administrators, members and credentials, built through the ordinary Core
operations.

Cleanup: the platform tables are cleared by the `platform` fixture. The
tenants a test creates are turned into `PURGED` tombstones with the
privileged role, so that later registry scans skip them; their rows and
the users are left in place. These tests are for disposable databases
only.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Sequence
from typing import Any

from platform_helpers import PlatformWorld
from sqlalchemy import text

from saas_os.core.api_keys import create_api_key
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import add_tenant_membership, issue_session
from saas_os.core.platform_authority import PlatformPermission
from saas_os.core.rbac import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.rbac.scope import RoleScope
from saas_os.core.tenancy import TenantStatus, create_tenant, transition_tenant_status

P = PlatformPermission
PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
TENANT_PURGE = SystemCaller(SystemAuthority.TENANT_PURGE)
BILLING = SystemCaller(SystemAuthority.BILLING_OPERATIONS)
REASON = "integration test"

# What makes a member an administrator (ADR-0043), plus the membership
# verbs the guarded mutations in these tests need.
ADMIN_PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("membership_role", "create"),
    ("membership", "suspend"),
    ("membership", "revoke"),
    ("membership", "create"),
)


class Scene:
    """Tenants and people for one test."""

    def __init__(self, platform: PlatformWorld) -> None:
        self.platform = platform
        self.tenants: list[uuid.UUID] = []

    # --- tenants -------------------------------------------------------------

    def tenant(
        self, *, parent: uuid.UUID | None = None, active: bool = False, caller: Any = PROVISIONING
    ) -> uuid.UUID:
        tenant_id = create_tenant(f"pc-{uuid.uuid4().hex[:10]}", parent_id=parent, caller=caller).id
        self.tenants.append(tenant_id)
        if active:
            transition_tenant_status(tenant_id, TenantStatus.ACTIVE, caller=PROVISIONING)
        return tenant_id

    def activate(self, *tenant_ids: uuid.UUID) -> None:
        """`PENDING -> ACTIVE`. A provisioning caller may attach a child
        only beneath a PENDING parent, so a test builds its tree first and
        activates it afterwards."""
        for tenant_id in tenant_ids:
            transition_tenant_status(tenant_id, TenantStatus.ACTIVE, caller=PROVISIONING)

    def status(self, tenant_id: uuid.UUID) -> str:
        return self.platform.scalar(
            "SELECT status FROM core.tenants WHERE id = :t", {"t": tenant_id}
        )

    def set_status(self, tenant_id: uuid.UUID, status: TenantStatus) -> None:
        """Test setup only, with the privileged role: put a tenant in a
        state without going through the lifecycle."""
        self.platform.execute(
            "UPDATE core.tenants SET status = :s WHERE id = :t",
            {"s": status.value, "t": tenant_id},
        )

    # --- people --------------------------------------------------------------

    def member(self, tenant_id: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
        """A new user with an ACTIVE membership and no role.
        Returns `(user_id, membership_id)`."""
        user_id = self.platform.user()
        membership = add_tenant_membership(tenant_id, user_id, caller=PROVISIONING)
        return user_id, membership.id

    def join(self, tenant_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
        return add_tenant_membership(tenant_id, user_id, caller=PROVISIONING).id

    def role(
        self,
        tenant_id: uuid.UUID,
        membership_id: uuid.UUID,
        permissions: Sequence[tuple[str, str]],
        *,
        scope: RoleScope = RoleScope.SELF,
    ) -> uuid.UUID:
        role = create_role(tenant_id, f"r-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        for resource, action in permissions:
            permission = register_permission(resource, action)
            grant_permission(tenant_id, role.id, permission.id, caller=PROVISIONING)
        assign_first_role_for_new_tenant(
            tenant_id, membership_id, role.id, scope=scope, caller=PROVISIONING
        )
        return role.id

    def make_admin(
        self,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        *,
        extra: Sequence[tuple[str, str]] = (),
        scope: RoleScope = RoleScope.SELF,
    ) -> uuid.UUID:
        """Make `user_id` an ACTIVE member and an administrator of
        `tenant_id`. Returns the membership id."""
        membership_id = self.join(tenant_id, user_id)
        self.role(tenant_id, membership_id, (*ADMIN_PERMISSIONS, *extra), scope=scope)
        return membership_id

    def admin(
        self,
        tenant_id: uuid.UUID,
        *,
        extra: Sequence[tuple[str, str]] = (),
        scope: RoleScope = RoleScope.SELF,
    ) -> tuple[UserCaller, uuid.UUID]:
        """A new user who is an administrator of `tenant_id`.
        Returns `(caller, membership_id)`."""
        user_id = self.platform.user()
        membership_id = self.make_admin(tenant_id, user_id, extra=extra, scope=scope)
        return UserCaller(user_id), membership_id

    def has_administrator(self, tenant_id: uuid.UUID) -> bool:
        from saas_os.core.rbac.administrators import find_administrator
        from saas_os.infra.db import session_scope

        with session_scope() as session:
            return find_administrator(session, tenant_id) is not None

    # --- credentials ---------------------------------------------------------

    def session_for(self, user_id: uuid.UUID) -> str:
        """Issue a session; returns the raw bearer token."""
        return issue_session(user_id)[1]

    def api_key(self, tenant_id: uuid.UUID, user_id: uuid.UUID) -> tuple[uuid.UUID, str]:
        """A user-owned key in a tenant the user is a member of.
        Returns `(key_id, raw_key)`."""
        key, raw = create_api_key(
            tenant_id, f"k-{uuid.uuid4().hex[:8]}", caller=UserCaller(user_id)
        )
        return key.id, raw

    def user_is_active(self, user_id: uuid.UUID) -> bool:
        return self.platform.scalar(
            "SELECT is_active FROM core.users WHERE id = :u", {"u": user_id}
        )

    def live_sessions(self, user_id: uuid.UUID) -> int:
        return self.platform.scalar(
            "SELECT count(*) FROM core.sessions WHERE user_id = :u AND revoked_at IS NULL",
            {"u": user_id},
        )

    def live_keys(self, user_id: uuid.UUID) -> int:
        return self.platform.scalar(
            "SELECT count(*) FROM core.api_keys WHERE user_id = :u AND revoked_at IS NULL",
            {"u": user_id},
        )

    # --- evidence ------------------------------------------------------------

    def tenant_audit(self, tenant_id: uuid.UUID, action: str | None = None) -> list[dict[str, Any]]:
        sql = (
            "SELECT actor_type, actor_user_id, action, resource_type, resource_id, outcome, "
            "metadata FROM core.audit_log WHERE tenant_id = :t"
        )
        params: dict[str, Any] = {"t": tenant_id}
        if action is not None:
            sql += " AND action = :a"
            params["a"] = action
        sql += " ORDER BY created_at, id"
        keys = (
            "actor_type",
            "actor_user_id",
            "action",
            "resource_type",
            "resource_id",
            "outcome",
            "metadata",
        )
        return [dict(zip(keys, row, strict=True)) for row in self.platform.execute(sql, params)]

    def unpurged_tenants(self) -> int:
        return self.platform.scalar("SELECT count(*) FROM core.tenants WHERE status <> 'purged'")

    # --- teardown ------------------------------------------------------------

    def cleanup(self) -> None:
        if self.tenants:
            # API keys (a downgrade test restores a NOT NULL on `user_id`), and
            # rows that reference the global permission catalog: other test
            # modules delete the permissions they registered, which these
            # would block.
            for table in ("api_keys", "delegation_grants", "deny_grants", "role_permissions"):
                self.platform.execute(
                    f"DELETE FROM core.{table} WHERE tenant_id = ANY(:t)",  # noqa: S608 -- fixed names
                    {"t": self.tenants},
                )
            self.platform.execute(
                "UPDATE core.tenants SET status = 'purged' WHERE id = ANY(:t)", {"t": self.tenants}
            )
        # The users stay (they are referenced by memberships and audit
        # rows); `PlatformWorld.cleanup()` must not try to delete them.
        self.platform.users.clear()


class Pause:
    """Stops the transaction on thread `thread_name` the `nth` time it
    passes `checkpoint()` -- every lock it has taken still held -- and
    records that transaction's backend pid."""

    def __init__(self, thread_name: str, nth: int = 1) -> None:
        self.thread_name = thread_name
        self.nth = nth
        self.paused = threading.Event()
        self.release = threading.Event()
        self.pid: int | None = None
        self.hits = 0

    def checkpoint(self, session: Any) -> None:
        if threading.current_thread().name != self.thread_name:
            return
        self.hits += 1
        if self.hits != self.nth:
            return
        self.pid = session.execute(text("SELECT pg_backend_pid()")).scalar_one()
        self.paused.set()
        assert self.release.wait(timeout=60), "pause never released"


def pause_after(
    monkeypatch: Any, module: Any, name: str, pause: Pause, *, session_arg: int = 0
) -> None:
    """Wrap `module.name` so that the paused thread stops right after the
    real function returns, still inside its transaction."""
    real: Callable[..., Any] = getattr(module, name)

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        result = real(*args, **kwargs)
        pause.checkpoint(kwargs.get("session", args[session_arg] if args else None))
        return result

    monkeypatch.setattr(module, name, wrapped)


def pause_before(
    monkeypatch: Any, module: Any, name: str, pause: Pause, *, session_arg: int = 0
) -> None:
    """Wrap `module.name` so that the paused thread stops just before the
    real function runs."""
    real: Callable[..., Any] = getattr(module, name)

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        pause.checkpoint(kwargs.get("session", args[session_arg] if args else None))
        return real(*args, **kwargs)

    monkeypatch.setattr(module, name, wrapped)
