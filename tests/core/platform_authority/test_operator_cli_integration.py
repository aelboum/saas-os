"""ADR-0050 -- `saas-os-operator` against real PostgreSQL, as the restricted
application role: each command reaches its Core function with the caller
Core requires, and Core's authorization decides.

Marked `integration`.
"""

from __future__ import annotations

from typing import Any

import pytest
from platform_helpers import PlatformWorld

from saas_os.core.platform_authority import PlatformPermission as P
from saas_os.core.tenancy import TenantStatus
from saas_os.ops import operator_cli as cli

pytestmark = pytest.mark.integration


def _run(*argv: str) -> int:
    return cli.main(list(argv))


def test_delete_then_purge_a_tenant(scene: Any, platform: PlatformWorld) -> None:
    tenant = scene.tenant(active=True)
    operator, _ = platform.operator([P.TENANT_DELETE])
    t, op = str(tenant), str(operator.user_id)

    assert (
        _run("delete-tenant", "--tenant", t, "--operator", op, "--reason", "T-1", "--confirm", t)
        == 0
    )
    assert scene.status(tenant) == "deleted"
    assert (
        _run(
            "purge-tenant",
            "--tenant",
            t,
            "--actor",
            op,
            "--no-product-participants",
            "--confirm",
            t,
        )
        == 0
    )
    assert scene.status(tenant) == "purged"


def test_an_operator_without_the_permission_is_refused_by_core(
    scene: Any, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    operator, _ = platform.operator([P.TENANT_READ])
    t = str(tenant)
    code = _run(
        "delete-tenant",
        "--tenant",
        t,
        "--operator",
        str(operator.user_id),
        "--reason",
        "T-1",
        "--confirm",
        t,
    )
    assert code == 1
    assert scene.status(tenant) == "active"


def test_purge_refuses_an_open_tenant(scene: Any, platform: PlatformWorld) -> None:
    tenant = scene.tenant(active=True)
    t = str(tenant)
    code = _run(
        "purge-tenant",
        "--tenant",
        t,
        "--actor",
        str(platform.user()),
        "--no-product-participants",
        "--confirm",
        t,
    )
    assert code == 1
    assert scene.status(tenant) == "active"


def test_move_a_tenant_beneath_another(scene: Any, platform: PlatformWorld) -> None:
    parent, child = scene.tenant(), scene.tenant()
    scene.activate(parent, child)
    operator, _ = platform.operator([P.TENANT_MOVE])
    code = _run(
        "move-tenant",
        "--tenant",
        str(child),
        "--new-parent",
        str(parent),
        "--operator",
        str(operator.user_id),
        "--reason",
        "T-2",
    )
    assert code == 0
    moved = platform.scalar("SELECT parent_id FROM core.tenants WHERE id = :t", {"t": child})
    assert moved == parent


def test_erase_a_user_from_a_tenant(scene: Any, platform: PlatformWorld) -> None:
    tenant = scene.tenant(active=True)
    user, _ = scene.member(tenant)
    actor = platform.user()
    code = _run(
        "erase-user",
        "--user",
        str(user),
        "--tenant",
        str(tenant),
        "--actor",
        str(actor),
        "--confirm",
        str(user),
    )
    assert code == 0
    remaining = platform.scalar(
        "SELECT count(*) FROM core.tenant_memberships WHERE user_id = :u", {"u": user}
    )
    assert remaining == 0


def test_an_enrolled_operator_is_not_erased(scene: Any, platform: PlatformWorld) -> None:
    tenant = scene.tenant(active=True)
    operator, _ = platform.operator([P.TENANT_READ])
    scene.join(tenant, operator.user_id)
    scene.session_for(operator.user_id)
    links_before = platform.scalar(
        "SELECT count(*) FROM core.external_identities WHERE user_id = :u",
        {"u": operator.user_id},
    )
    sessions_before = platform.scalar(
        "SELECT count(*) FROM core.sessions WHERE user_id = :u", {"u": operator.user_id}
    )
    assert (links_before, sessions_before) >= (1, 1)
    code = _run(
        "erase-user",
        "--user",
        str(operator.user_id),
        "--tenant",
        str(tenant),
        "--actor",
        str(platform.user()),
        "--confirm",
        str(operator.user_id),
    )
    assert code == 1
    remaining = platform.scalar(
        "SELECT count(*) FROM core.tenant_memberships WHERE user_id = :u",
        {"u": operator.user_id},
    )
    assert remaining == 1
    # Refused before anything was deleted: the identity link and the
    # operator's sessions are untouched.
    links = platform.scalar(
        "SELECT count(*) FROM core.external_identities WHERE user_id = :u",
        {"u": operator.user_id},
    )
    sessions = platform.scalar(
        "SELECT count(*) FROM core.sessions WHERE user_id = :u", {"u": operator.user_id}
    )
    assert (links, sessions) == (links_before, sessions_before)


def test_tenant_status_is_unchanged_by_a_refused_confirmation(
    scene: Any, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    operator, _ = platform.operator([P.TENANT_DELETE])
    code = _run(
        "delete-tenant",
        "--tenant",
        str(tenant),
        "--operator",
        str(operator.user_id),
        "--reason",
        "T-1",
        "--confirm",
        str(operator.user_id),
    )
    assert code == 2
    assert scene.status(tenant) == TenantStatus.ACTIVE.value
