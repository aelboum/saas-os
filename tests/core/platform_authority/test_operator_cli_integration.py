"""ADR-0050 -- `saas-os-operator` against real PostgreSQL, as the restricted
application role: each command reaches its Core function with the caller
Core requires, and Core's authorization decides.

Marked `integration`.
"""

from __future__ import annotations

import json
import sys
import types
import uuid
from typing import Any

import pytest
from platform_helpers import PlatformWorld

from saas_os.core.platform_authority import PlatformPermission as P
from saas_os.core.tenancy import TenantStatus, register_purge_participant
from saas_os.core.tenancy import purge_participants as participants_module
from saas_os.core.tenancy.purge_participants import TenantPurgeParticipantRegistry
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


# --- Product participants through `--setup` (public registration API) --------


class _RecordingParticipant:
    """A product participant, registered only through the public
    `saas_os.core.tenancy.register_purge_participant()`."""

    def __init__(self, name: str, calls: list[tuple[str, uuid.UUID]]) -> None:
        self._name = name
        self._calls = calls
        self.fail = False

    @property
    def name(self) -> str:
        return self._name

    def purge_tenant_data(self, tenant_id: uuid.UUID) -> None:
        self._calls.append((self._name, tenant_id))
        if self.fail:
            raise RuntimeError("product cleanup failed: customer-detail-SECRET")


@pytest.fixture
def operator_process(monkeypatch: pytest.MonkeyPatch) -> TenantPurgeParticipantRegistry:
    """A fresh process-wide registry, as a new `saas-os-operator` process
    starts with: nothing registered until `--setup` runs."""
    fresh = TenantPurgeParticipantRegistry()
    monkeypatch.setattr(participants_module, "_default_registry", fresh)
    return fresh


def _setup_module(
    monkeypatch: pytest.MonkeyPatch, register: Any, name: str = "_purge_setup_probe"
) -> str:
    module = types.ModuleType(name)
    module.register_purge_participants = register  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, name, module)
    return f"{name}:register_purge_participants"


def _deleted_tenant(scene: Any, platform: PlatformWorld) -> tuple[uuid.UUID, str]:
    tenant = scene.tenant(active=True)
    operator, _ = platform.operator([P.TENANT_DELETE])
    op = str(operator.user_id)
    t = str(tenant)
    assert (
        _run("delete-tenant", "--tenant", t, "--operator", op, "--reason", "T-9", "--confirm", t)
        == 0
    )
    return tenant, op


def _purge_via_cli(tenant: uuid.UUID, actor: str, setup: str) -> int:
    t = str(tenant)
    return _run("purge-tenant", "--tenant", t, "--actor", actor, "--setup", setup, "--confirm", t)


def test_purge_runs_participants_registered_by_setup_in_registration_order(
    scene: Any,
    platform: PlatformWorld,
    operator_process: TenantPurgeParticipantRegistry,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, uuid.UUID]] = []
    first = _RecordingParticipant("product.first", calls)
    second = _RecordingParticipant("product.second", calls)

    def register() -> None:
        register_purge_participant(first)
        register_purge_participant(second)

    tenant, actor = _deleted_tenant(scene, platform)
    capsys.readouterr()
    assert operator_process.names() == ()  # nothing until --setup runs

    assert _purge_via_cli(tenant, actor, _setup_module(monkeypatch, register)) == 0

    assert calls == [("product.first", tenant), ("product.second", tenant)]
    assert scene.status(tenant) == "purged"
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["participant_names"] == ["product.first", "product.second"]
    [completed] = scene.tenant_audit(tenant, "tenant.purge_completed")
    assert completed["metadata"]["participants_run"] == 2
    # Issue #95 negative control: a --setup purge records no override.
    assert "product_participants_skipped" not in completed["metadata"]


def test_no_product_participants_is_recorded_on_completion(
    scene: Any,
    platform: PlatformWorld,
    operator_process: TenantPurgeParticipantRegistry,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Issue #95: the explicit override is visible in the completion audit,
    so `participants_run: 0` from `--no-product-participants` can be told
    apart from a direct call in a process that registered nothing."""
    tenant, actor = _deleted_tenant(scene, platform)
    t = str(tenant)
    capsys.readouterr()

    code = _run(
        "purge-tenant", "--tenant", t, "--actor", actor, "--no-product-participants", "--confirm", t
    )

    assert code == 0
    assert scene.status(tenant) == "purged"
    assert json.loads(capsys.readouterr().out)["result"]["participant_names"] == []
    [started] = scene.tenant_audit(tenant, "tenant.purge_started")
    assert "product_participants_skipped" not in started["metadata"]
    [completed] = scene.tenant_audit(tenant, "tenant.purge_completed")
    assert completed["metadata"]["product_participants_skipped"] is True
    assert completed["metadata"]["participants_run"] == 0


def test_a_failing_participant_fails_the_command_and_a_rerun_completes(
    scene: Any,
    platform: PlatformWorld,
    operator_process: TenantPurgeParticipantRegistry,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, uuid.UUID]] = []
    first = _RecordingParticipant("product.first", calls)
    second = _RecordingParticipant("product.second", calls)
    second.fail = True

    def register() -> None:
        register_purge_participant(first)
        register_purge_participant(second)

    setup = _setup_module(monkeypatch, register)
    tenant, actor = _deleted_tenant(scene, platform)
    capsys.readouterr()

    assert _purge_via_cli(tenant, actor, setup) == 1
    captured = capsys.readouterr()
    assert captured.out == ""  # no result is printed for a failed purge
    assert captured.err.strip() == "failed: RuntimeError"
    assert scene.status(tenant) == "purging"
    assert scene.tenant_audit(tenant, "tenant.purge_completed") == []
    [failed] = scene.tenant_audit(tenant, "tenant.purge_failed")
    assert failed["metadata"]["failure_class"] == "participant_error"
    assert failed["metadata"]["failed_step"] == "participant:product.second"
    assert "SECRET" not in json.dumps(failed["metadata"])

    # The product fixes its participant and the operator runs the command
    # again; --setup registers the same objects, which is a no-op.
    second.fail = False
    assert _purge_via_cli(tenant, actor, setup) == 0
    assert scene.status(tenant) == "purged"
    # A retry re-runs every participant, including one that already succeeded.
    assert calls == [
        ("product.first", tenant),
        ("product.second", tenant),
        ("product.first", tenant),
        ("product.second", tenant),
    ]
    started = scene.tenant_audit(tenant, "tenant.purge_started")
    assert [row["metadata"]["resumed"] for row in started] == [False, True]
    assert len(scene.tenant_audit(tenant, "tenant.purge_completed")) == 1

    # A third run finds the tombstone: no participant runs, nothing is recorded.
    capsys.readouterr()
    assert _purge_via_cli(tenant, actor, setup) == 0
    assert json.loads(capsys.readouterr().out)["result"]["already_purged"] is True
    assert len(calls) == 4
    assert len(scene.tenant_audit(tenant, "tenant.purge_started")) == 2


def test_a_setup_that_registers_nothing_is_refused_before_the_tenant_is_touched(
    scene: Any,
    platform: PlatformWorld,
    operator_process: TenantPurgeParticipantRegistry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing registration: a setup that forgot to register the product's
    participants would leave product rows behind a PURGED tenant, so the
    command refuses and the tenant stays DELETED -- it never enters PURGING."""
    tenant, actor = _deleted_tenant(scene, platform)
    assert _purge_via_cli(tenant, actor, _setup_module(monkeypatch, lambda: None)) == 2
    assert operator_process.names() == ()
    assert scene.status(tenant) == "deleted"
    assert scene.tenant_audit(tenant, "tenant.purge_started") == []


def test_a_setup_registering_a_colliding_participant_is_refused_before_the_tenant_is_touched(
    scene: Any,
    platform: PlatformWorld,
    operator_process: TenantPurgeParticipantRegistry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, uuid.UUID]] = []

    def register() -> None:
        register_purge_participant(_RecordingParticipant("product.items", calls))
        register_purge_participant(_RecordingParticipant("product.items", calls))

    tenant, actor = _deleted_tenant(scene, platform)
    assert _purge_via_cli(tenant, actor, _setup_module(monkeypatch, register)) == 1
    assert calls == []
    assert scene.status(tenant) == "deleted"
    assert scene.tenant_audit(tenant, "tenant.purge_started") == []
