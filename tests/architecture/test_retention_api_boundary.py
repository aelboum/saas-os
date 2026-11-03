"""Architecture pins for the authenticated retention API and the approver
register (owner decisions of 2026-11-03;
`docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`, section 8.5).

- every retention request model forbids extra fields and declares no field
  named like an identity: the caller is only the session's user;
- only the platform-admin router calls the functions that release a hold,
  request, approve or authorise a deletion, or write the register, and only
  it constructs the session evidence they take;
- no `saas-os-operator` command releases a hold or approves anything;
- the vocabulary stays at twenty-eight permissions;
- nothing but the literal module constant switches deletion on.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from saas_os.api.platform_admin.router import RETENTION_REQUEST_MODELS
from saas_os.core.platform_authority import PlatformPermission

_REPO = Path(__file__).resolve().parents[2]
_SAAS_OS = _REPO / "saas_os"
_ROUTER = "saas_os/api/platform_admin/router.py"
_IDENTITY = re.compile(r"operator|user_id|actor|approver|requester|authori[sz]ed_by|executor")

# The functions only the router may call (each requires the session
# evidence of an authenticated platform-admin request).
_ROUTE_ONLY = {
    "release_permission_grant_ledger_hold",
    "request_permission_grant_ledger_deletion",
    "approve_permission_grant_ledger_deletion",
    "authorize_permission_grant_ledger_deletion_execution",
    "propose_representative_designation",
    "confirm_representative_designation",
    "enrol_approver",
    "revoke_register_entry",
    "PlatformSessionEvidence",
}


def _called_names(tree: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


def _callers(names: set[str]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted(_SAAS_OS.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        called = _called_names(ast.parse(path.read_text(encoding="utf-8"))) & names
        if called:
            found[path.relative_to(_REPO).as_posix()] = called
    return found


def test_every_retention_request_model_forbids_extra_fields_and_names_no_identity() -> None:
    assert len(RETENTION_REQUEST_MODELS) == 8
    for model in RETENTION_REQUEST_MODELS:
        assert model.model_config.get("extra") == "forbid", model.__name__
        for field in model.model_fields:
            assert not _IDENTITY.search(field), (model.__name__, field)


def test_only_the_router_releases_requests_approves_authorises_or_writes_the_register() -> None:
    callers = _callers(_ROUTE_ONLY)
    assert set(callers) == {_ROUTER}, callers
    assert callers[_ROUTER] == _ROUTE_ONLY


def test_the_scan_sees_a_new_caller(tmp_path: Path) -> None:
    """Not vacuous: a module calling one of them is reported."""
    tree = ast.parse("from x import enrol_approver\nenrol_approver(1)\n")
    assert _called_names(tree) & _ROUTE_ONLY == {"enrol_approver"}


def test_no_operator_command_releases_a_hold_or_approves() -> None:
    from saas_os.ops import operator_cli

    commands = set(operator_cli._COMMANDS)  # pyright: ignore[reportPrivateUsage]
    assert "hold-permission-grant-ledger" in commands  # an emergency hold stays
    assert not [
        c for c in commands if re.search(r"release|approv|authori[sz]|enrol|designat", c)
    ], commands
    ops = _REPO / "saas_os" / "ops"
    for path in ops.rglob("*.py"):
        called = _called_names(ast.parse(path.read_text(encoding="utf-8"))) & _ROUTE_ONLY
        assert not called, (path.name, called)


def test_the_vocabulary_stays_at_twenty_eight_permissions() -> None:
    assert len(PlatformPermission) == 28


def test_nothing_but_the_literal_constant_switches_deletion_on() -> None:
    source = (_SAAS_OS / "core" / "permission_grants" / "expiry.py").read_text(encoding="utf-8")
    assert re.search(r"^_DELETION_ENABLED = False$", source, re.MULTILINE)
    assert source.count("_DELETION_ENABLED =") == 1
    for forbidden in ("os.environ", "getenv", "get_settings", 'DELETION_ENABLED"', "argv"):
        assert forbidden not in source, forbidden


def test_the_hold_release_locks_the_tenant_row_before_the_hold_row() -> None:
    """Design 5.4. Pinned in the source because a race test cannot see it:
    the release's audit row has a foreign key onto the tenant, so the
    release waits for a deletion's tenant lock even without the explicit
    lock (the negative control of PR #203 showed that)."""
    import inspect

    from saas_os.core.permission_grants import retention

    source = inspect.getsource(retention.release_permission_grant_ledger_hold)
    tenant_lock = source.index(
        "select(Tenant.id).where(Tenant.id == tenant_of_hold).with_for_update()"
    )
    hold_lock = source.index(
        "session.get(PermissionGrantLedgerHold, hold_id, with_for_update=True)"
    )
    assert tenant_lock < hold_lock
    assert source.count("target_tenant_id=hold.target_tenant_id") >= 1
